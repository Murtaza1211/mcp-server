"""List and search IBM Liberty logs over SSH.

`<deployment_directory>/<application>/logs/` mixes Liberty's own logs
(messages.log, console.log, trace.log, ffdc/*) with arbitrary application
logs an app may write into subdirectories. list_logs() enumerates everything
under there so an LLM can decide what's relevant; analyze_logs() then greps
a chosen (or all) set of those files for the requested strings/exceptions,
optionally narrowed to a time window.

Liberty's default text log format prefixes each new log entry with a
bracketed timestamp, e.g. "[7/28/26 0:15:32:123 UTC]" - but continuation
lines (stack traces, multi-line messages) don't repeat it, and JSON-format
logging uses a completely different shape ("ibm_datetime":"..."). Time
filtering here is therefore best-effort: a matched block is only dropped
when a timestamp *was* found and is clearly outside the window. A block
where no timestamp could be parsed is always kept rather than silently
discarded, since hiding potentially-relevant log lines is worse than
including a few extra ones.
"""

import posixpath
import re
import shlex
from datetime import datetime, timezone
from pathlib import PurePosixPath

import paramiko

from .ssh import run_command, ssh_client

_MAX_AUTO_FILES = 300
_MAX_AUTO_FILE_SIZE = 25 * 1024 * 1024  # skip huge files (e.g. trace.log) unless explicitly requested
_MAX_MATCH_BLOCKS = 200
_CONTEXT_LINES = 2
# Files are grepped in batches of this size, all within a single SSH exec
# round-trip per batch, instead of one round-trip per file. Batching (rather
# than one giant command for every target) keeps the remote command line to a
# sane length and bounds how long any single exec call can take.
_BATCH_SIZE = 50
# Base + per-file timeout budget (seconds) for a batched grep exec call.
_BATCH_TIMEOUT_BASE = 15
_BATCH_TIMEOUT_PER_FILE = 2

# Marker emitted before each file's grep output in a batched command, so the
# combined stdout can be split back into per-file chunks client-side. Uses
# \x01 (SOH), which is vanishingly unlikely to appear in real log content.
_BATCH_MARKER_RE = re.compile(r"\x01\x01F(\d+)\x01\x01\n?")

# Liberty's default basic-format timestamp: [7/28/26 0:15:32:123 UTC] (comma after date optional).
_LIBERTY_BASIC_TS_RE = re.compile(
    r"\[(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}:\d{2})(?::(\d{3}))?\s*[A-Za-z]*\]"
)
# Liberty JSON-format logging: {"ibm_datetime":"2026-07-28T00:15:32.123+0000", ...}.
_LIBERTY_JSON_TS_RE = re.compile(r'"ibm_datetime"\s*:\s*"([0-9T:.+\-]+)"')
# Generic ISO-8601, for arbitrary application logs.
_ISO_TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def _extract_timestamp(text: str) -> datetime | None:
    m = _LIBERTY_BASIC_TS_RE.search(text)
    if m:
        date_part, time_part, millis = m.group(1), m.group(2), m.group(3)
        for year_fmt in ("%m/%d/%y", "%m/%d/%Y"):
            try:
                d = datetime.strptime(date_part, year_fmt)
                h, mi, s = (int(x) for x in time_part.split(":"))
                return d.replace(hour=h, minute=mi, second=s, microsecond=int(millis or 0) * 1000)
            except ValueError:
                continue
        return None

    m = _LIBERTY_JSON_TS_RE.search(text)
    if m:
        try:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=None)
        except ValueError:
            return None

    m = _ISO_TS_RE.search(text)
    if m:
        try:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=None)
        except ValueError:
            return None

    return None


def _parse_time_arg(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    return dt.replace(tzinfo=None)


def _categorize(rel_path: str) -> str:
    parts = PurePosixPath(rel_path).parts
    if parts and parts[0] == "ffdc":
        return "ffdc"
    if len(parts) == 1 and parts[0] in ("messages.log", "console.log", "trace.log"):
        return "liberty_core"
    return "app_or_other"


def _remote_is_dir(client: paramiko.SSHClient, path: PurePosixPath) -> bool:
    _exit_status, out, _err = run_command(client, f"test -d {shlex.quote(str(path))} && echo Y || echo N")
    return out.strip() == "Y"


def _list_files(client: paramiko.SSHClient, logs_dir: PurePosixPath) -> list[dict]:
    exit_status, out, err = run_command(
        client, f"find {shlex.quote(str(logs_dir))} -type f -printf '%s\\t%T@\\t%p\\n' 2>/dev/null"
    )
    files = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        size_str, mtime_str, path = parts
        try:
            size = int(size_str)
            mtime = datetime.fromtimestamp(float(mtime_str), tz=timezone.utc).isoformat()
        except ValueError:
            continue
        rel = str(PurePosixPath(path).relative_to(logs_dir))
        files.append({"path": rel, "size_bytes": size, "modified": mtime, "category": _categorize(rel)})
    files.sort(key=lambda f: f["path"])
    return files


def list_logs(server_ip: str, os_user: str, ssh_key: str, deployment_directory: str, application: str) -> dict:
    """SSH to server_ip and enumerate every file under the app's logs/ directory."""
    logs_dir = PurePosixPath(deployment_directory) / application / "logs"
    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            if not _remote_is_dir(client, logs_dir):
                return {
                    "server": server_ip,
                    "logs_directory": str(logs_dir),
                    "error": f"logs directory not found on {server_ip}: {logs_dir}",
                    "files": [],
                }
            files = _list_files(client, logs_dir)
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH authentication failed: {e}", "files": []}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH connection failed: {e}", "files": []}

    return {"server": server_ip, "logs_directory": str(logs_dir), "files": files}


def _resolve_log_file(logs_dir: PurePosixPath, rel: str) -> PurePosixPath | None:
    """Resolve a caller-supplied relative log path, refusing to leave logs_dir."""
    candidate = posixpath.normpath(str(logs_dir / rel.lstrip("/")))
    logs_dir_str = str(logs_dir)
    if not (candidate == logs_dir_str or candidate.startswith(logs_dir_str.rstrip("/") + "/")):
        return None
    return PurePosixPath(candidate)


def _build_batch_grep_command(paths: list[PurePosixPath], search: list[str]) -> str:
    """Build a single remote command that greps every path in `paths` and
    prints a unique marker before each file's output, so one SSH exec call
    can cover many files instead of one exec call per file.
    """
    terms = " ".join(f"-e {shlex.quote(term)}" for term in search)
    parts = []
    for i, path in enumerate(paths):
        parts.append(f"printf '\\1\\1F{i}\\1\\1\\n'")
        parts.append(f"grep -n -i -a -F -C {_CONTEXT_LINES} {terms} -- {shlex.quote(str(path))} 2>/dev/null")
    return " ; ".join(parts)


def _split_batch_output(raw: str, n: int) -> list[str]:
    """Split the combined stdout of _build_batch_grep_command back into one
    chunk per input file, in the same order the paths were given.
    """
    outputs = [""] * n
    matches = list(_BATCH_MARKER_RE.finditer(raw))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        file_idx = int(m.group(1))
        if 0 <= file_idx < n:
            outputs[file_idx] = raw[start:end]
    return outputs


def _split_blocks(grep_output: str) -> list[list[str]]:
    blocks: list[list[str]] = [[]]
    for line in grep_output.splitlines():
        if line == "--":
            blocks.append([])
        else:
            blocks[-1].append(line)
    return [b for b in blocks if b]


# Default patterns for scan_errors(): fully-qualified Java exception/error
# class names (java.lang.NullPointerException, com.example.MyException, ...)
# and Liberty's own severity-coded message IDs (SRVE0777E, CWWKG0033W, ...).
# Message IDs matter as much as exception class names here - many real
# Liberty failures (a full disk, a listener that failed to start, a config
# error) never throw a Java exception at all, they only ever appear as an
# E/W-severity message code. Restricted to E (error) and W (warning) by
# default to skip informational/audit codes.
_DEFAULT_EXCEPTION_PATTERN = r"\b([a-zA-Z][a-zA-Z0-9_]*\.)+[A-Z][A-Za-z0-9_$]*(Exception|Error)\b"
_DEFAULT_MSGID_PATTERN = r"\b[A-Z]{2,10}[0-9]{4,5}[EW]\b"

_SCAN_EXCEPTION_RE = re.compile(_DEFAULT_EXCEPTION_PATTERN)
_SCAN_MSGID_RE = re.compile(_DEFAULT_MSGID_PATTERN)


def _build_batch_scan_command(paths: list[PurePosixPath], patterns: list[str]) -> str:
    """Like _build_batch_grep_command, but for extended-regex error/exception
    patterns instead of literal search terms.
    """
    terms = " ".join(f"-e {shlex.quote(p)}" for p in patterns)
    parts = []
    for i, path in enumerate(paths):
        parts.append(f"printf '\\1\\1F{i}\\1\\1\\n'")
        parts.append(f"grep -n -a -E -C {_CONTEXT_LINES} {terms} -- {shlex.quote(str(path))} 2>/dev/null")
    return " ; ".join(parts)


def _identify_error(matched_line: str, exception_re: re.Pattern, msgid_re: re.Pattern) -> tuple[str, str] | None:
    """Return (identifier, type) for the first exception class name or
    message ID found in a matched line, exception class taking priority
    since it's the more specific signal when both are present.
    """
    m = exception_re.search(matched_line)
    if m:
        return m.group(0), "exception"
    m = msgid_re.search(matched_line)
    if m:
        return m.group(0), "message_id"
    return None


# grep -n prefixes matched lines "N:content" and context lines "N-content".
_GREP_LINE_RE = re.compile(r"^(\d+)([:\-])(.*)$", re.DOTALL)


def _parse_grep_block(block: list[str]) -> list[tuple[bool, str]]:
    """Parse a grep -n block's lines into (is_matched_line, text) pairs."""
    parsed = []
    for line in block:
        m = _GREP_LINE_RE.match(line)
        parsed.append((m.group(2) == ":", m.group(3)) if m else (False, line))
    return parsed


def _nearest_timestamp(parsed: list[tuple[bool, str]], anchor: int) -> datetime | None:
    """Best-effort timestamp nearest to `anchor` in a parsed block: the anchor
    line itself, then preceding lines (closest first, since stack-trace/
    continuation lines belong to the nearest earlier timestamped header),
    then following lines.
    """
    order = [anchor, *range(anchor - 1, -1, -1), *range(anchor + 1, len(parsed))]
    for idx in order:
        ts = _extract_timestamp(parsed[idx][1])
        if ts is not None:
            return ts
    return None


def _block_timestamp(block: list[str]) -> datetime | None:
    """Best-effort timestamp for a grep context block: anchored on the
    block's first matched line (see _nearest_timestamp).
    """
    parsed = _parse_grep_block(block)
    match_indices = [i for i, (is_match, _) in enumerate(parsed) if is_match]
    anchor = match_indices[0] if match_indices else 0
    return _nearest_timestamp(parsed, anchor)


def analyze_logs(
    server_ip: str,
    os_user: str,
    ssh_key: str,
    deployment_directory: str,
    application: str,
    search: list[str],
    start_time: str | None = None,
    end_time: str | None = None,
    log_files: list[str] | None = None,
) -> dict:
    """SSH to server_ip and grep the app's logs for `search` terms, optionally within
    [start_time, end_time]. If log_files is omitted, searches every discovered log file
    up to a size/count cap (large files like trace.log are skipped in that mode - pass
    log_files explicitly, from list_logs, to search them anyway).
    """
    logs_dir = PurePosixPath(deployment_directory) / application / "logs"

    if not search:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": "search must contain at least one term"}

    try:
        start_dt = _parse_time_arg(start_time)
        end_dt = _parse_time_arg(end_time)
    except ValueError as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"invalid start_time/end_time: {e}"}

    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            if not _remote_is_dir(client, logs_dir):
                return {
                    "server": server_ip,
                    "logs_directory": str(logs_dir),
                    "error": f"logs directory not found on {server_ip}: {logs_dir}",
                    "results": [],
                }

            all_files = _list_files(client, logs_dir)

            skipped: list[dict] = []
            if log_files:
                targets = []
                for rel in log_files:
                    resolved = _resolve_log_file(logs_dir, rel)
                    if resolved is None:
                        skipped.append({"path": rel, "reason": "outside logs directory"})
                        continue
                    targets.append((rel, resolved))
            else:
                if len(all_files) > _MAX_AUTO_FILES:
                    return {
                        "server": server_ip,
                        "logs_directory": str(logs_dir),
                        "error": (
                            f"{len(all_files)} files under logs/ exceeds the auto-scan limit of "
                            f"{_MAX_AUTO_FILES}; call list_logs and pass specific log_files instead."
                        ),
                        "results": [],
                    }
                targets = []
                for f in all_files:
                    if f["size_bytes"] > _MAX_AUTO_FILE_SIZE:
                        skipped.append({"path": f["path"], "reason": "file too large for auto-scan; pass it explicitly via log_files"})
                        continue
                    if start_dt:
                        file_mtime = datetime.fromisoformat(f["modified"]).replace(tzinfo=None)
                        if file_mtime < start_dt:
                            continue  # file's last write predates the window - can't contain anything newer
                    targets.append((f["path"], logs_dir / f["path"]))

            results = []
            truncated = False
            total_blocks = 0
            for batch_start in range(0, len(targets), _BATCH_SIZE):
                if total_blocks >= _MAX_MATCH_BLOCKS:
                    truncated = True
                    break
                batch = targets[batch_start : batch_start + _BATCH_SIZE]
                batch_paths = [abs_path for _rel, abs_path in batch]
                batch_cmd = _build_batch_grep_command(batch_paths, search)
                batch_timeout = _BATCH_TIMEOUT_BASE + _BATCH_TIMEOUT_PER_FILE * len(batch)
                _exit_status, out, _err = run_command(client, batch_cmd, timeout=batch_timeout)
                per_file_output = _split_batch_output(out, len(batch))

                for (rel, _abs_path), file_out in zip(batch, per_file_output):
                    if total_blocks >= _MAX_MATCH_BLOCKS:
                        truncated = True
                        break
                    for block in _split_blocks(file_out):
                        if total_blocks >= _MAX_MATCH_BLOCKS:
                            truncated = True
                            break
                        ts = _block_timestamp(block)
                        if ts is not None:
                            if start_dt and ts < start_dt:
                                continue
                            if end_dt and ts > end_dt:
                                continue
                        results.append(
                            {
                                "file": rel,
                                "timestamp": ts.isoformat() if ts else None,
                                "lines": block,
                            }
                        )
                        total_blocks += 1
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH authentication failed: {e}", "results": []}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH connection failed: {e}", "results": []}

    return {
        "server": server_ip,
        "logs_directory": str(logs_dir),
        "search": search,
        "results": results,
        "truncated": truncated,
        "skipped_files": skipped,
    }


_MAX_SCAN_BLOCKS = 200


def scan_errors(
    server_ip: str,
    os_user: str,
    ssh_key: str,
    deployment_directory: str,
    application: str,
    log_files: list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    patterns: list[str] | None = None,
    include_context: bool = False,
) -> dict:
    """SSH to server_ip and scan the app's logs for exceptions/errors, returning a
    grouped summary (identifier, count, first/last seen, one sample line) instead of
    every raw match - meant as a cheap first pass an LLM can use to decide what's worth
    a full analyze_logs() call, rather than reading full context for every occurrence.

    By default matches both fully-qualified Java exception/error class names (e.g.
    java.lang.NullPointerException) and Liberty's own E/W-severity message codes (e.g.
    SRVE0777E, CWWKG0033W) - many real Liberty failures (full disk, a listener that
    failed to start, a config problem) only ever show up as a message code, never as a
    Java exception, so message IDs are included by default rather than treated as a
    secondary/optional signal.

    Pass `patterns` (a list of extended-regex patterns) to replace the default pattern
    set entirely - e.g. to scan for something else altogether, or to narrow to a
    specific exception family.

    Like analyze_logs: batches files (up to 50 per SSH exec call), applies the same
    best-effort time-window filtering (a block is only dropped when a timestamp was
    found and falls outside [start_time, end_time]; unparseable blocks are kept), and
    caps total matched blocks at 200 - if truncated, reported counts are a lower bound,
    not exact.
    """
    logs_dir = PurePosixPath(deployment_directory) / application / "logs"

    scan_patterns = patterns if patterns else [_DEFAULT_EXCEPTION_PATTERN, _DEFAULT_MSGID_PATTERN]
    # If the caller supplied custom patterns, identify matches using those same
    # patterns (compiled), rather than the default exception/message-id split.
    if patterns:
        try:
            compiled_patterns = [re.compile(p) for p in patterns]
        except re.error as e:
            return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"invalid pattern: {e}"}

        def identify(matched_line: str) -> tuple[str, str] | None:
            for cp in compiled_patterns:
                m = cp.search(matched_line)
                if m:
                    return m.group(0), "custom"
            return None
    else:
        def identify(matched_line: str) -> tuple[str, str] | None:
            return _identify_error(matched_line, _SCAN_EXCEPTION_RE, _SCAN_MSGID_RE)

    try:
        start_dt = _parse_time_arg(start_time)
        end_dt = _parse_time_arg(end_time)
    except ValueError as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"invalid start_time/end_time: {e}"}

    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            if not _remote_is_dir(client, logs_dir):
                return {
                    "server": server_ip,
                    "logs_directory": str(logs_dir),
                    "error": f"logs directory not found on {server_ip}: {logs_dir}",
                    "errors": [],
                }

            all_files = _list_files(client, logs_dir)

            skipped: list[dict] = []
            if log_files:
                targets = []
                for rel in log_files:
                    resolved = _resolve_log_file(logs_dir, rel)
                    if resolved is None:
                        skipped.append({"path": rel, "reason": "outside logs directory"})
                        continue
                    targets.append((rel, resolved))
            else:
                if len(all_files) > _MAX_AUTO_FILES:
                    return {
                        "server": server_ip,
                        "logs_directory": str(logs_dir),
                        "error": (
                            f"{len(all_files)} files under logs/ exceeds the auto-scan limit of "
                            f"{_MAX_AUTO_FILES}; call list_logs and pass specific log_files instead."
                        ),
                        "errors": [],
                    }
                targets = []
                for f in all_files:
                    if f["size_bytes"] > _MAX_AUTO_FILE_SIZE:
                        skipped.append({"path": f["path"], "reason": "file too large for auto-scan; pass it explicitly via log_files"})
                        continue
                    if start_dt:
                        file_mtime = datetime.fromisoformat(f["modified"]).replace(tzinfo=None)
                        if file_mtime < start_dt:
                            continue
                    targets.append((f["path"], logs_dir / f["path"]))

            # identifier -> aggregated summary
            aggregated: dict[str, dict] = {}
            truncated = False
            total_blocks = 0
            for batch_start in range(0, len(targets), _BATCH_SIZE):
                if total_blocks >= _MAX_SCAN_BLOCKS:
                    truncated = True
                    break
                batch = targets[batch_start : batch_start + _BATCH_SIZE]
                batch_paths = [abs_path for _rel, abs_path in batch]
                batch_cmd = _build_batch_scan_command(batch_paths, scan_patterns)
                batch_timeout = _BATCH_TIMEOUT_BASE + _BATCH_TIMEOUT_PER_FILE * len(batch)
                _exit_status, out, _err = run_command(client, batch_cmd, timeout=batch_timeout)
                per_file_output = _split_batch_output(out, len(batch))

                for (rel, _abs_path), file_out in zip(batch, per_file_output):
                    if total_blocks >= _MAX_SCAN_BLOCKS:
                        truncated = True
                        break
                    for block in _split_blocks(file_out):
                        if total_blocks >= _MAX_SCAN_BLOCKS:
                            truncated = True
                            break

                        # A single block can contain more than one matched line -
                        # grep merges nearby matches into one continuous block when
                        # their context windows overlap (e.g. two errors 3 lines
                        # apart with -C 2). Each matched line is its own occurrence
                        # and needs its own identification + nearest timestamp, not
                        # just the block's first match.
                        parsed = _parse_grep_block(block)
                        match_indices = [i for i, (is_match, _) in enumerate(parsed) if is_match]

                        for idx in match_indices:
                            if total_blocks >= _MAX_SCAN_BLOCKS:
                                truncated = True
                                break

                            matched_line = parsed[idx][1]
                            found = identify(matched_line)
                            if found is None:
                                continue
                            identifier, kind = found

                            ts = _nearest_timestamp(parsed, idx)
                            if ts is not None:
                                if start_dt and ts < start_dt:
                                    continue
                                if end_dt and ts > end_dt:
                                    continue

                            entry = aggregated.get(identifier)
                            if entry is None:
                                entry = {
                                    "identifier": identifier,
                                    "type": kind,
                                    "count": 0,
                                    "first_seen": None,
                                    "last_seen": None,
                                    "files": [],
                                    "sample_line": matched_line,
                                }
                                if include_context:
                                    entry["sample_context"] = block
                                aggregated[identifier] = entry

                            entry["count"] += 1
                            if rel not in entry["files"]:
                                entry["files"].append(rel)
                            if ts is not None:
                                ts_iso = ts.isoformat()
                                if entry["first_seen"] is None or ts_iso < entry["first_seen"]:
                                    entry["first_seen"] = ts_iso
                                if entry["last_seen"] is None or ts_iso > entry["last_seen"]:
                                    entry["last_seen"] = ts_iso

                            total_blocks += 1
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH authentication failed: {e}", "errors": []}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "logs_directory": str(logs_dir), "error": f"SSH connection failed: {e}", "errors": []}

    errors = sorted(aggregated.values(), key=lambda e: e["count"], reverse=True)

    return {
        "server": server_ip,
        "logs_directory": str(logs_dir),
        "patterns_used": scan_patterns,
        "errors": errors,
        "truncated": truncated,
        "skipped_files": skipped,
    }
