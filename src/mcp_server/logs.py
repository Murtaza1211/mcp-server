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


def _build_grep_command(path: PurePosixPath, search: list[str]) -> str:
    terms = " ".join(f"-e {shlex.quote(term)}" for term in search)
    return f"grep -n -i -a -F -C {_CONTEXT_LINES} {terms} -- {shlex.quote(str(path))} 2>/dev/null"


def _split_blocks(grep_output: str) -> list[list[str]]:
    blocks: list[list[str]] = [[]]
    for line in grep_output.splitlines():
        if line == "--":
            blocks.append([])
        else:
            blocks[-1].append(line)
    return [b for b in blocks if b]


# grep -n prefixes matched lines "N:content" and context lines "N-content".
_GREP_LINE_RE = re.compile(r"^(\d+)([:\-])(.*)$", re.DOTALL)


def _block_timestamp(block: list[str]) -> datetime | None:
    """Best-effort timestamp for a grep context block: prefer the matched line itself,
    then walk backwards through preceding context (closest first, since stack-trace/
    continuation lines belong to the nearest earlier timestamped header), then forwards.
    """
    parsed = []
    for line in block:
        m = _GREP_LINE_RE.match(line)
        parsed.append((m.group(2) == ":", m.group(3)) if m else (False, line))

    match_indices = [i for i, (is_match, _) in enumerate(parsed) if is_match]
    anchor = match_indices[0] if match_indices else 0

    order = [anchor, *range(anchor - 1, -1, -1), *range(anchor + 1, len(parsed))]
    for idx in order:
        ts = _extract_timestamp(parsed[idx][1])
        if ts is not None:
            return ts
    return None


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
            for rel, abs_path in targets:
                if total_blocks >= _MAX_MATCH_BLOCKS:
                    truncated = True
                    break
                _exit_status, out, _err = run_command(client, _build_grep_command(abs_path, search))
                for block in _split_blocks(out):
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
