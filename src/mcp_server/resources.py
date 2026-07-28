"""Resource checks (disk, memory, file descriptors) in support of IBM Liberty triage.

Complements read_config / list_logs / analyze_logs / check_connectivity: those
look at the app's config, logs, and outward dependencies, while check_resources
looks at whether the box itself is in a state that would explain a failure -
often the actual root cause behind log lines that look like an app bug but
aren't (disk full, OOM pressure, fd exhaustion).

Disk is checked for exactly three things, not every mounted filesystem: the
filesystem holding <deployment_directory>/<application> (where logs/FFDC/work
files actually get written), /tmp (where the JVM writes temp files by
default), and / (root - if it's a distinct filesystem from the other two,
worth a cheap sanity check; if it's the same filesystem, that's visible from
matching 'mounted_on' values rather than hidden). This intentionally does not
enumerate every mount - a filesystem irrelevant to this app would just add
noise to a triage report, the same reasoning behind check_connectivity taking
explicit targets instead of auto-discovering every hostname in config.
"""

import re
import shlex

import paramiko

from .ssh import run_command, ssh_client

_TIMEOUT = 20

_SECTION_RE = re.compile(r"\x01\x01(DISK:\w+|MEM|PROC)\x01\x01\n?")
_ULIMIT_RE = re.compile(r"Max open files\s+(\d+|unlimited)\s+(\d+|unlimited)")

_DISK_LABELS = ("deployment", "tmp", "root")


def _build_resource_script(deployment_path: str, application: str) -> str:
    paths = [
        ("deployment", deployment_path),
        ("tmp", "/tmp"),
        ("root", "/"),
    ]
    parts = []
    for label, path in paths:
        path_q = shlex.quote(path)
        parts.append(f"printf '\\1\\1DISK:{label}\\1\\1\\n'")
        parts.append(f"df -Pk {path_q} 2>/dev/null | tail -n +2")
        parts.append(f"df -Pi {path_q} 2>/dev/null | tail -n +2")

    parts.append("printf '\\1\\1MEM\\1\\1\\n'")
    parts.append("free -m 2>/dev/null || cat /proc/meminfo 2>/dev/null")

    parts.append("printf '\\1\\1PROC\\1\\1\\n'")
    app_q = shlex.quote(application)
    parts.append(
        f'pid=$(ps -ef 2>/dev/null | grep -i java | grep -F {app_q} | grep -v grep | awk \'{{print $2}}\' | head -n1); '
        f'if [ -n "$pid" ]; then '
        f'echo "PID=$pid"; '
        f'echo "FD_COUNT=$(ls /proc/$pid/fd 2>/dev/null | wc -l)"; '
        f'grep -i "Max open files" /proc/$pid/limits 2>/dev/null; '
        f'else echo "PID=NONE"; fi'
    )
    return "\n".join(parts)


def _split_sections(raw: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(raw))
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        sections[key] = raw[start:end]
    return sections


def _parse_disk_section(chunk: str) -> dict:
    lines = [l for l in chunk.splitlines() if l.strip()]
    if not lines:
        return {"available": False, "detail": "path not found or df failed"}

    result: dict = {"available": True}

    # First line: df -Pk -> filesystem, 1024-blocks, used, available, capacity%, mounted-on
    block_fields = lines[0].split()
    if len(block_fields) >= 6:
        fs, total_kb, used_kb, avail_kb, pct, mount = block_fields[0], *block_fields[1:5], " ".join(block_fields[5:])
        try:
            result["filesystem"] = fs
            result["mounted_on"] = mount
            result["total_mb"] = round(int(total_kb) / 1024, 1)
            result["used_mb"] = round(int(used_kb) / 1024, 1)
            result["available_mb"] = round(int(avail_kb) / 1024, 1)
            result["used_pct"] = int(pct.rstrip("%"))
        except ValueError:
            pass

    # Second line (if present): df -Pi -> filesystem, inodes, iused, ifree, iuse%, mounted-on
    if len(lines) >= 2:
        inode_fields = lines[1].split()
        if len(inode_fields) >= 6:
            _fs, total_i, used_i, avail_i, ipct = inode_fields[0], *inode_fields[1:5]
            try:
                result["total_inodes"] = int(total_i)
                result["used_inodes"] = int(used_i)
                result["available_inodes"] = int(avail_i)
                result["inode_used_pct"] = int(ipct.rstrip("%"))
            except ValueError:
                pass

    return result


def _parse_mem_section(chunk: str) -> dict:
    lines = [l for l in chunk.splitlines() if l.strip()]
    mem: dict = {}

    for line in lines:
        if line.startswith("Mem:"):
            fields = line.split()
            # free -m: Mem: total used free shared buff/cache available
            if len(fields) >= 4:
                try:
                    mem["total_mb"] = int(fields[1])
                    mem["used_mb"] = int(fields[2])
                    mem["free_mb"] = int(fields[3])
                    if len(fields) >= 7:
                        mem["available_mb"] = int(fields[6])
                except ValueError:
                    pass
        elif line.startswith("Swap:"):
            fields = line.split()
            if len(fields) >= 4:
                try:
                    mem["swap_total_mb"] = int(fields[1])
                    mem["swap_used_mb"] = int(fields[2])
                    mem["swap_free_mb"] = int(fields[3])
                except ValueError:
                    pass

    if mem:
        mem["source"] = "free"
        return mem

    # Fallback: /proc/meminfo (kB values)
    kv = {}
    for line in lines:
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            kv[m.group(1)] = int(m.group(2))
    if kv:
        mem["source"] = "/proc/meminfo"
        if "MemTotal" in kv:
            mem["total_mb"] = round(kv["MemTotal"] / 1024, 1)
        if "MemAvailable" in kv:
            mem["available_mb"] = round(kv["MemAvailable"] / 1024, 1)
        if "MemFree" in kv:
            mem["free_mb"] = round(kv["MemFree"] / 1024, 1)
        if "SwapTotal" in kv:
            mem["swap_total_mb"] = round(kv["SwapTotal"] / 1024, 1)
        if "SwapFree" in kv:
            mem["swap_free_mb"] = round(kv["SwapFree"] / 1024, 1)

    return mem


def _parse_proc_section(chunk: str) -> dict:
    lines = [l for l in chunk.splitlines() if l.strip()]
    result: dict = {"found": False}

    for line in lines:
        if line.startswith("PID="):
            pid_val = line[len("PID="):].strip()
            if pid_val and pid_val != "NONE":
                result["found"] = True
                result["pid"] = pid_val
        elif line.startswith("FD_COUNT="):
            try:
                result["open_file_descriptors"] = int(line[len("FD_COUNT="):].strip())
            except ValueError:
                pass
        else:
            m = _ULIMIT_RE.search(line)
            if m:
                soft, hard = m.group(1), m.group(2)
                result["fd_soft_limit"] = soft if soft == "unlimited" else int(soft)
                result["fd_hard_limit"] = hard if hard == "unlimited" else int(hard)

    if result.get("found") and isinstance(result.get("open_file_descriptors"), int) and isinstance(
        result.get("fd_soft_limit"), int
    ):
        limit = result["fd_soft_limit"]
        if limit > 0:
            result["fd_usage_pct"] = round(result["open_file_descriptors"] / limit * 100, 1)

    return result


def check_resources(
    server_ip: str,
    os_user: str,
    ssh_key: str,
    deployment_directory: str,
    application: str,
) -> dict:
    """SSH to server_ip and check disk (deployment dir, /tmp, root - not every
    mounted filesystem), memory/swap, and the app process's open file
    descriptor count vs. its ulimit. Every one of these is a well-known cause
    of Liberty failures that look like unrelated app errors in the logs.
    """
    deployment_path = f"{deployment_directory.rstrip('/')}/{application}"
    script = _build_resource_script(deployment_path, application)

    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            _exit_status, out, _err = run_command(client, script, timeout=_TIMEOUT)
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "error": f"SSH authentication failed: {e}"}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "error": f"SSH connection failed: {e}"}

    sections = _split_sections(out)

    disk = {}
    for label in _DISK_LABELS:
        disk[label] = _parse_disk_section(sections.get(f"DISK:{label}", ""))

    return {
        "server": server_ip,
        "deployment_path_checked": deployment_path,
        "disk": disk,
        "memory": _parse_mem_section(sections.get("MEM", "")),
        "process": _parse_proc_section(sections.get("PROC", "")),
    }
