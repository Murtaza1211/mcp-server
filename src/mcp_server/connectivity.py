"""Outward-facing connectivity checks in support of IBM Liberty triage.

Complements read_config / list_logs / analyze_logs: those look at the app's
own config and logs, while check_connectivity looks outward - can the box
actually resolve and reach the dependency hosts (DB, LDAP, downstream APIs,
etc.) that its config points at.

A hostname resolving to more than one IP (common for DB replicas, LDAP pairs,
load-balanced backends) is handled explicitly: every IPv4 address returned by
DNS is probed individually, never just "the hostname" (which would let the
OS/shell resolver silently pick one address for you and hide a dead backend
behind a healthy one). IPv6 addresses are filtered out - these deployments
are IPv4-only, so an AAAA record without a working A record would otherwise
be misreported as a DNS failure.
"""

import re
import shlex

import paramiko

from .ssh import run_command, ssh_client

_TCP_PROBE_TIMEOUT = 3  # seconds, per address
_MAX_TARGETS = 50  # sanity cap; this is meant for a handful of known dependencies, not a port scanner

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Marker emitted before each target's output in the batched remote script,
# analogous to the one used in logs.py's batched grep.
_TARGET_MARKER_RE = re.compile(r"\x01\x01T(\d+)\x01\x01\n?")


def _parse_target(raw: str) -> tuple[str, int] | None:
    """Parse a 'host:port' string. Returns None if malformed."""
    if ":" not in raw:
        return None
    host, _, port_str = raw.rpartition(":")
    if not host or not port_str.isdigit():
        return None
    return host, int(port_str)


def _build_target_script(host: str, port: int, index: int) -> str:
    """Remote bash snippet for one target: resolve DNS (IPv4 only), then
    probe every resolved address independently rather than letting the
    shell's own hostname resolution silently pick just one.
    """
    host_q = shlex.quote(host)
    return f"""
printf '\\1\\1T{index}\\1\\1\\n'
ips=$(getent hosts {host_q} 2>/dev/null | awk '{{print $1}}' | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort -u)
if [ -z "$ips" ]; then
  echo "DNS_FAILED"
else
  for ip in $ips; do
    err=$(timeout {_TCP_PROBE_TIMEOUT} bash -c "echo > /dev/tcp/$ip/{port}" 2>&1 >/dev/null)
    rc=$?
    if [ $rc -eq 0 ]; then
      status=connected
    elif [ $rc -eq 124 ]; then
      status=timeout
    elif echo "$err" | grep -qi refused; then
      status=refused
    else
      status=unreachable
    fi
    echo "$status $ip"
  done
fi
""".strip()


def _split_target_output(raw: str, n: int) -> list[str]:
    outputs = [""] * n
    matches = list(_TARGET_MARKER_RE.finditer(raw))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        idx = int(m.group(1))
        if 0 <= idx < n:
            outputs[idx] = raw[start:end]
    return outputs


def _parse_target_result(target: str, chunk: str) -> dict:
    lines = [l for l in chunk.splitlines() if l.strip()]
    if not lines or lines[0] == "DNS_FAILED":
        return {
            "target": target,
            "resolved": False,
            "addresses": [],
            "reachable": False,
            "fully_reachable": False,
            "detail": "dns_failed",
        }

    addresses = []
    for line in lines:
        parts = line.split()
        if len(parts) != 2:
            continue
        status, ip = parts
        addresses.append({"ip": ip, "reachable": status == "connected", "detail": status})

    if not addresses:
        return {
            "target": target,
            "resolved": False,
            "addresses": [],
            "reachable": False,
            "fully_reachable": False,
            "detail": "dns_failed",
        }

    return {
        "target": target,
        "resolved": True,
        "addresses": addresses,
        # reachable: at least one resolved address is reachable ("can the app get through at all")
        "reachable": any(a["reachable"] for a in addresses),
        # fully_reachable: every resolved address is reachable ("is any backend silently down")
        "fully_reachable": all(a["reachable"] for a in addresses),
    }


def check_connectivity(
    server_ip: str,
    os_user: str,
    ssh_key: str,
    targets: list[str],
) -> dict:
    """SSH to server_ip and, for each 'host:port' in `targets`, resolve DNS
    and probe TCP reachability of every resolved IPv4 address individually.

    Every IP a hostname resolves to is probed on its own - if a hostname
    resolves to multiple addresses (e.g. active-active DB replicas), a
    healthy address will not mask a dead one. Both `reachable` (at least one
    address works) and `fully_reachable` (every address works) are reported
    per target, since they answer different triage questions.

    IPv6 addresses are filtered out; these deployments are IPv4-only.
    """
    if not targets:
        return {"server": server_ip, "error": "targets must contain at least one 'host:port' entry", "results": []}
    if len(targets) > _MAX_TARGETS:
        return {
            "server": server_ip,
            "error": f"{len(targets)} targets exceeds the limit of {_MAX_TARGETS}; split into multiple calls",
            "results": [],
        }

    parsed = []
    malformed = []
    for raw in targets:
        p = _parse_target(raw)
        if p is None:
            malformed.append(raw)
        else:
            parsed.append((raw, p))

    if not parsed:
        return {"server": server_ip, "error": "no valid 'host:port' targets given", "malformed_targets": malformed, "results": []}

    script = "\n".join(
        _build_target_script(host, port, i) for i, (_raw, (host, port)) in enumerate(parsed)
    )

    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            timeout = 15 + _TCP_PROBE_TIMEOUT * sum(1 for _ in parsed) * 2  # headroom for multiple IPs per target
            _exit_status, out, _err = run_command(client, script, timeout=timeout)
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "error": f"SSH authentication failed: {e}", "results": []}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "error": f"SSH connection failed: {e}", "results": []}

    chunks = _split_target_output(out, len(parsed))
    results = [_parse_target_result(raw, chunk) for (raw, _p), chunk in zip(parsed, chunks)]

    return {
        "server": server_ip,
        "results": results,
        "malformed_targets": malformed,
    }
