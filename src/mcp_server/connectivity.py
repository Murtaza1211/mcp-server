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
    """Remote bash snippet for one target: resolve DNS (IPv4 only, skipped
    entirely for literal-IP targets), then probe every resolved address
    independently and in parallel.

    Literal IPs bypass DNS completely rather than calling getent on them:
    getent hosts on an IP does a *reverse* (PTR) lookup, not a no-op - in
    environments where reverse DNS isn't maintained (common; forward zones
    get more upkeep than reverse ones), that reverse lookup can be slow or
    fail outright, for a question ("is this reachable") that never needed
    resolution in the first place.

    Each resolved address is probed with a Python socket connect+settimeout
    when python3 is available, since `timeout N bash -c "echo > /dev/tcp/..."`
    doesn't reliably enforce its timeout when a connection is silently
    dropped (no RST/ICMP) rather than actively refused - the outer `timeout`
    sends SIGTERM expecting to interrupt a blocked connect() syscall, but the
    shell can ride out the OS's own SYN-retry timeout instead, which is far
    longer. Falls back to the bash /dev/tcp approach only if python3 isn't
    present, matching how health_check.py already falls back between
    curl/wget/python3 for its HTTP probe.

    Probes for all resolved addresses of one target run in parallel
    (backgrounded, collected via `wait`), not sequentially - the difference
    between paying the sum of every address's timeout vs. just the slowest
    one.
    """
    if _IPV4_RE.match(host):
        # Literal IP target: no DNS step at all, forward or reverse.
        resolve_block = f'ips="{host}"'
    else:
        host_q = shlex.quote(host)
        resolve_block = (
            f"ips=$(timeout 5 getent hosts {host_q} 2>/dev/null | awk '{{print $1}}' "
            r"| grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)"
        )

    probe_snippet = f'''python3 - "$ip" {port} <<'PYEOF' 2>/dev/null
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout({_TCP_PROBE_TIMEOUT})
try:
    s.connect((ip, port))
    print("connected")
except socket.timeout:
    print("timeout")
except ConnectionRefusedError:
    print("refused")
except OSError:
    print("unreachable")
finally:
    s.close()
PYEOF
'''

    return f"""
printf '\\1\\1T{index}\\1\\1\\n'
{resolve_block}
if [ -z "$ips" ]; then
  echo "DNS_FAILED"
else
  tmp_{index}=$(mktemp)
  for ip in $ips; do
    (
      if command -v python3 >/dev/null 2>&1; then
        result=$({probe_snippet})
        [ -z "$result" ] && result=unreachable
      else
        err=$(timeout {_TCP_PROBE_TIMEOUT} bash -c "echo > /dev/tcp/$ip/{port}" 2>&1 >/dev/null)
        rc=$?
        if [ $rc -eq 0 ]; then
          result=connected
        elif [ $rc -eq 124 ]; then
          result=timeout
        elif echo "$err" | grep -qi refused; then
          result=refused
        else
          result=unreachable
        fi
      fi
      echo "$result $ip" >> "$tmp_{index}"
    ) &
  done
  wait
  cat "$tmp_{index}"
  rm -f "$tmp_{index}"
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
