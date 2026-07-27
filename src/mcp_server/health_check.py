"""HTTP and process health checks for an IBM Liberty server, run over SSH.

Assumes a non-root SSH user with no access to root-owned paths, and no JDK
installed on the target host - so no `jps`/`jcmd`/`server status`. Process
detection instead greps `ps -ef` output, and the HTTP check shells out to
whatever of curl/wget/python3 is actually present on the box.
"""

import shlex

import paramiko

from .ssh import ssh_client

_EXEC_TIMEOUT = 15

_HTTP_CHECK_SCRIPT_TEMPLATE = r"""URL=__URL__
if command -v curl >/dev/null 2>&1; then
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O /dev/null -S --timeout=5 "$URL" 2>&1 | awk '/HTTP\//{code=$2} END{if (code) print code; else print "000"}'
elif command -v python3 >/dev/null 2>&1; then
  python3 -c '
import sys, urllib.request, urllib.error
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=5)
    print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print("000")
' "$URL"
else
  echo NO_HTTP_CLIENT
fi
"""

_PROCESS_CHECK_SCRIPT_TEMPLATE = r"""APP=__APP__
MATCH=$(ps -ef 2>/dev/null | grep -F -- "$APP" | grep java | grep -v grep | head -5)
if [ -n "$MATCH" ]; then
  PID=$(echo "$MATCH" | head -1 | awk '{print $2}')
  printf 'RUNNING\t%s\n' "$PID"
  echo "$MATCH"
else
  echo NOT_RUNNING
fi
"""


def _build_http_check_script(port: int, uri: str) -> str:
    path = uri if uri.startswith("/") else f"/{uri}"
    url = f"http://127.0.0.1:{port}{path}"
    return _HTTP_CHECK_SCRIPT_TEMPLATE.replace("__URL__", shlex.quote(url))


def _build_process_check_script(application: str) -> str:
    return _PROCESS_CHECK_SCRIPT_TEMPLATE.replace("__APP__", shlex.quote(application))


def _run(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=_EXEC_TIMEOUT)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return exit_status, out, err


def _http_check(client: paramiko.SSHClient, port: int, uri: str) -> dict:
    try:
        _exit_status, out, err = _run(client, _build_http_check_script(port, uri))
    except (paramiko.SSHException, OSError) as e:
        return {"reachable": None, "status_code": None, "healthy": None, "detail": f"exec failed: {e}"}

    output = out.strip()
    if output == "NO_HTTP_CLIENT":
        return {
            "reachable": None,
            "status_code": None,
            "healthy": None,
            "detail": "neither curl, wget, nor python3 available on target host",
        }
    if output.isdigit() and len(output) == 3:
        code = int(output)
        if code == 0:
            return {
                "reachable": False,
                "status_code": None,
                "healthy": False,
                "detail": "connection failed (port not reachable or connection refused)",
            }
        return {"reachable": True, "status_code": code, "healthy": 200 <= code < 400, "detail": f"HTTP {code}"}
    return {
        "reachable": None,
        "status_code": None,
        "healthy": None,
        "detail": f"unexpected output: {output!r} (stderr: {err.strip()})",
    }


def _process_check(client: paramiko.SSHClient, application: str) -> dict:
    try:
        _exit_status, out, err = _run(client, _build_process_check_script(application))
    except (paramiko.SSHException, OSError) as e:
        return {"running": None, "pid": None, "detail": f"exec failed: {e}"}

    lines = out.splitlines()
    if not lines or lines[0].strip() == "NOT_RUNNING":
        return {"running": False, "pid": None, "detail": "no matching java process found"}
    if lines[0].startswith("RUNNING\t"):
        pid = lines[0].split("\t", 1)[1].strip()
        return {"running": True, "pid": pid, "detail": "\n".join(lines[1:]).strip()}
    return {"running": None, "pid": None, "detail": f"unexpected output: {out!r} (stderr: {err.strip()})"}


def check_health(server_ip: str, os_user: str, ssh_key: str, port: int, uri: str, application: str) -> dict:
    """SSH to server_ip and report HTTP reachability plus process status for application."""
    try:
        with ssh_client(server_ip, os_user, ssh_key) as client:
            http_result = _http_check(client, port, uri)
            process_result = _process_check(client, application)
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "application": application, "error": f"SSH authentication failed: {e}"}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "application": application, "error": f"SSH connection failed: {e}"}

    return {
        "server": server_ip,
        "application": application,
        "http": http_result,
        "process": process_result,
    }
