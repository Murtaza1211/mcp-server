from mcp.server.fastmcp import FastMCP

from .config_reader import read_config as _read_config
from .connectivity import check_connectivity as _check_connectivity
from .health_check import check_health as _check_health
from .logs import analyze_logs as _analyze_logs
from .logs import list_logs as _list_logs
from .resources import check_resources as _check_resources

mcp = FastMCP("mcp-server")


@mcp.tool()
def read_config(server_ip: str, os_user: str, ssh_key: str, deployment_directory: str, application: str) -> dict:
    """SSH to a server and read a Liberty-style app's server.xml plus jvm.options,
    server.env, bootstrap.properties, and any *.properties files referenced from
    server.xml, with password/token/secret/key values redacted.

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        deployment_directory: Base deployment directory containing the application folder.
        application: Name of the application subfolder to read config from.
    """
    return _read_config(server_ip, os_user, ssh_key, deployment_directory, application)


@mcp.tool()
def health_check(server_ip: str, os_user: str, ssh_key: str, port: int, uri: str, application: str) -> dict:
    """SSH to a server and check an IBM Liberty app's health: an HTTP probe against
    http://127.0.0.1:port/uri (via curl/wget/python3, whichever is present), and a
    process check via `ps -ef` (no JDK/jps/server-status dependency, no root paths).

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        port: Local port the application listens on.
        uri: URI path to request for the HTTP health check (e.g. /health).
        application: Application/server name to look for among running processes.
    """
    return _check_health(server_ip, os_user, ssh_key, port, uri, application)


@mcp.tool()
def list_logs(server_ip: str, os_user: str, ssh_key: str, deployment_directory: str, application: str) -> dict:
    """SSH to a server and enumerate every file under <deployment_directory>/<application>/logs/
    (Liberty's own messages.log/console.log/trace.log/ffdc/*, plus any app-written logs in
    subdirectories), with size, last-modified time, and a rough category for each. Call this
    first, then pass the relevant paths as log_files to analyze_logs - avoids blindly grepping
    every file (trace.log especially can be huge).

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        deployment_directory: Base deployment directory containing the application folder.
        application: Name of the application subfolder whose logs/ directory to list.
    """
    return _list_logs(server_ip, os_user, ssh_key, deployment_directory, application)


@mcp.tool()
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
    """SSH to a server and search the app's logs for the given strings/exception names,
    returning matches with a couple of lines of context. Time filtering is best-effort:
    Liberty log entries carry a leading timestamp but continuation/stack-trace lines don't
    repeat it, so a match is only excluded when a timestamp was actually found and falls
    outside the window - anything unparseable is kept rather than silently dropped.

    If log_files is omitted, every discovered log file is searched, except ones over ~25MB
    (skipped and reported back) - call list_logs first and pass specific log_files to search
    those anyway, or to scope the search down for a large deployment.

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        deployment_directory: Base deployment directory containing the application folder.
        application: Name of the application subfolder whose logs/ directory to search.
        search: Strings or exception names to search for (case-insensitive, literal match).
        start_time: Optional ISO-8601 timestamp; matches before this are excluded when detectable.
        end_time: Optional ISO-8601 timestamp; matches after this are excluded when detectable.
        log_files: Optional list of paths (relative to logs/, as returned by list_logs) to
            restrict the search to. Recommended for large deployments or to include files
            skipped by the size cap.
    """
    return _analyze_logs(
        server_ip, os_user, ssh_key, deployment_directory, application, search, start_time, end_time, log_files
    )


@mcp.tool()
def check_connectivity(server_ip: str, os_user: str, ssh_key: str, targets: list[str]) -> dict:
    """SSH to a server and, for each 'host:port' dependency target, resolve DNS and probe
    TCP reachability. If a hostname resolves to more than one IPv4 address (e.g. active-active
    DB replicas or an LDAP pair), every address is probed individually rather than letting the
    shell's own resolution silently pick one - a healthy address will not mask a dead one.
    IPv6 addresses are filtered out (IPv4-only deployments).

    Both `reachable` (true if at least one resolved address answers) and `fully_reachable`
    (true only if every resolved address answers) are reported per target, since they answer
    different triage questions: "can the app get through at all" vs. "is a backend silently
    down behind a healthy one".

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        targets: List of 'host:port' strings for the dependencies to check (e.g. the DB or
            LDAP hosts referenced in the app's config, as returned by read_config).
    """
    return _check_connectivity(server_ip, os_user, ssh_key, targets)


@mcp.tool()
def check_resources(server_ip: str, os_user: str, ssh_key: str, deployment_directory: str, application: str) -> dict:
    """SSH to a server and check disk, memory, and file-descriptor pressure that could
    explain a Liberty failure that otherwise looks like an unrelated app bug.

    Disk is checked for exactly three filesystems - the one holding
    <deployment_directory>/<application> (where logs/FFDC/work files get written), /tmp
    (where the JVM writes temp files by default), and / (root) - not every mounted
    filesystem, to keep the result focused on what's actually relevant to this app.
    Each disk check reports both space and inode usage, since a full inode table can
    block writes even when there's free space left. Memory reports total/used/free/
    available plus swap. The process check finds the app's PID (same ps -ef approach as
    health_check) and reports its open file descriptor count against its ulimit -
    "too many open files" is one of the most common real-world Liberty failure causes.

    Args:
        server_ip: Hostname or IP address of the server to connect to over SSH.
        os_user: SSH username to authenticate as.
        ssh_key: Path to the private key file (on this machine) used for authentication.
        deployment_directory: Base deployment directory containing the application folder.
        application: Name of the application subfolder (also used to find its process
            among running processes, same as health_check).
    """
    return _check_resources(server_ip, os_user, ssh_key, deployment_directory, application)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
