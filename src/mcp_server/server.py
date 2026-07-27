from mcp.server.fastmcp import FastMCP

from .config_reader import read_config as _read_config
from .health_check import check_health as _check_health
from .logs import analyze_logs as _analyze_logs
from .logs import list_logs as _list_logs

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
