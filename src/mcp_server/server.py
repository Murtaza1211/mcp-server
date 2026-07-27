from mcp.server.fastmcp import FastMCP

from .config_reader import read_config as _read_config
from .health_check import check_health as _check_health

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
