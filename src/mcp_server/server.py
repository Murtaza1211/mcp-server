from mcp.server.fastmcp import FastMCP

from .config_reader import read_config as _read_config

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
