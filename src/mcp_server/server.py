from mcp.server.fastmcp import FastMCP

from .config_reader import read_config as _read_config

mcp = FastMCP("mcp-server")


@mcp.tool()
def read_config(deployment_directory: str, application: str) -> dict:
    """Read a Liberty-style app's server.xml plus jvm.options, server.env,
    bootstrap.properties, and any *.properties files referenced from server.xml,
    with password/token/secret/key values redacted.

    Args:
        deployment_directory: Base deployment directory containing the application folder.
        application: Name of the application subfolder to read config from.
    """
    return _read_config(deployment_directory, application)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
