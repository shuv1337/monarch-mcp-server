"""FastMCP application instance and entry point."""

import logging

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The gql aiohttp transport logs full GraphQL requests/responses at INFO, which
# can include Monarch account payloads. Raise its floor to WARNING so those
# payloads are not written to logs. Transport-level errors still surface; drop
# this to INFO/DEBUG temporarily if you need to trace GraphQL traffic.
logging.getLogger("gql.transport.aiohttp").setLevel(logging.WARNING)

# Initialize FastMCP server
mcp = FastMCP("Monarch Money MCP Server")

# Import tools package to trigger @mcp.tool() registration
import monarch_mcp_server.tools  # noqa: E402, F401

# Export for `mcp run`
app = mcp


def main() -> None:
    """Main entry point for the server."""
    logger.info("Starting Monarch Money MCP Server...")
    try:
        mcp.run()
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


if __name__ == "__main__":
    # When this file is executed directly (``python src/.../app.py`` or
    # ``python -m monarch_mcp_server.app``) it runs as the ``__main__``
    # module, while the tools modules import and register against the
    # canonical ``monarch_mcp_server.app`` module — a *second* instance of
    # this file with its own ``mcp`` object. Running the local ``main()``
    # would start a server with zero tools. Delegate to the canonical
    # module so the server that runs is the one the tools registered on.
    from monarch_mcp_server.app import main as _canonical_main

    _canonical_main()
