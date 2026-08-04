"""Allow ``python -m monarch_mcp_server`` to start the server.

This imports the canonical ``monarch_mcp_server.app`` module, so the tools
register on the same FastMCP instance that ``main()`` runs.
"""

from monarch_mcp_server.app import main

if __name__ == "__main__":
    main()
