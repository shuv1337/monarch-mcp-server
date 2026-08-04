"""Tests for security-sensitive MCP tool registration."""

import asyncio

from monarch_mcp_server.app import mcp
from monarch_mcp_server.tools.auth import setup_authentication


def test_authentication_mutations_are_not_registered_as_mcp_tools():
    exposed_tools = set(mcp._tool_manager._tools)

    assert "monarch_login" not in exposed_tools
    assert "monarch_login_with_token" not in exposed_tools
    assert "monarch_logout" not in exposed_tools
    assert {"setup_authentication", "check_auth_status"} <= exposed_tools


def test_setup_instructions_require_out_of_band_authentication():
    instructions = asyncio.run(setup_authentication())

    assert "outside MCP" in instructions
    assert "login_setup.py" in instructions
    assert "pbpaste" in instructions
