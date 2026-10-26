"""Transport selection and real MCP requests through the HTTP ASGI application."""

import json
import time
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from monarch_mcp_server import app


@pytest.fixture(autouse=True)
def isolate_transport(monkeypatch):
    for suffix in ("TRANSPORT", "HOST", "PORT", "ALLOWED_HOSTS", "ALLOWED_ORIGINS"):
        monkeypatch.delenv(f"MONARCH_MCP_{suffix}", raising=False)
    monkeypatch.setattr(app.mcp, "settings", app.mcp.settings.model_copy(deep=True))
    monkeypatch.setattr(app.mcp, "_session_manager", None)
    run = Mock()
    monkeypatch.setattr(app.mcp, "run", run)
    return run


def test_default_remains_stdio(isolate_transport):
    app.main([])
    isolate_transport.assert_called_once_with()


def test_environment_configures_http(monkeypatch, isolate_transport):
    monkeypatch.setenv("MONARCH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MONARCH_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("MONARCH_MCP_PORT", "9000")
    monkeypatch.setenv(
        "MONARCH_MCP_ALLOWED_HOSTS", "mcp.example.com, server.lan:9000, "
    )
    monkeypatch.setenv("MONARCH_MCP_ALLOWED_ORIGINS", "https://client.example.com")
    app.main([])
    isolate_transport.assert_called_once_with(transport="streamable-http")
    assert (app.mcp.settings.host, app.mcp.settings.port) == ("0.0.0.0", 9000)
    security = app.mcp.settings.transport_security
    assert security.enable_dns_rebinding_protection
    assert "server.lan:9000" in security.allowed_hosts
    assert "https://client.example.com" in security.allowed_origins


def test_cli_overrides_environment(monkeypatch, isolate_transport):
    monkeypatch.setenv("MONARCH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("MONARCH_MCP_HOST", "127.0.0.1")
    monkeypatch.setenv("MONARCH_MCP_PORT", "invalid")
    monkeypatch.setenv("MONARCH_MCP_ALLOWED_HOSTS", "old.example.com")
    monkeypatch.setenv("MONARCH_MCP_ALLOWED_ORIGINS", "https://old.example.com")
    app.main(
        [
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "9001",
            "--allowed-host",
            "mcp.example.com",
            "--allowed-host",
            "server.lan:9001",
            "--allowed-origin",
            "https://client.example.com",
        ]
    )
    isolate_transport.assert_called_once_with(transport="streamable-http")
    assert (app.mcp.settings.host, app.mcp.settings.port) == ("0.0.0.0", 9001)
    security = app.mcp.settings.transport_security
    assert "mcp.example.com" in security.allowed_hosts
    assert "server.lan:9001" in security.allowed_hosts
    assert "old.example.com" not in security.allowed_hosts
    assert "https://client.example.com" in security.allowed_origins
    assert "https://old.example.com" not in security.allowed_origins


def test_stdio_overrides_container_default(monkeypatch, isolate_transport):
    monkeypatch.setenv("MONARCH_MCP_TRANSPORT", "streamable-http")
    app.main(["--transport", "stdio"])
    isolate_transport.assert_called_once_with()


@pytest.mark.parametrize("port", ["0", "65536", "-1", "invalid"])
def test_invalid_environment_port_fails(monkeypatch, isolate_transport, port):
    monkeypatch.setenv("MONARCH_MCP_PORT", port)
    with pytest.raises(SystemExit) as exc:
        app.main([])
    assert exc.value.code == 2
    isolate_transport.assert_not_called()


def test_invalid_environment_transport_fails(monkeypatch, isolate_transport):
    monkeypatch.setenv("MONARCH_MCP_TRANSPORT", "invalid")
    with pytest.raises(SystemExit) as exc:
        app.main([])
    assert exc.value.code == 2
    isolate_transport.assert_not_called()


HEADERS = {"Accept": "application/json, text/event-stream"}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "transport-test", "version": "1.0"},
    },
}


def rpc_result(response):
    assert response.status_code == 200, response.text
    # Keep the production SSE response mode, rather than changing server settings.
    data = next(
        line[6:] for line in response.text.splitlines() if line.startswith("data: ")
    )
    return json.loads(data)["result"]


def test_http_initialize_list_and_call_tool(mock_monarch_client):
    app.main(["--transport", "http", "--host", "0.0.0.0"])
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert rpc_result(response)["serverInfo"]["name"] == "Monarch Money MCP Server"
        headers = {**HEADERS, "Mcp-Session-Id": response.headers["mcp-session-id"]}
        initialized = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )
        assert initialized.status_code == 202
        listed = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
        )
        assert "get_accounts" in {tool["name"] for tool in rpc_result(listed)["tools"]}
        called = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "get_accounts", "arguments": {}},
            },
        )
        result = rpc_result(called)
        assert not result.get("isError")
        assert "Checking Account" in result["content"][0]["text"]
        mock_monarch_client.get_accounts.assert_awaited_once()
        assert client.delete("/mcp", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "headers,status",
    [
        ({"Host": "evil.example"}, 421),
        ({"Origin": "https://evil.example"}, 403),
        ({"Origin": "null"}, 403),
        ({"Origin": "http://localhost"}, 200),
        ({"Host": "localhost"}, 200),
    ],
)
def test_http_validates_host_and_origin(headers, status):
    app.main(["--transport", "http", "--host", "0.0.0.0"])
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post("/mcp", headers={**HEADERS, **headers}, json=INITIALIZE)
        assert response.status_code == status


def test_http_allows_configured_remote_host_and_origin():
    app.main(
        [
            "--transport",
            "http",
            "--allowed-host",
            "mcp.example.com",
            "--allowed-origin",
            "https://client.example.com",
        ]
    )
    with TestClient(
        app.mcp.streamable_http_app(), base_url="https://mcp.example.com"
    ) as client:
        response = client.post(
            "/mcp",
            json=INITIALIZE,
            headers={
                **HEADERS,
                "Origin": "https://client.example.com",
            },
        )
        assert "serverInfo" in rpc_result(response)


def test_http_deleted_session_is_reclaimed():
    """Ending a session must release its retained state, not just disable it."""
    app.main(["--transport", "http"])
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert "serverInfo" in rpc_result(response)
        session_id = response.headers["mcp-session-id"]
        manager = app.mcp.session_manager
        assert session_id in manager._server_instances
        headers = {**HEADERS, "Mcp-Session-Id": session_id}
        assert client.delete("/mcp", headers=headers).status_code == 200
        assert session_id not in manager._server_instances


def test_http_refused_opening_request_does_not_retain_session():
    """A rejected Host must not leave an orphan session and running task."""
    app.main(["--transport", "http"])
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post(
            "/mcp", headers={**HEADERS, "Host": "evil.example"}, json=INITIALIZE
        )
        assert response.status_code == 421
        assert not app.mcp.session_manager._server_instances


def test_http_trailing_slash_never_redirects_tool_payload():
    """Keep the application's nonredirecting MCP endpoint across SDK updates."""
    app.main(["--transport", "http"])
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post(
            "/mcp/",
            headers={**HEADERS, "Host": "evil.example"},
            json=INITIALIZE,
            follow_redirects=False,
        )
        assert response.status_code == 404
        assert "location" not in response.headers


def test_http_session_limit_rejects_new_sessions_but_preserves_existing():
    """Bound retained sessions while allowing an existing client to finish."""
    app.main(["--transport", "http"])
    app.mcp.settings.max_sessions = 1
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        first = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert "serverInfo" in rpc_result(first)
        second = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert second.status_code == 503
        headers = {**HEADERS, "Mcp-Session-Id": first.headers["mcp-session-id"]}
        assert client.post(
            "/mcp", headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        ).status_code == 202
        listed = client.post(
            "/mcp", headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert "tools" in rpc_result(listed)
        assert client.delete("/mcp", headers=headers).status_code == 200
        replacement = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert "serverInfo" in rpc_result(replacement)


def test_http_session_retention_defaults_are_bounded():
    """Do not silently lose the patched SDK's idle, count, or body limits."""
    app.main(["--transport", "http"])
    app.mcp.streamable_http_app()
    manager = app.mcp.session_manager
    assert 0 < manager.session_idle_timeout <= 1800
    assert 0 < manager.max_sessions <= 10000
    assert 0 < manager.max_request_body_size <= 4 * 1024 * 1024


def test_http_idle_session_expires_and_rejects_stale_id():
    app.main(["--transport", "http"])
    app.mcp.settings.session_idle_timeout = 0.1
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
        assert "serverInfo" in rpc_result(response)
        session_id = response.headers["mcp-session-id"]
        deadline = time.monotonic() + 3
        while session_id in app.mcp.session_manager._server_instances:
            assert time.monotonic() < deadline, "Idle session was not reclaimed"
            time.sleep(0.02)
        stale = client.post(
            "/mcp", headers={**HEADERS, "Mcp-Session-Id": session_id},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert stale.status_code == 404


def test_http_oversized_chunked_body_is_rejected_without_retained_session():
    app.main(["--transport", "http"])
    app.mcp.settings.max_request_body_size = 128
    with TestClient(
        app.mcp.streamable_http_app(), base_url="http://localhost:8000"
    ) as client:
        response = client.post(
            "/mcp", headers={**HEADERS, "Content-Type": "application/json"},
            content=iter([b" " * 64, b" " * 65]),
        )
        assert "content-length" not in response.request.headers
        assert response.request.headers["transfer-encoding"] == "chunked"
        assert response.status_code == 413
        assert not app.mcp.session_manager._server_instances
