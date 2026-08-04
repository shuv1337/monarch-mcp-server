"""Authentication tools."""

import logging

from mcp.server.fastmcp import Context

from monarch_mcp_server import auth
from monarch_mcp_server.app import mcp
from monarch_mcp_server.secure_session import secure_session

logger = logging.getLogger(__name__)


def _stored_auth_mode() -> str | None:
    session = secure_session.load_session()
    if not session:
        return None
    if isinstance(session.get("cookies"), dict) and session["cookies"]:
        return "cookie"
    if isinstance(session.get("token"), str) and session["token"]:
        return "token"
    return None


@mcp.tool()
async def setup_authentication() -> str:
    """Get instructions for setting up secure authentication with Monarch Money."""
    return """🔐 Monarch Money - Authentication Setup

Authentication is intentionally performed outside MCP so credentials,
cookies, tokens, and MFA codes never enter the model-facing tool surface.

From a local terminal:
   Run in terminal: python login_setup.py
   On macOS, browser cookies are read directly from the clipboard with
   pbpaste and are never echoed. A chmod 600 cookie file is also supported.

✅ Session persists across restarts
✅ Verified session stored securely in system keyring"""


async def monarch_login(ctx: Context) -> str:
    """Sign in to Monarch Money.

    Opens a secure form in the client UI to collect email, password, and
    (if required) an MFA code. Credentials never pass through the model —
    they flow client-UI → server directly via the MCP protocol.
    """
    return await auth.login_interactive(ctx)


async def monarch_login_with_token(ctx: Context) -> str:
    """Sign in to Monarch Money using a browser-copied session token.

    Useful for SSO users who can't use password login. Grab the token from
    browser DevTools → Application → Local Storage → app.monarchmoney.com.
    """
    return await auth.login_with_token_interactive(ctx)


async def monarch_logout() -> str:
    """Clear the stored Monarch Money session from the system keyring."""
    return await auth.logout()


@mcp.tool()
async def check_auth_status() -> str:
    """Check if already authenticated with Monarch Money."""
    try:
        auth_mode = _stored_auth_mode()
        if auth_mode:
            return (
                "✅ Authenticated session found in secure storage "
                f"(auth_mode={auth_mode}).\n"
                "💡 Try get_accounts to test the live connection."
            )
        return (
            "❌ No authenticated session found in secure storage.\n"
            "Run login_setup.py from a local terminal."
        )
    except Exception as e:
        return f"Error checking auth status ({type(e).__name__})."


@mcp.tool()
async def debug_session_loading() -> str:
    """Debug keyring session loading issues."""
    try:
        auth_mode = _stored_auth_mode()
        if auth_mode:
            return f"✅ Session found in secure storage (auth_mode={auth_mode})."
        return "❌ No session found in secure storage. Run login_setup.py."
    except Exception as e:
        logger.warning("Keyring access failed (%s)", type(e).__name__)
        return f"❌ Keyring access failed ({type(e).__name__})."
