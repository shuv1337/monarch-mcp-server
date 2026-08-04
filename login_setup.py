#!/usr/bin/env python3
"""
Standalone script to perform interactive Monarch Money login.

Supports three auth paths in order of recommendation:

1. Session cookies pasted from a logged-in browser. Long-lived, works
   for all account types including SSO, sidesteps Cloudflare CAPTCHA.
2. Email and password (with optional email OTP and MFA prompts). Now
   requests a long-lived session token from Monarch.
3. Legacy session token paste. Kept for users with a working token
   captured under the old auth model.
"""

import argparse
import asyncio
import getpass
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from monarchmoney import CaptchaRequiredException, RequireMFAException
from monarch_mcp_server.monarch_auth import (
    EmailOtpRequiredException,
    create_monarch_client,
    login_with_browser_cookies,
    login_with_current_auth,
)
from monarch_mcp_server.secure_session import secure_session


def _read_cookie_file(cookie_file: Path) -> str:
    """Read a cookie header from an owner-only regular file.

    The file is opened without following symlinks where the platform supports
    it, then checked through the open descriptor to avoid a path-swap race.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(cookie_file, flags)
    except OSError as exc:
        raise ValueError("Could not open the cookie file.") from exc

    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("Cookie input must be a regular file.")
        if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError(
                "Cookie file permissions are too broad; run chmod 600 on it."
            )

        with os.fdopen(fd, encoding="utf-8") as handle:
            fd = -1
            cookie_string = handle.read().strip()
    finally:
        if fd >= 0:
            os.close(fd)

    if not cookie_string:
        raise ValueError("Cookie file is empty.")
    return cookie_string


def _read_macos_clipboard() -> str:
    """Read the macOS clipboard without writing its contents to the terminal."""
    try:
        result = subprocess.run(
            ["pbpaste"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Could not read the macOS clipboard with pbpaste.") from exc

    cookie_string = result.stdout.strip()
    if not cookie_string:
        raise ValueError("The macOS clipboard is empty.")
    return cookie_string


def _read_cookie_header(cookie_file: Optional[Path] = None) -> str:
    if cookie_file is not None:
        return _read_cookie_file(cookie_file)

    if sys.platform == "darwin":
        input(
            "Copy the Cookie header, then press Return to read it from the clipboard: "
        )
        return _read_macos_clipboard()

    cookie_path = input("Path to an owner-only Cookie header file: ").strip()
    if not cookie_path:
        raise ValueError("No cookie file path provided.")
    return _read_cookie_file(Path(cookie_path).expanduser())


async def _login_with_cookies(cookie_file: Optional[Path] = None):
    print("\n📋 To copy the right cookie string:")
    print("  1. Log in to https://app.monarch.com in Chrome or Firefox")
    print("  2. Open DevTools (F12) → Network tab")
    print("  3. Click any request whose Name starts with 'graphql'")
    print("     (or any request to api.monarch.com)")
    print("  4. Scroll to 'Request Headers' and find the 'cookie:' header")
    print("  5. Copy the full value (a long string of key=value; pairs)")
    if sys.platform == "darwin" and cookie_file is None:
        print(
            "  6. Return here; the script will read it with pbpaste without echoing it"
        )
    elif cookie_file is None:
        print("  6. Save it to an owner-only file (chmod 600) and provide its path")
    print()
    try:
        cookie_string = _read_cookie_header(cookie_file)
    except ValueError as exc:
        print(f"❌ {exc}")
        return None
    try:
        mm = await login_with_browser_cookies(cookie_string)
        print("✅ Cookie login successful")
        return mm
    except Exception as e:
        print(f"❌ Cookie login failed ({type(e).__name__}).")
        return None


async def _login_with_password():
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    try:
        mm = await login_with_current_auth(email, password)
        print("✅ Login successful")
        return mm
    except CaptchaRequiredException as e:
        print(f"❌ {e}")
        print("Re-run this script and choose option 1 (session cookies).")
        return None
    except EmailOtpRequiredException:
        print("📧 Monarch sent a verification code to your email.")
        code = input("Email verification code: ").strip()
        if not code:
            print("❌ No code provided. Exiting.")
            return None
        try:
            mm = await login_with_current_auth(email, password, email_otp=code)
        except RequireMFAException:
            mfa_code = input("Two Factor Code: ").strip()
            mm = await login_with_current_auth(
                email, password, email_otp=code, mfa_code=mfa_code
            )
        print("✅ Email verification successful")
        return mm
    except RequireMFAException:
        mfa_code = input("Two Factor Code: ").strip()
        if not mfa_code:
            print("❌ No MFA code provided. Exiting.")
            return None
        mm = await login_with_current_auth(email, password, mfa_code=mfa_code)
        print("✅ MFA authentication successful")
        return mm


def _login_with_legacy_token():
    print("\n📋 To get a legacy session token:")
    print("  1. Log in to https://app.monarch.com in Chrome or Firefox")
    print("  2. DevTools (F12) → Application tab → Local Storage")
    print("     → https://app.monarch.com → key 'token'")
    print("  3. Copy the value")
    print()
    print(
        "⚠️  Monarch may no longer accept Authorization: Token auth on the "
        "GraphQL endpoint. If the test call below fails with 401, re-run "
        "this script and choose option 1 (cookies) instead."
    )
    token = getpass.getpass("Paste your session token: ").strip()
    if not token:
        print("❌ No token provided. Exiting.")
        return None
    mm = create_monarch_client(token=token)
    print("✅ Token configured")
    return mm


async def _verify_and_save_session(mm) -> bool:
    """Verify a replacement session before allowing it to replace storage."""
    print("\nTesting connection...")
    try:
        accounts = await mm.get_accounts()
        if accounts and isinstance(accounts, dict):
            print("✅ Connection verified")
        else:
            print(f"❌ Unexpected accounts response: {type(accounts)}")
            return False
    except Exception as test_error:
        print(f"❌ Connection test failed ({type(test_error).__name__}).")
        print(
            "\nIf this looks like 401 Unauthorized, the cookie or token "
            "is invalid. The existing saved session has not been changed."
        )
        return False

    try:
        print("\n🔐 Saving session securely to system keyring...")
        secure_session.save_authenticated_session(mm)
        print("✅ Session saved")
        return True
    except Exception as save_error:
        print(f"❌ Could not save session ({type(save_error).__name__}).")
        return False


async def main(cookie_file: Optional[Path] = None):
    print("\n🏦 Monarch Money - Claude Desktop Setup")
    print("=" * 45)
    print("This will authenticate you once and save a session")
    print("for seamless access through Claude Desktop.\n")

    try:
        import monarchmoney

        print(
            f"📦 MonarchMoney version: "
            f"{getattr(monarchmoney, '__version__', 'unknown')}"
        )
    except Exception as e:
        print(f"⚠️  Could not check version: {e}")

    try:
        print("\nHow do you sign in to Monarch Money?")
        print(
            "  1) Session cookies from browser   "
            "(recommended: long-lived, supports SSO)"
        )
        print("  2) Email and password")
        print("  3) Legacy session token paste")
        choice = input("Choice [1]: ").strip() or "1"

        mm = None
        if choice == "1":
            mm = await _login_with_cookies(cookie_file)
        elif choice == "2":
            mm = await _login_with_password()
        elif choice == "3":
            mm = _login_with_legacy_token()
        else:
            print(f"❌ Unrecognized choice: {choice!r}. Exiting.")
            return

        if mm is None:
            return

        if not await _verify_and_save_session(mm):
            return

        print("\n🎉 Setup complete. Restart Claude Desktop to pick up the session.")
        print("\n💡 Useful tools in Claude:")
        print("   • get_accounts - View all your accounts")
        print("   • get_transactions - Recent transactions")
        print("   • get_budgets - Budget information")
        print("   • get_cashflow - Income/expense analysis")

    except Exception as e:
        print(f"\n❌ Login failed ({type(e).__name__}).")


def _parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cookie-file",
        type=Path,
        help="Read the Cookie header from an owner-only regular file (chmod 600).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    asyncio.run(main(cookie_file=args.cookie_file))
