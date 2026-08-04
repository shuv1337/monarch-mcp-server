"""Regression tests for out-of-band authentication setup."""

import asyncio
import stat
import subprocess
from unittest.mock import AsyncMock, MagicMock

import pytest

import login_setup


def test_macos_clipboard_read_does_not_echo_cookie(monkeypatch, capsys):
    cookie = "session_id=synthetic; csrftoken=synthetic"
    completed = subprocess.CompletedProcess(["pbpaste"], 0, stdout=cookie)
    run = MagicMock(return_value=completed)
    monkeypatch.setattr(login_setup.subprocess, "run", run)

    assert login_setup._read_macos_clipboard() == cookie
    run.assert_called_once_with(
        ["pbpaste"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    output = capsys.readouterr()
    assert cookie not in output.out
    assert cookie not in output.err


def test_cookie_file_requires_owner_only_permissions(tmp_path):
    cookie_file = tmp_path / "cookie.txt"
    cookie_file.write_text("session_id=synthetic")
    cookie_file.chmod(0o644)

    with pytest.raises(ValueError, match="chmod 600"):
        login_setup._read_cookie_file(cookie_file)


def test_cookie_file_accepts_private_regular_file(tmp_path):
    cookie_file = tmp_path / "cookie.txt"
    cookie_file.write_text("session_id=synthetic\n")
    cookie_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

    assert login_setup._read_cookie_file(cookie_file) == "session_id=synthetic"


def test_failed_replacement_keeps_existing_session(monkeypatch, capsys):
    class FakeSession:
        current = "existing-session"

        def save_authenticated_session(self, _mm):
            self.current = "replacement-session"

        def delete_token(self):
            self.current = None

    fake_session = FakeSession()
    monkeypatch.setattr(login_setup, "secure_session", fake_session)
    mm = AsyncMock()
    mm.get_accounts.side_effect = RuntimeError("synthetic sensitive failure")

    saved = asyncio.run(login_setup._verify_and_save_session(mm))

    assert saved is False
    assert fake_session.current == "existing-session"
    assert "synthetic sensitive failure" not in capsys.readouterr().out


def test_replacement_is_saved_only_after_live_verification(monkeypatch):
    events = []
    mm = AsyncMock()

    async def get_accounts():
        events.append("verified")
        return {"accounts": []}

    mm.get_accounts.side_effect = get_accounts

    class FakeSession:
        def save_authenticated_session(self, received_mm):
            assert received_mm is mm
            events.append("saved")

    monkeypatch.setattr(login_setup, "secure_session", FakeSession())

    assert asyncio.run(login_setup._verify_and_save_session(mm)) is True
    assert events == ["verified", "saved"]
