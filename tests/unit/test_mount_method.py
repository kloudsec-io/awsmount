"""Mount-method selection and doctor wording (macOS FUSE is optional)."""

from __future__ import annotations

from pathlib import Path

import pytest

from awsmount import doctor

SRC = Path(doctor.__file__).resolve().parent


def test_macos_auto_prefers_webdav_even_when_fuse_is_installed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """FUSE-T/macFUSE being present must not change the default."""
    monkeypatch.setattr(doctor._platform, "os_name", lambda: "macos")
    monkeypatch.setattr(doctor, "fuse_usable", lambda: (True, ""))
    assert doctor.preferred_mount_method() == "webdav"


def test_linux_auto_uses_fuse(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux has open-source libfuse; FUSE stays the Linux default."""
    monkeypatch.setattr(doctor._platform, "os_name", lambda: "linux")
    assert doctor.preferred_mount_method() == "fuse"


def test_unknown_os_has_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows and others get no automatic mount method."""
    monkeypatch.setattr(doctor._platform, "os_name", lambda: "windows")
    assert doctor.preferred_mount_method() is None


def test_no_message_tells_users_to_install_fuse_t() -> None:
    """awsmount must not nudge anyone toward closed-source FUSE-T."""
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if "brew install fuse-t" in path.read_text(encoding="utf-8")]
    assert offenders == []


def test_optional_status_exists_and_is_not_missing() -> None:
    """FUSE layers on macOS are reported as optional, not MISSING."""
    assert doctor.OPTIONAL == "optional"
    assert doctor.OPTIONAL != doctor.MISSING
