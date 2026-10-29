"""Mount-method diagnostics (``awsmount doctor``, ARCHITECTURE: Command line).

No AWS call is made unless credential checks are requested; then one
``sts get_caller_identity`` per profile goes through the guarded client
factory.
"""

from __future__ import annotations

import ctypes.util
import importlib
import importlib.util
import os
import shutil
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from awsmount import platform as _platform

__all__ = [
    "Check",
    "DoctorReport",
    "FAIL",
    "MISSING",
    "OPTIONAL",
    "NA",
    "OK",
    "credential_checks",
    "fuse_usable",
    "linux_fuse_library",
    "mfusepy_status",
    "package_available",
    "preferred_mount_method",
    "run_doctor",
]

OK = "OK"
MISSING = "MISSING"
FAIL = "FAIL"
OPTIONAL = "optional"
NA = "N/A"

MOUNT_WEBDAV = "/sbin/mount_webdav"
FUSE_T_LIB = "/usr/local/lib/libfuse-t.dylib"
MACFUSE_FS = "/Library/Filesystems/macfuse.fs"
PACKAGES = ("boto3", "click", "prompt_toolkit", "wsgidav", "cheroot",
            "mfusepy")

AddCheck = Callable[["Check"], None]


@dataclass(frozen=True)
class Check:
    """One diagnostic row: ``method | status | detail``."""

    method: str
    status: str
    detail: str

    @property
    def ok(self) -> bool:
        """True when the status is OK."""
        return self.status == OK


@dataclass
class DoctorReport:
    """All checks plus the per-method summary."""

    checks: list[Check] = field(default_factory=list)
    summary: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        """``shell: OK · webdav-serve: OK · ...``."""
        return " \u00b7 ".join(f"{k}: {v}" for k, v in self.summary.items())

    def render_text(self) -> str:
        """Aligned table followed by the summary line."""
        rows = [("method", "status", "detail")] + [
            (c.method, c.status, c.detail) for c in self.checks]
        width0 = max(len(r[0]) for r in rows)
        width1 = max(len(r[1]) for r in rows)
        lines = [f"{a:<{width0}} | {b:<{width1}} | {c}".rstrip()
                 for a, b, c in rows]
        lines.append("")
        lines.append(self.summary_line())
        return "\n".join(lines) + "\n"

    def to_json(self) -> dict[str, Any]:
        """JSON-serialisable form."""
        return {"checks": [asdict(c) for c in self.checks],
                "summary": dict(self.summary)}


def package_available(name: str) -> bool:
    """True when ``name`` can be imported (without importing it)."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def mfusepy_status() -> tuple[bool, str]:
    """Whether mfusepy imports (it loads libfuse at import time)."""
    if not package_available("mfusepy"):
        return False, "pip install mfusepy"
    _platform.prefer_libfuse3()
    try:
        importlib.import_module("mfusepy")
    except Exception as exc:
        return False, f"installed but cannot load libfuse: {exc}"
    return True, "loads"


def linux_fuse_library() -> str | None:
    """libfuse3 (or libfuse 2) shared library name, if found."""
    return ctypes.util.find_library("fuse3") or \
        ctypes.util.find_library("fuse")


def _linux_checks(add: AddCheck, mfusepy_ok: bool) -> tuple[bool, str]:
    lib = linux_fuse_library()
    add(Check("libfuse", OK if lib else MISSING,
              lib or "apt install fuse3"))
    dev = os.path.exists("/dev/fuse") and \
        os.access("/dev/fuse", os.R_OK | os.W_OK)
    add(Check("/dev/fuse", OK if dev else MISSING,
              "read/write" if dev else
              "missing or not accessible (Docker: --device /dev/fuse "
              "--cap-add SYS_ADMIN)"))
    tool = shutil.which("fusermount3") or shutil.which("fusermount")
    add(Check("fusermount", OK if tool else MISSING,
              tool or "apt install fuse3"))
    if not lib or not tool:
        return False, "apt install fuse3"
    if not dev:
        return False, "/dev/fuse not accessible"
    if not mfusepy_ok:
        return False, "pip install mfusepy"
    return True, ""


def _macos_checks(add: AddCheck, mfusepy_ok: bool) -> tuple[bool, str]:
    webdav = os.access(MOUNT_WEBDAV, os.X_OK)
    add(Check("mount_webdav", OK if webdav else MISSING,
              MOUNT_WEBDAV if webdav else f"{MOUNT_WEBDAV} not found"))
    fuse_t = os.path.exists(FUSE_T_LIB)
    add(Check("fuse-t", OK if fuse_t else OPTIONAL,
              FUSE_T_LIB if fuse_t else
              "not installed; not needed (WebDAV mount works)"))
    macfuse = os.path.exists(MACFUSE_FS)
    add(Check("macfuse", OK if macfuse else OPTIONAL,
              MACFUSE_FS if macfuse else
              "not installed; not needed (WebDAV mount works)"))
    if not (fuse_t or macfuse):
        return False, "not needed, WebDAV mount works"
    if not mfusepy_ok:
        return False, "pip install mfusepy"
    return True, ""


def _ignore(check: Check) -> None:
    return None


def fuse_usable() -> tuple[bool, str]:
    """``(usable, hint)`` for a FUSE mount on this machine."""
    osn = _platform.os_name()
    if osn == "linux":
        return _linux_checks(_ignore, mfusepy_status()[0])
    if osn == "macos":
        return _macos_checks(_ignore, mfusepy_status()[0])
    return False, "unsupported OS"


def preferred_mount_method() -> str | None:
    """``--method auto``: Linux -> fuse; macOS -> webdav; others -> None.

    On macOS the built-in WebDAV mount is always preferred: it needs no
    install and no admin rights, and it is the tested path. FUSE on macOS
    (FUSE-T or macFUSE, both third-party) is used only when explicitly
    requested with ``--method fuse``.
    """
    osn = _platform.os_name()
    if osn == "linux":
        return "fuse"
    if osn == "macos":
        return "webdav"
    return None


def credential_checks(profiles: Sequence[str | None],
                      endpoint_url: str | None = None) -> list[Check]:
    """One ``sts get_caller_identity`` per profile."""
    from awsmount.config import Config
    from awsmount.session.budget import ApiBudget
    from awsmount.session.clients import ClientFactory
    from awsmount.session.progress import Progress

    checks: list[Check] = []
    config = Config(profiles=tuple(profiles) or (None,),
                    endpoint_url=endpoint_url, max_api_calls=0)
    budget = ApiBudget(0, 0)
    factory = ClientFactory(config, budget,
                            Progress(False, sys.stderr, budget),
                            frozenset())
    for profile in config.profiles:
        label = profile or "default"
        try:
            region = factory.session(profile).region_name or "us-east-1"
            sts = factory.get(profile, region, "sts")
            ident = sts.get_caller_identity()
        except Exception as exc:
            checks.append(Check(f"credentials:{label}", FAIL,
                                f"{type(exc).__name__}: {exc}"))
            continue
        checks.append(Check(f"credentials:{label}", OK,
                            f"{ident.get('Account')} {ident.get('Arn')}"))
    return checks


def run_doctor(*, check_credentials: bool = False,
               profiles: Sequence[str | None] = (None,),
               endpoint_url: str | None = None) -> DoctorReport:
    """Run every check for this machine."""
    report = DoctorReport()
    add = report.checks.append
    version = sys.version.split()[0]
    add(Check("python", OK if sys.version_info >= (3, 11) else FAIL,
              version if sys.version_info >= (3, 11)
              else f"{version} (>= 3.11 required)"))
    have: dict[str, bool] = {}
    for name in PACKAGES:
        if name == "mfusepy":
            ok, detail = mfusepy_status()
        else:
            ok = package_available(name)
            detail = "installed" if ok else f"pip install {name}"
        have[name] = ok
        status = OK if ok else (
            OPTIONAL if name == "mfusepy" and _platform.os_name() == "macos"
            else MISSING)
        add(Check(f"package:{name}", status, detail))
    osn = _platform.os_name()
    if osn == "linux":
        fuse_ok, fuse_hint = _linux_checks(add, have["mfusepy"])
    elif osn == "macos":
        fuse_ok, fuse_hint = _macos_checks(add, have["mfusepy"])
    else:
        fuse_ok, fuse_hint = False, "unsupported OS"
    summary = report.summary
    summary["shell"] = OK if have["prompt_toolkit"] else \
        f"{MISSING} (pip install prompt_toolkit)"
    serve_ok = have["wsgidav"] and have["cheroot"]
    summary["webdav-serve"] = OK if serve_ok else \
        f"{MISSING} (pip install wsgidav cheroot)"
    if osn == "macos":
        mount_ok = serve_ok and os.access(MOUNT_WEBDAV, os.X_OK)
        summary["webdav-mount"] = OK if mount_ok else \
            f"{MISSING} ({MOUNT_WEBDAV} and wsgidav/cheroot required)"
    else:
        summary["webdav-mount"] = \
            f"{NA} (use fuse, or 'awsmount serve' + davfs2)"
    if osn == "macos":
        # FUSE is optional on macOS; only call it MISSING when neither
        # mount method works.
        mount_ok = serve_ok and os.access(MOUNT_WEBDAV, os.X_OK)
        summary["fuse"] = OK if fuse_ok else (
            f"{OPTIONAL} ({fuse_hint})" if mount_ok
            else f"{MISSING} ({fuse_hint})")
    elif osn == "linux":
        summary["fuse"] = OK if fuse_ok else f"{MISSING} ({fuse_hint})"
    else:
        summary["fuse"] = f"{NA} ({fuse_hint})"
    if check_credentials:
        report.checks.extend(credential_checks(profiles, endpoint_url))
    return report
