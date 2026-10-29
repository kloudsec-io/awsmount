"""Wiring checks: everything the CLI reaches by name must exist.

These tests exist because integration bugs hid where unit tests never
looked: a module nobody imported, or a function the CLI looks up by string.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
import re
from pathlib import Path

import pytest

import awsmount

SRC = Path(awsmount.__file__).resolve().parent
CLI_SOURCE = (SRC / "cli.py").read_text(encoding="utf-8")

# Modules that import optional native libraries at import time.
OPTIONAL_NATIVE = {"mfusepy"}


def _all_modules() -> list[str]:
    return sorted(
        info.name for info in pkgutil.walk_packages(
            awsmount.__path__, prefix="awsmount."))


@pytest.mark.parametrize("name", _all_modules())
def test_every_module_imports(name: str) -> None:
    """Importing any module must work without libfuse or a network."""
    importlib.import_module(name)


def _from_imports(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom) and node.level == 0
                and node.module
                and node.module.split(".")[0] == "awsmount"):
            for alias in node.names:
                found.append((node.module, alias.name))
    return found


def test_every_from_import_resolves() -> None:
    """`from awsmount.x import y` must name something that exists."""
    missing = []
    for path in sorted(SRC.rglob("*.py")):
        for module, attr in _from_imports(path):
            mod = importlib.import_module(module)
            if hasattr(mod, attr):
                continue
            try:
                importlib.import_module(f"{module}.{attr}")
            except ImportError:
                missing.append(f"{path.name}: {module}.{attr}")
    assert missing == []


def _adapter_targets() -> list[tuple[str, str]]:
    return re.findall(r'_adapter\(\s*"([\w.]+)",\s*"(\w+)"', CLI_SOURCE)


def test_cli_adapter_targets_found() -> None:
    """Guard the regex itself so the next test cannot pass vacuously."""
    assert len(_adapter_targets()) >= 3


@pytest.mark.parametrize("module,func", _adapter_targets())
def test_cli_adapter_functions_exist(module: str, func: str) -> None:
    """Every function the CLI looks up by string exists and is callable."""
    mod = importlib.import_module(module)
    assert callable(getattr(mod, func, None)), f"{module}.{func}"


def test_provider_modules_all_exist_and_register() -> None:
    """PROVIDER_MODULES matches the files on disk, no more, no less."""
    from awsmount.providers import PROVIDER_MODULES

    on_disk = {
        p.stem for p in (SRC / "providers").glob("*.py")
        if p.stem not in {"__init__", "base", "common", "refs",
                          "cfn_types"}}
    assert set(PROVIDER_MODULES) == on_disk
    assert len(PROVIDER_MODULES) == len(set(PROVIDER_MODULES))


def test_registry_validates_clean() -> None:
    """Cross references between providers all resolve."""
    from awsmount.providers import ProviderRegistry

    assert ProviderRegistry().validate() == []


def test_webdav_server_api_used_by_macos_module() -> None:
    """macos.py calls WebDavServer with keywords the class accepts."""
    import inspect

    from awsmount.adapters.webdav.server import WebDavServer

    params = inspect.signature(WebDavServer.__init__).parameters
    for keyword in ("port", "links_mode", "verbose", "credentials",
                    "digest"):
        assert keyword in params, keyword


def test_webdav_session_token_is_lowercase() -> None:
    """wsgidav matches shares through a lowercased lookup (real bug)."""
    from awsmount.adapters.webdav.auth import Credentials

    for _ in range(50):
        token = Credentials.generate().token
        assert token == token.lower()
        assert len(token) >= 40


def test_console_script_target_exists() -> None:
    """pyproject's entry point resolves to a callable."""
    # Locate pyproject.toml from the test file, not from the package:
    # the package may be installed (site-packages) rather than editable.
    root = Path(__file__).resolve().parents[2]
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'awsmount\s*=\s*"([\w.]+):(\w+)"', text)
    assert match is not None
    mod = importlib.import_module(match.group(1))
    assert callable(getattr(mod, match.group(2)))
