"""The guarded transport depends on httpx internals, so the installed version must match the pin."""

import re
from importlib.metadata import version
from pathlib import Path

import pytest

REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"


def pinned(package: str) -> str:
    match = re.search(rf"^{re.escape(package)}==(\S+)", REQUIREMENTS.read_text(), re.M | re.I)
    assert match, f"{package} must be pinned with == in requirements.txt"
    return match.group(1)


@pytest.mark.parametrize("package", ["httpx", "httpcore"])
def test_installed_version_matches_pin(package):
    expected, installed = pinned(package), version(package)
    assert installed == expected, (
        f"{package} {installed} is installed but requirements.txt pins {expected}. "
        "app/security.py replaces httpx's private AsyncHTTPTransport._pool to install the "
        "SSRF-guarding network backend. Before upgrading, re-verify the guarded transport "
        "(tests/test_security.py: SNI, rebinding and proxy tests) and then update the pin."
    )


def test_every_runtime_dependency_is_pinned_exactly():
    for line in REQUIREMENTS.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            assert re.fullmatch(r"[A-Za-z0-9_.\-]+==[0-9][\w.]*", line), f"not an exact pin: {line!r}"
