"""Tests for version consistency across project files."""
import json
import re
from pathlib import Path

import pytest
import tomllib


REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_manifest_version() -> str:
    manifest = json.loads((REPO_ROOT / "custom_components/helios2n/manifest.json").read_text())
    return manifest["version"]


def _read_pyproject_version() -> str:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    return pyproject["project"]["version"]


def _read_readme_badge_version() -> str | None:
    readme = (REPO_ROOT / "README.md").read_text()
    match = re.search(r"version-([0-9]+\.[0-9]+\.[0-9]+)", readme)
    return match.group(1) if match else None


def _read_changelog_versions() -> tuple[str | None, str | None]:
    changelog = (REPO_ROOT / "docs/CHANGELOG.md").read_text()
    unreleased_match = re.search(r"## \[Unreleased\]", changelog)
    released_match = re.search(r"## \[([0-9]+\.[0-9]+\.[0-9]+)\]", changelog)
    unreleased_present = unreleased_match is not None
    latest_released = released_match.group(1) if released_match else None
    return unreleased_present, latest_released


class TestVersionSync:
    """All version specifiers must match each other before release."""

    def test_all_versions_are_equal(self):
        manifest_version = _read_manifest_version()
        pyproject_version = _read_pyproject_version()
        badge_version = _read_readme_badge_version()
        _, changelog_latest = _read_changelog_versions()

        versions = {
            "manifest.json": manifest_version,
            "pyproject.toml": pyproject_version,
            "README.md badge": badge_version,
            "CHANGELOG.md latest": changelog_latest,
        }

        missing = [name for name, v in versions.items() if v is None]
        assert not missing, f"Missing version in: {', '.join(missing)}"

        unique_versions = set(versions.values())
        assert len(unique_versions) == 1, (
            f"Version mismatch across files: {versions}"
        )

    def test_changelog_has_unreleased_section(self):
        unreleased_present, _ = _read_changelog_versions()
        assert unreleased_present, "CHANGELOG.md must have a ## [Unreleased] section at the top"
