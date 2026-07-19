"""Tests ensuring translation files stay in sync with the English source."""
from pathlib import Path

import json
import pytest

TRANSLATIONS_DIR = Path(__file__).resolve().parent.parent / "custom_components" / "helios2n" / "translations"

REFERENCE = "en.json"


def _leaf_keys(d: dict, prefix: str = "") -> set[str]:
    """Collect dotted paths for all leaf (non-dict) values."""
    keys: set[str] = set()
    for key, value in d.items():
        if isinstance(value, dict):
            keys |= _leaf_keys(value, f"{prefix}{key}.")
        else:
            keys.add(f"{prefix}{key}")
    return keys


def _load(name: str) -> dict:
    return json.loads((TRANSLATIONS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def reference_keys() -> set[str]:
    return _leaf_keys(_load(REFERENCE))


@pytest.mark.parametrize("translation_file", [p.name for p in sorted(TRANSLATIONS_DIR.glob("*.json")) if p.name != REFERENCE])
def test_translation_parity(translation_file: str, reference_keys: set[str]) -> None:
    """Every non-English translation must define the same leaf keys as en.json."""
    other_keys = _leaf_keys(_load(translation_file))
    missing = reference_keys - other_keys
    extra = other_keys - reference_keys
    assert not missing, f"{translation_file} missing keys vs {REFERENCE}: {sorted(missing)}"
    assert not extra, f"{translation_file} has extra keys vs {REFERENCE}: {sorted(extra)}"
