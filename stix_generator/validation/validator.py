"""Wraps the official OASIS stix2-validator for schema conformance checks.

Note: the `stix2-validator` PyPI wheel does not bundle the actual STIX 2.1 JSON
schemas (a known packaging gap — they normally ship via a git submodule that
isn't included in the sdist/wheel). We vendor them from the official
oasis-open/cti-stix2-json-schemas repo under third_party/ and copy them into
the installed package's expected lookup path the first time validation runs.
"""

import shutil
from pathlib import Path

import stix2validator
from stix2validator import ValidationOptions, validate_string
from stix2validator.util import DEFAULT_VER

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VENDORED_SCHEMAS = PROJECT_ROOT / "third_party" / "cti-stix2-json-schemas" / "schemas"


def _ensure_schemas_installed() -> None:
    package_dir = Path(stix2validator.__file__).resolve().parent
    target = package_dir / f"schemas-{DEFAULT_VER}" / "schemas"
    if target.exists():
        return

    if not VENDORED_SCHEMAS.exists():
        raise RuntimeError(
            "STIX JSON schemas not found. Clone them with:\n"
            "  git clone --depth 1 --branch stix2.1 "
            "https://github.com/oasis-open/cti-stix2-json-schemas.git "
            "third_party/cti-stix2-json-schemas"
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(VENDORED_SCHEMAS, target)


def validate_bundle(bundle_json: str) -> dict:
    """Validate a serialized STIX bundle. Returns {is_valid, errors, warnings}."""
    _ensure_schemas_installed()

    options = ValidationOptions(strict=False)
    results = validate_string(bundle_json, options)
    if isinstance(results, list):
        is_valid = all(r.is_valid for r in results)
        errors = [str(e) for r in results for e in (r.errors or [])]
        warnings = [str(w) for r in results for w in (r.warnings or [])]
    else:
        is_valid = results.is_valid
        errors = [str(e) for e in (results.errors or [])]
        warnings = [str(w) for w in (results.warnings or [])]

    return {"is_valid": is_valid, "errors": errors, "warnings": warnings}
