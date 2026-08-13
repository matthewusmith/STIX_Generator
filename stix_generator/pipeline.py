"""End-to-end CLI: report file -> STIX 2.1 bundle.

Usage:
    python -m stix_generator.pipeline data/reports/foo.pdf --out data/output/foo.json
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

from stix_generator.construction.builder import build_bundle
from stix_generator.extraction.extractor import DEFAULT_MODEL, extract
from stix_generator.ingestion.loader import load_report
from stix_generator.validation.validator import validate_bundle


def run(report_path: Path, output_path: Path, model: str = DEFAULT_MODEL, enable_critic: bool = False) -> None:
    print(f"[1/4] Loading report: {report_path}")
    report_text = load_report(report_path)
    print(f"      {len(report_text):,} characters loaded")

    print(f"[2/4] Extracting entities/relationships via {model}...")
    extraction, grounding_warnings = extract(report_text, model=model, enable_critic=enable_critic)
    print(
        f"      {len(extraction.entities)} entities, "
        f"{len(extraction.observables)} observables, "
        f"{len(extraction.relationships)} relationships"
    )
    for warning in grounding_warnings:
        print(f"      GROUNDING WARNING: {warning}")

    print("[3/4] Constructing STIX bundle...")
    bundle, warnings = build_bundle(extraction)
    for warning in warnings:
        print(f"      WARNING: {warning}")

    print("[4/4] Validating against STIX 2.1 schema...")
    bundle_json = bundle.serialize(pretty=True)
    validation = validate_bundle(bundle_json)
    status = "VALID" if validation["is_valid"] else "INVALID"
    print(f"      {status}")
    for error in validation["errors"]:
        print(f"      ERROR: {error}")
    for warning in validation["warnings"]:
        print(f"      SCHEMA WARNING: {warning}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(bundle_json, encoding="utf-8")
    print(f"\nBundle written to {output_path}")

    type_counts = Counter(obj["type"] for obj in json.loads(bundle_json)["objects"])
    print("\nObject counts:")
    for obj_type, count in sorted(type_counts.items()):
        print(f"  {obj_type}: {count}")


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to a .pdf, .txt, or .md CTI report")
    parser.add_argument("--out", type=Path, default=None, help="Output bundle path (default: data/output/<report_stem>.json)")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Claude model to use for extraction")
    parser.add_argument(
        "--critic",
        action="store_true",
        help="Run an extra self-critique pass after extraction to catch hallucinations/omissions "
        "(roughly doubles extraction API cost)",
    )
    args = parser.parse_args()

    output_path = args.out or Path("data/output") / f"{args.report.stem}.json"

    try:
        run(args.report, output_path, model=args.model, enable_critic=args.critic)
    except Exception as exc:  # noqa: BLE001
        print(f"\nPipeline failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
