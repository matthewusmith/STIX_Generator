"""CLI: run extraction against a report and score it against a gold file, or scaffold one.

Usage:
    python -m stix_generator.evaluation data/reports/foo.pdf --golden data/golden/foo.json
    python -m stix_generator.evaluation data/reports/foo.pdf --save-golden
"""

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from stix_generator.evaluation.scoring import print_scorecard, score_extraction
from stix_generator.extraction.extractor import DEFAULT_MODEL, extract
from stix_generator.extraction.schema import ExtractionResult
from stix_generator.ingestion.loader import load_report


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to a .pdf, .txt, or .md CTI report")
    parser.add_argument(
        "--golden",
        type=Path,
        default=None,
        help="Path to a gold-standard ExtractionResult JSON file to score against "
        "(default: data/golden/<report_stem>.json)",
    )
    parser.add_argument(
        "--save-golden",
        action="store_true",
        help="Run extraction once and write the raw result as a DRAFT gold file instead of scoring "
        "(requires hand review before it's trustworthy ground truth)",
    )
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Claude model to use for extraction")
    parser.add_argument(
        "--critic",
        action="store_true",
        help="Run the extra self-critique pass before scoring/saving (roughly doubles API cost)",
    )
    args = parser.parse_args()

    golden_path = args.golden or Path("data/golden") / f"{args.report.stem}.json"

    print(f"Loading report: {args.report}")
    report_text = load_report(args.report)

    print(f"Extracting via {args.model}{' (with critic pass)' if args.critic else ''}...")
    result, grounding_warnings = extract(report_text, model=args.model, enable_critic=args.critic)
    for warning in grounding_warnings:
        print(f"  GROUNDING WARNING: {warning}")

    if args.save_golden:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nDRAFT gold file written to {golden_path}")
        print(
            "This is scaffolded from a single model run — it may contain the same hallucinations "
            "or omissions being measured. Hand-review every entity, observable, and relationship "
            "against the source report before treating this as ground truth."
        )
        return

    if not golden_path.exists():
        print(f"\nNo gold file found at {golden_path}.", file=sys.stderr)
        print("Run with --save-golden first to scaffold one, then hand-correct it.", file=sys.stderr)
        sys.exit(1)

    gold = ExtractionResult.model_validate_json(golden_path.read_text(encoding="utf-8"))
    scorecard = score_extraction(gold, result)
    print(f"\nScorecard vs {golden_path}:")
    print_scorecard(scorecard)


if __name__ == "__main__":
    main()
