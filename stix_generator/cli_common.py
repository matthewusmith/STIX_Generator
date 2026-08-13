"""CLI scaffolding shared by stix_generator.pipeline and stix_generator.evaluation."""

import argparse
from pathlib import Path

from stix_generator.extraction.extractor import DEFAULT_MODEL


def add_extraction_args(parser: argparse.ArgumentParser) -> None:
    """Adds the report path, --model, and --critic args common to both CLIs."""
    parser.add_argument("report", type=Path, help="Path to a .pdf, .txt, or .md CTI report")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Claude model to use for extraction")
    parser.add_argument(
        "--critic",
        action="store_true",
        help="Run an extra self-critique pass after extraction to catch hallucinations/omissions "
        "(roughly doubles extraction API cost)",
    )


def print_grounding_warnings(warnings: list[str], indent: str = "  ") -> None:
    for warning in warnings:
        print(f"{indent}GROUNDING WARNING: {warning}")
