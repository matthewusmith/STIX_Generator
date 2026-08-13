"""Deterministically checks each extracted item's evidence_quote against the source text.

This is a cheap substring/fuzzy check, not an LLM judge — it catches quotes that were
never in the report at all (the clearest hallucination signal available without another
API call), while a windowed fuzzy fallback tolerates PDF-extraction noise (hyphenation,
line-wrap whitespace) without becoming a semantic judgment call. Items that fail are
flagged, not dropped: a failed match may just mean the model paraphrased a real finding
rather than inventing one, and only a human (or a further LLM pass) can tell the difference.
"""

from difflib import SequenceMatcher

from stix_generator.extraction.schema import ExtractionResult
from stix_generator.extraction.text_normalize import normalize_for_matching

FUZZY_MATCH_THRESHOLD = 0.9


def _is_grounded(quote: str, normalized_text: str) -> bool:
    normalized_quote = normalize_for_matching(quote)
    if not normalized_quote:
        return False
    if normalized_quote in normalized_text:
        return True

    window = len(normalized_quote)
    if window == 0 or window > len(normalized_text):
        return False

    # A blind fixed-step slide over the whole text can straddle the threshold: a window
    # offset by only ~10 chars from the true match (e.g. a PDF line-wrap hyphen inserting
    # one stray character) can score below FUZZY_MATCH_THRESHOLD even though a
    # correctly-anchored window would score >0.99. Anchor on the longest common substring
    # between quote and text first, then score exactly one window around it.
    matcher = SequenceMatcher(None, normalized_text, normalized_quote, autojunk=False)
    anchor_match = matcher.find_longest_match(0, len(normalized_text), 0, len(normalized_quote))
    if anchor_match.size == 0:
        return False

    anchor = anchor_match.a - anchor_match.b
    start = max(0, min(anchor, len(normalized_text) - window))
    candidate = normalized_text[start : start + window]
    ratio = SequenceMatcher(None, normalized_quote, candidate).ratio()
    return ratio >= FUZZY_MATCH_THRESHOLD


def verify_grounding(result: ExtractionResult, report_text: str) -> tuple[ExtractionResult, list[str]]:
    """Sets grounding_status on every item in result and returns (result, warnings)."""
    normalized_text = normalize_for_matching(report_text)
    warnings: list[str] = []

    for entity in result.entities:
        if _is_grounded(entity.evidence_quote, normalized_text):
            entity.grounding_status = "verified"
        else:
            entity.grounding_status = "unverified"
            warnings.append(
                f"Entity '{entity.name}' ({entity.local_id}) unverified: evidence quote not found in source text."
            )

    for observable in result.observables:
        if _is_grounded(observable.evidence_quote, normalized_text):
            observable.grounding_status = "verified"
        else:
            observable.grounding_status = "unverified"
            warnings.append(
                f"Observable '{observable.value}' ({observable.local_id}) unverified: evidence quote not found in source text."
            )

    for rel in result.relationships:
        if _is_grounded(rel.evidence_quote, normalized_text):
            rel.grounding_status = "verified"
        else:
            rel.grounding_status = "unverified"
            warnings.append(
                f"Relationship '{rel.source_local_id}' -{rel.relationship_type}-> '{rel.target_local_id}' "
                "unverified: evidence quote not found in source text."
            )

    return result, warnings
