"""Shared text normalization for matching strings across defanging/whitespace noise.

Used by extraction.grounding (matching an evidence_quote against report text) and
evaluation.scoring (matching observable values between gold and predicted results).
"""

import re
import unicodedata

_SMART_QUOTES = {
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-",
}

_DEFANG_PATTERNS = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
]


def normalize_for_matching(text: str) -> str:
    """Lowercase, straighten quotes, undo common defanging, and collapse whitespace."""
    result = unicodedata.normalize("NFKC", text)
    for smart, plain in _SMART_QUOTES.items():
        result = result.replace(smart, plain)
    for pattern, replacement in _DEFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    result = result.lower()
    result = re.sub(r"\s+", " ", result).strip()
    return result
