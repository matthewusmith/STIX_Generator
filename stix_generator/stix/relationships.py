"""STIX 2.1 spec-defined relationship pairings (source type, relationship type) -> target types.

Transcribed from the per-object "Relationships" tables in the STIX 2.1 spec (section 4)
plus the SCO targets the spec lists for infrastructure/malware. Any pairing is *schema*
legal, but these are the ones consumers understand; the builder rewrites anything else
(see `resolve_relationship`) and the prompt shows the model this same table.
"""

SCO_NETWORK = {"ipv4-addr", "ipv6-addr", "domain-name", "url"}

ALLOWED: dict[tuple[str, str], set[str]] = {
    ("attack-pattern", "delivers"): {"malware"},
    ("attack-pattern", "targets"): {"identity", "location", "vulnerability"},
    ("attack-pattern", "uses"): {"malware", "tool"},
    ("campaign", "attributed-to"): {"intrusion-set", "threat-actor"},
    ("campaign", "compromises"): {"infrastructure"},
    ("campaign", "originates-from"): {"location"},
    ("campaign", "targets"): {"identity", "location", "vulnerability"},
    ("campaign", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    ("identity", "located-at"): {"location"},
    ("indicator", "indicates"): {"attack-pattern", "campaign", "infrastructure", "intrusion-set", "malware", "threat-actor", "tool"},
    ("indicator", "based-on"): {"observed-data"} | SCO_NETWORK,  # SCO form is the OpenCTI/TIP convention
    ("infrastructure", "communicates-with"): {"infrastructure"} | SCO_NETWORK,
    ("infrastructure", "consists-of"): {"infrastructure", "observed-data"} | SCO_NETWORK,
    ("infrastructure", "controls"): {"infrastructure", "malware"},
    ("infrastructure", "delivers"): {"malware"},
    ("infrastructure", "has"): {"vulnerability"},
    ("infrastructure", "hosts"): {"tool", "malware"},
    ("infrastructure", "located-at"): {"location"},
    ("infrastructure", "uses"): {"infrastructure"},
    ("malware", "authored-by"): {"threat-actor", "intrusion-set"},
    ("malware", "beacons-to"): {"infrastructure"},
    ("malware", "exfiltrates-to"): {"infrastructure"},
    ("malware", "communicates-with"): SCO_NETWORK,
    ("malware", "controls"): {"malware"},
    ("malware", "downloads"): {"malware", "tool", "file"},
    ("malware", "drops"): {"malware", "tool", "file"},
    ("malware", "exploits"): {"vulnerability"},
    ("malware", "originates-from"): {"location"},
    ("malware", "targets"): {"identity", "infrastructure", "location", "vulnerability"},
    ("malware", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    ("malware", "variant-of"): {"malware"},
    ("threat-actor", "attributed-to"): {"identity"},
    ("threat-actor", "compromises"): {"infrastructure"},
    ("threat-actor", "hosts"): {"infrastructure"},
    ("threat-actor", "owns"): {"infrastructure"},
    ("threat-actor", "impersonates"): {"identity"},
    ("threat-actor", "located-at"): {"location"},
    ("threat-actor", "targets"): {"identity", "location", "vulnerability"},
    ("threat-actor", "uses"): {"attack-pattern", "infrastructure", "malware", "tool"},
    ("tool", "delivers"): {"malware"},
    ("tool", "drops"): {"malware"},
    ("tool", "has"): {"vulnerability"},
    ("tool", "targets"): {"identity", "infrastructure", "location", "vulnerability"},
    ("tool", "uses"): {"infrastructure"},
}

# Common relationships valid between any two objects.
COMMON = {"related-to", "derived-from", "duplicate-of"}

# When a (source, type, target) triple isn't in ALLOWED, try these rewrites of the
# relationship type first — each preserves the analyst's meaning better than a flat
# fall-back to related-to. Checked in order; the first one that lands in ALLOWED wins.
REWRITES: dict[str, list[str]] = {
    "exploits": ["targets"],          # actor/tool/campaign "exploits" a CVE -> targets it
    "communicates-with": ["uses"],    # tool/actor talking to infra -> uses
    "hosts": ["consists-of", "uses"],
    "controls": ["uses"],
    "delivers": ["uses"],
}


def resolve_relationship(source_type: str, rel_type: str, target_type: str) -> tuple[str, str | None]:
    """Returns (relationship_type_to_emit, note_or_None). The note is a warning string
    when the original type had to be rewritten."""
    if rel_type in COMMON or target_type in ALLOWED.get((source_type, rel_type), set()):
        return rel_type, None
    for candidate in REWRITES.get(rel_type, []):
        if target_type in ALLOWED.get((source_type, candidate), set()):
            return candidate, f"'{source_type} -{rel_type}-> {target_type}' is not a spec pairing; emitted as '{candidate}'."
    return "related-to", f"'{source_type} -{rel_type}-> {target_type}' is not a spec pairing; emitted as 'related-to'."


def prompt_table() -> str:
    """Markdown rendering of ALLOWED for the extraction system prompt."""
    lines = []
    for (src, rel), targets in ALLOWED.items():
        if src in ("indicator",):
            continue  # not model-authored
        lines.append(f"- {src} `{rel}` → {', '.join(sorted(targets))}")
    return "\n".join(lines)
