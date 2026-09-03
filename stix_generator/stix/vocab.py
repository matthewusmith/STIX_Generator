"""STIX 2.1 open vocabularies (spec section 10) used by this project, plus a normalizer.

Open vocabularies are *suggested* values — anything is schema-legal — but TIPs key
filters and UI on them, so off-vocab values (e.g. "AI model", "Opportunistic exploit
operator") are effectively invisible. The prompt shows the model these lists, and the
builder normalizes what comes back: values that match after slugifying are kept on the
typed property, anything else is moved into the description so no information is lost.
"""

import re

THREAT_ACTOR_ROLE = [
    "agent", "director", "independent", "infrastructure-architect",
    "infrastructure-operator", "malware-author", "sponsor",
]
THREAT_ACTOR_SOPHISTICATION = ["none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"]
ATTACK_MOTIVATION = [
    "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
    "personal-gain", "personal-satisfaction", "revenge", "unpredictable",
]
MALWARE_TYPE = [
    "adware", "backdoor", "bot", "bootkit", "ddos", "downloader", "dropper", "exploit-kit",
    "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation",
    "rogue-security-software", "rootkit", "screen-capture", "spyware", "trojan", "unknown",
    "virus", "webshell", "wiper", "worm",
]
TOOL_TYPE = [
    "denial-of-service", "exploitation", "information-gathering", "network-capture",
    "credential-exploitation", "remote-access", "vulnerability-scanning", "unknown",
]
INFRASTRUCTURE_TYPE = [
    "amplification", "anonymization", "botnet", "command-and-control", "control-system",
    "exfiltration", "firewall", "hosting-malware", "hosting-target-lists", "phishing",
    "reconnaissance", "routers-switches", "staging", "unknown", "workstation",
]
IDENTITY_CLASS = ["individual", "group", "system", "organization", "class", "unknown"]
INDUSTRY_SECTOR = [
    "agriculture", "aerospace", "automotive", "chemical", "commercial", "communications",
    "construction", "defense", "education", "energy", "entertainment", "financial-services",
    "government", "government-emergency-services", "government-local", "government-national",
    "government-public-services", "government-regional", "healthcare", "hospitality-leisure",
    "infrastructure", "infrastructure-dams", "infrastructure-nuclear", "infrastructure-water",
    "insurance", "manufacturing", "mining", "non-profit", "pharmaceuticals", "retail",
    "technology", "telecommunications", "transportation", "utilities",
]

# property name -> (vocab name for messages, allowed values)
PROPERTY_VOCABS: dict[str, tuple[str, list[str]]] = {
    "roles": ("threat-actor-role-ov", THREAT_ACTOR_ROLE),
    "sophistication": ("threat-actor-sophistication-ov", THREAT_ACTOR_SOPHISTICATION),
    "primary_motivation": ("attack-motivation-ov", ATTACK_MOTIVATION),
    "malware_types": ("malware-type-ov", MALWARE_TYPE),
    "tool_types": ("tool-type-ov", TOOL_TYPE),
    "infrastructure_types": ("infrastructure-type-ov", INFRASTRUCTURE_TYPE),
    "identity_class": ("identity-class-ov", IDENTITY_CLASS),
    "sectors": ("industry-sector-ov", INDUSTRY_SECTOR),
}


def slugify(value: str) -> str:
    """'Remote Access Trojan' -> 'remote-access-trojan'; the spec's casing/separator rule."""
    value = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return value.strip("-")


def normalize_vocab(prop: str, value, warnings: list[str], label: str) -> tuple[object | None, list[str]]:
    """Returns (normalized_value_or_None, rejected_original_values).

    Accepts a str or list[str] depending on the property. Values that slugify onto a
    vocab entry are kept; the rest are returned so the caller can preserve them in prose.
    """
    vocab_name, allowed = PROPERTY_VOCABS[prop]
    is_list = isinstance(value, list)
    raw = value if is_list else [value]
    kept: list[str] = []
    rejected: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            continue
        slug = slugify(item)
        if slug in allowed:
            kept.append(slug)
        else:
            rejected.append(item)
    if rejected:
        warnings.append(f"{label}: {prop} value(s) {rejected} not in {vocab_name}; kept in description instead.")
    if is_list:
        return (kept or None), rejected
    return (kept[0] if kept else None), rejected
