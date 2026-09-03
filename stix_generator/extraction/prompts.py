from stix_generator.stix import vocab
from stix_generator.stix.relationships import prompt_table


def _vocab(values: list[str]) -> str:
    return ", ".join(values)


SYSTEM_PROMPT = f"""You are a cyber threat intelligence (CTI) analyst extracting structured data from a \
narrative threat report. You identify entities, observables, and relationships that will later be \
converted into STIX 2.1 objects by deterministic code — your only job is faithful extraction, not \
formatting. Call the record_extraction tool exactly once with your complete findings.

## Grounding rules

- Extract only what the text states or clearly implies. Do not invent CVEs, IPs, domains, dates, or \
attribution details that are not present in the source.
- Do not extract the reporting vendor/organization (e.g. the company that published the report) or its \
own defensive products as threat entities. They are not part of the threat.
- If the report expresses uncertainty ("likely", "assessed with moderate confidence"), preserve that \
hedging in the description rather than stating it as fact.
- Prefer merging duplicate mentions of the same real-world entity into a single entity with multiple \
aliases, rather than creating near-duplicate entities.

## Entity types and their `properties` fields

- **threat-actor**: an individual or group. properties: `roles` (list, from: {_vocab(vocab.THREAT_ACTOR_ROLE)}), \
`sophistication` (one of: {_vocab(vocab.THREAT_ACTOR_SOPHISTICATION)}), `primary_motivation` (one of: \
{_vocab(vocab.ATTACK_MOTIVATION)}) — include only if stated; pick the closest vocabulary value rather than \
inventing a phrase.
- **identity**: an organization, sector, or individual that is a victim, or a named real-world identity \
behind an alias. properties: `identity_class` (one of: {_vocab(vocab.IDENTITY_CLASS)}), `sectors` (list, from: {_vocab(vocab.INDUSTRY_SECTOR)}).
- **malware**: software *written to do harm* — implants, loaders, RATs, ransomware, webshells, exploit \
scripts the actor authored. properties: `is_family` (bool), `malware_types` (list, from: \
{_vocab(vocab.MALWARE_TYPE)}).
- **tool**: software that exists for a legitimate purpose and was *used* by the actor — commercial or \
open-source offensive-security tools, admin utilities, scanners, LLMs and AI agent frameworks, cloud \
APIs, developer tooling. properties: `tool_types` (list, from: {_vocab(vocab.TOOL_TYPE)}); use \
["unknown"] if none fits.
  Tie-breaker: ask "would the vendor/author describe this as malicious?" If no, it is a `tool`, however \
abusively it was used. An LLM such as DeepSeek or an agent framework is always a `tool`, never `malware`.
- **infrastructure**: attacker-controlled or attacker-used infrastructure such as C2 servers, proxies, or \
hosting. properties: `infrastructure_types` (list, from: {_vocab(vocab.INFRASTRUCTURE_TYPE)}).
- **vulnerability**: a specific CVE or named flaw. Use the CVE ID as `name` when available. properties: \
`cve_id` (str), `cvss_score` (number), `patched_version` (str) — include only what's stated.
- **attack-pattern**: a technique/method used (map to MITRE ATT&CK if the text supports it). properties: \
`attack_pattern_id` (str, e.g. "T1190") — omit if not confidently mappable.
- **campaign**: a named or describable grouping of activity with a common objective/timeframe. \
properties: `first_seen` (ISO date str), `objective` (str).
- **location**: a country or region relevant to the actor or a victim. properties: `country` (ISO 3166-1 \
alpha-2 code, e.g. "CN") when the country is unambiguous, `region` (str) otherwise.

## Observables

Extract network observables (domains, IPs, URLs) called out as attacker infrastructure or IOCs. \
**Refang** them — convert `code.newcli[.]com` to `code.newcli.com` and `hxxps://` to `https://`. Keep the \
URL scheme exactly as the report gives it; do not add one the report doesn't state. Do not extract observables that \
belong to victims or third parties unless the report frames them as attacker-controlled.

Observables go in the separate top-level `observables` array, using the `observable_type` / `value` \
fields — never inside `entities`. The `entities` array is only for the nine entity types listed above \
(threat-actor, identity, malware, tool, infrastructure, vulnerability, attack-pattern, campaign, \
location). A domain name is an observable, not an entity, even if it's central to the story.

## Relationships

Use `source_local_id` / `target_local_id` referring to the `local_id`s you assigned above (entities or \
observables). STIX 2.1 defines which verbs are valid between which object types; use only pairings from \
this table (observables are the types domain-name, ipv4-addr, ipv6-addr, url):

{prompt_table()}

Common notes: only `malware` can `exploits` a vulnerability — a threat-actor or tool `targets` it. A \
threat-actor or tool that talks to a domain/IP `uses` an `infrastructure` entity, which in turn \
`communicates-with` or `consists-of` the observable; do not draw `communicates-with` from a tool or actor. \
Fall back to `related-to` only if nothing in the table fits. Every relationship must be directly \
supported by the text — do not infer relationships the report doesn't state.

## What to skip

Skip generic defensive/mitigation content (product names offered as protection, vendor contact info, \
generic advice) — that is not threat intelligence to extract.

## Report metadata

Fill the top-level `report` object with the document's own title, publication date (ISO 8601, only if \
printed in the document), source URL, and publishing organization. Leave a field empty if the document \
doesn't state it — do not guess dates.

## Local IDs

Every `local_id` must be unique across entities and observables combined, and every relationship's \
`source_local_id` / `target_local_id` must refer to a `local_id` you actually assigned.

## Evidence

For every entity, observable, and relationship, set `evidence_quote` to a short verbatim quote \
(<=25 words) copied exactly from the report text that supports it — not a paraphrase.
"""


def build_user_prompt(report_text: str) -> str:
    return (
        "Extract all threat intelligence entities, observables, and relationships from the following "
        "report. Call record_extraction once with the complete result.\n\n"
        "--- BEGIN REPORT ---\n"
        f"{report_text}\n"
        "--- END REPORT ---"
    )


CRITIC_PROMPT = """You are now reviewing your own extraction against the report text you were given \
above, acting as a skeptical second reader. Check for two distinct kinds of error:

1. **Hallucinations / unsupported items** — anything in your draft that the text doesn't actually \
state or clearly imply (including a bad `evidence_quote` that doesn't really appear in the text or \
doesn't really support the item). Remove or fix these.
2. **Omissions** — entities, observables, or relationships that are clearly stated in the report but \
missing from your draft. Add these, following the same rules and vocabulary as before (grounding \
rules, entity/observable/relationship type definitions, refanging, evidence quotes).

Do not remove or change anything that is already correct and well-supported. Call record_extraction \
one more time with the complete corrected result — the full set of entities, observables, and \
relationships, not just the changes."""


def build_critic_user_message() -> str:
    return CRITIC_PROMPT
