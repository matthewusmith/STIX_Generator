"""Prompts for the three extraction passes.

Prompt-caching note: the Anthropic cache is prefix-based over (tools, system, messages).
To let passes B and C reuse the cached report from pass A, every pass sends the *same*
tool list and the *same* system prompt, and the report itself is the first user content
block with a cache breakpoint on it. Only the instruction block after the report differs
per pass. `tool_choice` selects which tool each pass must call.
"""

from stix_generator.stix import vocab
from stix_generator.stix.relationships import prompt_table


def _vocab(values: list[str]) -> str:
    return ", ".join(values)


SYSTEM_PROMPT = f"""You are a cyber threat intelligence (CTI) analyst extracting structured data from a \
narrative threat report. The work happens in three passes, each requested separately: (A) entities and \
observables, (B) relationships between the entities already found, (C) verification of those \
relationships. The results are converted into STIX 2.1 objects by deterministic code — your only job is \
faithful extraction, not formatting. In every pass, call the requested tool exactly once with your \
complete findings.

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
hosting. properties: `infrastructure_types` (list, from: {_vocab(vocab.INFRASTRUCTURE_TYPE)}). When an \
actor or tool talks to a domain/IP, that endpoint is an infrastructure entity — extract it so relationships \
can be routed through it.
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
URL scheme exactly as the report gives it; do not add one the report doesn't state. Do not extract \
observables that belong to victims or third parties unless the report frames them as attacker-controlled.

Observables go in the separate top-level `observables` array, using the `observable_type` / `value` \
fields — never inside `entities`. The `entities` array is only for the nine entity types listed above. A \
domain name is an observable, not an entity, even if it's central to the story.

## Report metadata

Fill the top-level `report` object with the document's own title, publication date (ISO 8601, only if \
printed in the document), source URL, and publishing organization. Leave a field empty if the document \
doesn't state it — do not guess dates.

## Local IDs

Every `local_id` must be unique across entities and observables combined.

## Relationships (pass B)

Relationships connect the `local_id`s from pass A; you will be given the exact list. STIX 2.1 defines \
which verbs are valid between which object types; use only pairings from this table (observables are the \
types domain-name, ipv4-addr, ipv6-addr, url):

{prompt_table()}

Common notes: only `malware` can `exploits` a vulnerability — a threat-actor or tool `targets` it. A \
threat-actor or tool that talks to a domain/IP `uses` an `infrastructure` entity, which in turn \
`communicates-with` or `consists-of` the observable; do not draw `communicates-with` from a tool or actor. \
Fall back to `related-to` only if nothing in the table fits. Every relationship must be directly \
supported by the text — do not infer relationships the report doesn't state. Do not introduce entities \
that were not in the list; if a needed entity is missing, omit the relationship.

## Verification (pass C)

You will be shown numbered relationships (source, verb, target) without any justification. Judge each \
one against the report text alone:
- `supported`: the text states this relationship with this verb. Give the quote.
- `downgrade`: the text connects these two items, but with a weaker or different verb than claimed \
(e.g. `exploits` claimed, only `targets` supported; or nothing more specific than `related-to`). Give the \
replacement verb and the quote that supports it.
- `unsupported`: the text does not connect these two items. No quote.
Judge every index exactly once. Do not add relationships.

## What to skip

Skip generic defensive/mitigation content (product names offered as protection, vendor contact info, \
generic advice) — that is not threat intelligence to extract.

## Evidence

Every `evidence_quote` is a short verbatim quote (<=25 words) copied exactly from the report text — not \
a paraphrase.
"""


def report_block(report_text: str) -> dict:
    """The cached user content block shared by every pass."""
    return {
        "type": "text",
        "text": f"--- BEGIN REPORT ---\n{report_text}\n--- END REPORT ---",
        "cache_control": {"type": "ephemeral"},
    }


PASS_A_INSTRUCTION = (
    "Pass A. Extract all threat intelligence entities and observables from the report above, plus the "
    "report metadata. Call record_entities once with the complete result."
)

CRITIC_INSTRUCTION = """Pass A review. You are now reviewing your own entity/observable extraction against \
the report text above, acting as a skeptical second reader. Check for two distinct kinds of error:

1. **Hallucinations / unsupported items** — anything in your draft that the text doesn't actually \
state or clearly imply (including a bad `evidence_quote` that doesn't really appear in the text or \
doesn't really support the item), and any entity given the wrong type. Remove or fix these.
2. **Omissions** — entities or observables that are clearly stated in the report but missing from \
your draft. Add these, following the same rules and vocabulary as before.

Do not remove or change anything that is already correct and well-supported. Call record_entities one \
more time with the complete corrected result — the full set, not just the changes."""


def roster(entities, observables) -> str:
    lines = ["local_id | type | name | aliases"]
    for e in entities:
        aliases = ", ".join(e.aliases) if e.aliases else "-"
        lines.append(f"{e.local_id} | {e.type} | {e.name} | {aliases}")
    for o in observables:
        lines.append(f"{o.local_id} | {o.observable_type} | {o.value} | -")
    return "\n".join(lines)


def pass_b_instruction(entities, observables) -> str:
    return (
        "Pass B. These are the entities and observables extracted from the report above:\n\n"
        f"{roster(entities, observables)}\n\n"
        "Extract every relationship the report states between them, using only these local_ids and only "
        "verbs valid for the source/target types. Call record_relationships once with the complete result."
    )


def pass_c_instruction(relationships, entities, observables) -> str:
    names = {e.local_id: f"{e.type} '{e.name}'" for e in entities}
    names.update({o.local_id: f"{o.observable_type} '{o.value}'" for o in observables})
    lines = [
        f"[{i}] {names.get(r.source_local_id, r.source_local_id)} --{r.relationship_type}--> "
        f"{names.get(r.target_local_id, r.target_local_id)}"
        for i, r in enumerate(relationships)
    ]
    return (
        "Pass C. Judge each of the following proposed relationships against the report above:\n\n"
        + "\n".join(lines)
        + "\n\nCall record_verdicts once with a verdict for every index."
    )
