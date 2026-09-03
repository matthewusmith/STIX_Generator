"""Deterministically turns the extraction IR into a schema-valid STIX 2.1 Bundle.

The LLM never emits STIX JSON directly: it names entities and relationships, and this
module is solely responsible for STIX object types, required properties, ID generation,
and observable patterns. Keeping that split means STIX-format correctness doesn't depend
on the model getting spec details right.

Design notes:

* **Stable IDs.** Every SDO/SRO gets a UUIDv5 derived from its identity-defining content
  (type + normalized name, or CVE/ATT&CK ID where one exists) under a project namespace,
  so re-running the same report yields the same object IDs and a TIP ingests it as an
  update rather than a duplicate. SCOs already get content-based IDs from the stix2 lib.
* **Observables become SCO + Indicator.** Each extracted observable produces the cyber
  observable object itself (domain-name, ipv4-addr, ...) plus an Indicator carrying a
  STIX pattern, linked by `indicator --based-on--> sco`. Model-authored relationships
  (`communicates-with`, `hosts`, ...) resolve to the SCO, which is what those verbs mean.
* **A Report SDO wraps the bundle.** It references every other object so a TIP can group
  the ingest, and carries the source document's title/date/URL when the extractor found them.
"""

import re
import uuid
from datetime import datetime, timezone

import stix2

from stix_generator.extraction.schema import ExtractedObservable, ExtractionResult
from stix_generator.stix.relationships import resolve_relationship
from stix_generator.stix.vocab import normalize_vocab

# Fixed namespace for UUIDv5 generation. Changing this changes every ID this project emits.
STIX_GENERATOR_NAMESPACE = uuid.UUID("6f1b0e5a-3c1d-4b3e-9a6c-2d8f7e5a1c42")

GENERATOR_IDENTITY_NAME = "STIX Generator"

OBSERVABLE_PATTERN_TEMPLATES = {
    "domain-name": "[domain-name:value = '{value}']",
    "ipv4-addr": "[ipv4-addr:value = '{value}']",
    "ipv6-addr": "[ipv6-addr:value = '{value}']",
    "url": "[url:value = '{value}']",
}

OBSERVABLE_SCO_CLASSES = {
    "domain-name": stix2.DomainName,
    "ipv4-addr": stix2.IPv4Address,
    "ipv6-addr": stix2.IPv6Address,
    "url": stix2.URL,
}


def _normalize_key(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def stable_id(stix_type: str, *key_parts: str) -> str:
    """Deterministic STIX identifier: `<type>--<uuid5(namespace, type|part|part...)>`."""
    key = "|".join([stix_type, *(_normalize_key(p) for p in key_parts)])
    return f"{stix_type}--{uuid.uuid5(STIX_GENERATOR_NAMESPACE, key)}"


def _escape_pattern_value(value: str) -> str:
    # STIX pattern string literals are single-quoted; escape backslashes and quotes.
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    candidates = [value, f"{value}T00:00:00+00:00"]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _generator_identity() -> stix2.Identity:
    return stix2.Identity(
        id=stable_id("identity", GENERATOR_IDENTITY_NAME),
        name=GENERATOR_IDENTITY_NAME,
        identity_class="system",
        description="Automated STIX 2.1 extraction from narrative CTI reporting.",
    )


def _apply_vocab(kwargs: dict, props: dict, prop: str, warnings: list[str], label: str) -> None:
    """Copy props[prop] into kwargs if it normalizes onto the STIX open vocab; anything
    that doesn't is appended to the description as 'Reported <prop>: ...' so the
    analyst's original wording survives without polluting the typed property."""
    if prop not in props or props[prop] in (None, "", []):
        return
    value, rejected = normalize_vocab(prop, props[prop], warnings, label)
    if value is not None:
        kwargs[prop] = value
    if rejected:
        pretty = prop.replace("_", " ")
        kwargs["description"] = f"{kwargs.get('description', '')} Reported {pretty}: {', '.join(rejected)}.".strip()


def _build_entity(entity, warnings: list[str], created_by_ref: str):
    props = entity.properties or {}
    label = f"{entity.type} '{entity.name}' ({entity.local_id})"
    common = {"name": entity.name, "description": entity.description, "created_by_ref": created_by_ref}
    if entity.aliases:
        common["aliases"] = entity.aliases

    if entity.type == "threat-actor":
        kwargs = dict(common, id=stable_id("threat-actor", entity.name))
        for key in ("roles", "sophistication", "primary_motivation"):
            _apply_vocab(kwargs, props, key, warnings, label)
        return stix2.ThreatActor(**kwargs)

    if entity.type == "identity":
        tmp: dict = {"description": common["description"]}
        _apply_vocab(tmp, props, "identity_class", warnings, label)
        identity_class = tmp.get("identity_class", "unknown")
        kwargs = dict(common, id=stable_id("identity", entity.name, identity_class), identity_class=identity_class)
        kwargs["description"] = tmp["description"]
        _apply_vocab(kwargs, props, "sectors", warnings, label)
        return stix2.Identity(**kwargs)

    if entity.type == "malware":
        kwargs = dict(common, id=stable_id("malware", entity.name))
        kwargs["is_family"] = bool(props.get("is_family", False))
        _apply_vocab(kwargs, props, "malware_types", warnings, label)
        return stix2.Malware(**kwargs)

    if entity.type == "tool":
        kwargs = dict(common, id=stable_id("tool", entity.name))
        _apply_vocab(kwargs, props, "tool_types", warnings, label)
        return stix2.Tool(**kwargs)

    if entity.type == "infrastructure":
        kwargs = dict(common, id=stable_id("infrastructure", entity.name))
        _apply_vocab(kwargs, props, "infrastructure_types", warnings, label)
        kwargs.setdefault("infrastructure_types", ["unknown"])
        return stix2.Infrastructure(**kwargs)

    if entity.type == "vulnerability":
        cve_id = props.get("cve_id")
        # Key on the CVE when there is one: it is the real-world identity of the vuln,
        # and two reports naming it slightly differently should still collapse to one object.
        kwargs = dict(common, id=stable_id("vulnerability", cve_id or entity.name))
        external_refs = []
        if cve_id:
            external_refs.append({"source_name": "cve", "external_id": cve_id})
        if props.get("cvss_score") is not None:
            kwargs["description"] = f"{kwargs['description']} (CVSS: {props['cvss_score']})".strip()
        if props.get("patched_version"):
            kwargs["description"] = f"{kwargs['description']} Patched in {props['patched_version']}.".strip()
        if external_refs:
            kwargs["external_references"] = external_refs
        return stix2.Vulnerability(**kwargs)

    if entity.type == "attack-pattern":
        attack_id = props.get("attack_pattern_id")
        kwargs = dict(common, id=stable_id("attack-pattern", attack_id or entity.name))
        if attack_id:
            kwargs["external_references"] = [{"source_name": "mitre-attack", "external_id": attack_id}]
        return stix2.AttackPattern(**kwargs)

    if entity.type == "campaign":
        kwargs = dict(common, id=stable_id("campaign", entity.name))
        if props.get("objective"):
            kwargs["objective"] = props["objective"]
        first_seen = _parse_datetime(props.get("first_seen", ""))
        if first_seen:
            kwargs["first_seen"] = first_seen
        return stix2.Campaign(**kwargs)

    if entity.type == "location":
        kwargs = {"name": entity.name, "description": entity.description, "created_by_ref": created_by_ref}
        if props.get("country"):
            kwargs["country"] = props["country"]
        if props.get("region"):
            kwargs["region"] = props["region"]
        if "country" not in kwargs and "region" not in kwargs:
            warnings.append(f"Skipped location '{entity.name}' ({entity.local_id}): no country or region given.")
            return None
        kwargs["id"] = stable_id("location", kwargs.get("country") or kwargs.get("region"))
        return stix2.Location(**kwargs)

    warnings.append(f"Unknown entity type '{entity.type}' for '{entity.name}' ({entity.local_id}); skipped.")
    return None


def _build_observable(
    observable: ExtractedObservable,
    warnings: list[str],
    created_by_ref: str,
    valid_from: datetime,
) -> tuple[object, stix2.Indicator, stix2.Relationship] | None:
    """Returns (sco, indicator, indicator-based-on-sco relationship), or None if unsupported."""
    sco_cls = OBSERVABLE_SCO_CLASSES.get(observable.observable_type)
    template = OBSERVABLE_PATTERN_TEMPLATES.get(observable.observable_type)
    if not sco_cls or not template:
        warnings.append(f"Unsupported observable type '{observable.observable_type}' ({observable.local_id}); skipped.")
        return None

    value = observable.value.strip()
    if observable.observable_type == "url" and "://" not in value:
        # url:value must be a valid URI, which requires a scheme. Reports routinely give
        # scheme-less paths ("evil.example/x"); assume http:// rather than drop the IOC,
        # and say so, since the scheme is our assumption and not the report's.
        warnings.append(f"URL '{value}' ({observable.local_id}) had no scheme; assumed http://.")
        value = f"http://{value}"

    # SCO ids are content-derived by the stix2 library (UUIDv5 over the value), so
    # the same domain in two reports resolves to the same object without our help.
    sco = sco_cls(value=value)

    pattern = template.format(value=_escape_pattern_value(value))
    indicator = stix2.Indicator(
        id=stable_id("indicator", pattern),
        name=value,
        description=observable.description or f"{observable.observable_type} observed as attacker infrastructure.",
        indicator_types=["malicious-activity"],
        pattern=pattern,
        pattern_type="stix",
        valid_from=valid_from,
        created_by_ref=created_by_ref,
    )
    based_on = _relationship("based-on", indicator.id, sco.id, "", created_by_ref)
    return sco, indicator, based_on


def _relationship(rel_type: str, source_ref: str, target_ref: str, description: str, created_by_ref: str):
    kwargs = {
        "id": stable_id("relationship", rel_type, source_ref, target_ref),
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "created_by_ref": created_by_ref,
    }
    if description:
        kwargs["description"] = description
    return stix2.Relationship(**kwargs)


def _build_report(extraction: ExtractionResult, object_refs: list[str], created_by_ref: str, published: datetime):
    meta = extraction.report
    name = meta.title.strip() or "Untitled CTI report"
    kwargs = {
        "id": stable_id("report", name, meta.published or ""),
        "name": name,
        "report_types": ["threat-report"],
        "published": published,
        "object_refs": object_refs,
        "created_by_ref": created_by_ref,
    }
    external_refs = []
    if meta.source_url.strip():
        external_refs.append({"source_name": meta.publisher.strip() or "source", "url": meta.source_url.strip()})
    if external_refs:
        kwargs["external_references"] = external_refs
    if meta.publisher.strip():
        kwargs["description"] = f"Published by {meta.publisher.strip()}."
    return stix2.Report(**kwargs)


def build_bundle(extraction: ExtractionResult) -> tuple[stix2.Bundle, list[str]]:
    warnings: list[str] = []
    id_map: dict[str, str] = {}
    objects: list = []

    generator = _generator_identity()
    objects.append(generator)
    created_by = generator.id

    published = _parse_datetime(extraction.report.published)
    if published is None:
        if extraction.report.published:
            warnings.append(
                f"Could not parse report publication date '{extraction.report.published}'; using current time."
            )
        published = datetime.now(timezone.utc)

    for entity in extraction.entities:
        obj = _build_entity(entity, warnings, created_by)
        if obj is None:
            continue
        if obj.id in {o.id for o in objects}:
            # Two extracted entities collapsed to the same stable ID (same type + name).
            # The extraction prompt asks the model to merge these; if it didn't, keep the
            # first and point the second local_id at it so relationships still resolve.
            warnings.append(
                f"Entity '{entity.name}' ({entity.local_id}) duplicates an earlier entity with the same "
                f"type and name; merged into {obj.id}."
            )
            id_map[entity.local_id] = obj.id
            continue
        id_map[entity.local_id] = obj.id
        objects.append(obj)

    for observable in extraction.observables:
        built = _build_observable(observable, warnings, created_by, valid_from=published)
        if built is None:
            continue
        sco, indicator, based_on = built
        existing_ids = {o.id for o in objects}
        for obj in (sco, indicator, based_on):
            if obj.id not in existing_ids:
                objects.append(obj)
        # Model-authored relationships attach to the observable itself, not its indicator.
        id_map[observable.local_id] = sco.id

    for rel in extraction.relationships:
        source_ref = id_map.get(rel.source_local_id)
        target_ref = id_map.get(rel.target_local_id)
        if not source_ref or not target_ref:
            # Schema validation already rejects unknown local_ids; this only fires when a
            # referenced entity/observable was itself skipped by the builder above.
            warnings.append(
                f"Dropped relationship '{rel.source_local_id}' -{rel.relationship_type}-> "
                f"'{rel.target_local_id}': endpoint was not built."
            )
            continue
        rel_type, note = resolve_relationship(
            source_ref.split("--", 1)[0], rel.relationship_type, target_ref.split("--", 1)[0]
        )
        if note:
            warnings.append(f"Relationship {rel.source_local_id} -> {rel.target_local_id}: {note}")
        objects.append(_relationship(rel_type, source_ref, target_ref, rel.description, created_by))

    report = _build_report(
        extraction,
        object_refs=[o.id for o in objects if o.id != created_by],
        created_by_ref=created_by,
        published=published,
    )
    objects.append(report)

    bundle = stix2.Bundle(*objects, allow_custom=True)
    return bundle, warnings
