"""Deterministically turns the extraction IR into a schema-valid STIX 2.1 Bundle.

The LLM never emits STIX JSON directly: it names entities and relationships, and this
module is solely responsible for STIX object types, required properties, ID generation,
and observable patterns. Keeping that split means STIX-format correctness doesn't depend
on the model getting spec details right.
"""

from datetime import datetime, timezone

import stix2

from stix_generator.extraction.schema import ExtractedObservable, ExtractionResult

OBSERVABLE_PATTERN_TEMPLATES = {
    "domain-name": "[domain-name:value = '{value}']",
    "ipv4-addr": "[ipv4-addr:value = '{value}']",
    "ipv6-addr": "[ipv6-addr:value = '{value}']",
    "url": "[url:value = '{value}']",
}


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    candidates = [value, f"{value}T00:00:00+00:00"]
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _build_entity(entity, warnings: list[str]):
    props = entity.properties or {}
    common = {"name": entity.name, "description": entity.description}
    if entity.aliases:
        common["aliases"] = entity.aliases

    if entity.type == "threat-actor":
        kwargs = dict(common)
        for key in ("roles", "sophistication", "primary_motivation"):
            if key in props:
                kwargs[key] = props[key]
        return stix2.ThreatActor(**kwargs)

    if entity.type == "identity":
        kwargs = dict(common)
        kwargs["identity_class"] = props.get("identity_class", "unknown")
        if "sectors" in props:
            kwargs["sectors"] = props["sectors"]
        return stix2.Identity(**kwargs)

    if entity.type == "malware":
        kwargs = dict(common)
        kwargs["is_family"] = bool(props.get("is_family", False))
        if "malware_types" in props:
            kwargs["malware_types"] = props["malware_types"]
        return stix2.Malware(**kwargs)

    if entity.type == "tool":
        kwargs = dict(common)
        if "tool_types" in props:
            kwargs["tool_types"] = props["tool_types"]
        return stix2.Tool(**kwargs)

    if entity.type == "infrastructure":
        kwargs = dict(common)
        kwargs["infrastructure_types"] = props.get("infrastructure_types") or ["unknown"]
        return stix2.Infrastructure(**kwargs)

    if entity.type == "vulnerability":
        kwargs = dict(common)
        cve_id = props.get("cve_id")
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
        kwargs = dict(common)
        attack_id = props.get("attack_pattern_id")
        if attack_id:
            kwargs["external_references"] = [{"source_name": "mitre-attack", "external_id": attack_id}]
        return stix2.AttackPattern(**kwargs)

    if entity.type == "campaign":
        kwargs = dict(common)
        if props.get("objective"):
            kwargs["objective"] = props["objective"]
        first_seen = _parse_datetime(props.get("first_seen", ""))
        if first_seen:
            kwargs["first_seen"] = first_seen
        return stix2.Campaign(**kwargs)

    if entity.type == "location":
        kwargs = {"description": entity.description}
        if props.get("country"):
            kwargs["country"] = props["country"]
        if props.get("region"):
            kwargs["region"] = props["region"]
        if "country" not in kwargs and "region" not in kwargs:
            warnings.append(f"Skipped location '{entity.name}' ({entity.local_id}): no country or region given.")
            return None
        return stix2.Location(**kwargs)

    warnings.append(f"Unknown entity type '{entity.type}' for '{entity.name}' ({entity.local_id}); skipped.")
    return None


def _build_observable_indicator(observable: ExtractedObservable, warnings: list[str]):
    template = OBSERVABLE_PATTERN_TEMPLATES.get(observable.observable_type)
    if not template:
        warnings.append(f"Unsupported observable type '{observable.observable_type}' ({observable.local_id}); skipped.")
        return None

    pattern = template.format(value=observable.value)
    return stix2.Indicator(
        name=observable.value,
        description=observable.description or f"{observable.observable_type} observed as attacker infrastructure.",
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
    )


def build_bundle(extraction: ExtractionResult) -> tuple[stix2.Bundle, list[str]]:
    warnings: list[str] = []
    id_map: dict[str, str] = {}
    objects = []

    for entity in extraction.entities:
        obj = _build_entity(entity, warnings)
        if obj is None:
            continue
        if entity.local_id in id_map:
            warnings.append(f"Duplicate local_id '{entity.local_id}' reused; later one wins.")
        id_map[entity.local_id] = obj.id
        objects.append(obj)

    for observable in extraction.observables:
        obj = _build_observable_indicator(observable, warnings)
        if obj is None:
            continue
        if observable.local_id in id_map:
            warnings.append(f"Duplicate local_id '{observable.local_id}' reused; later one wins.")
        id_map[observable.local_id] = obj.id
        objects.append(obj)

    for rel in extraction.relationships:
        source_ref = id_map.get(rel.source_local_id)
        target_ref = id_map.get(rel.target_local_id)
        if not source_ref or not target_ref:
            warnings.append(
                f"Dropped relationship '{rel.source_local_id}' -{rel.relationship_type}-> "
                f"'{rel.target_local_id}': unresolved local_id."
            )
            continue
        objects.append(
            stix2.Relationship(
                relationship_type=rel.relationship_type,
                source_ref=source_ref,
                target_ref=target_ref,
                description=rel.description,
            )
        )

    bundle = stix2.Bundle(*objects, allow_custom=True)
    return bundle, warnings
