"""Intermediate representation (IR) for the extraction step.

The LLM's job stops here: identify entities, observables, and relationships
from the source text. Turning this IR into schema-valid STIX 2.1 objects
(assigning real IDs, building patterns, choosing required properties) is
handled deterministically in stix_generator.construction — not by the model.

Extraction is three model passes, each with its own tool schema:

  A. `record_entities`      — entities, observables, report metadata
  B. `record_relationships` — relationships between pass A's local_ids (checked on parse)
  C. `record_verdicts`      — a supported / downgrade / unsupported verdict per pass-B relationship

The assembled result of all three is the same `ExtractionResult` the builder and the
evaluator have always consumed, so golden files and downstream code are unaffected.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from stix_generator.stix.relationships import ALLOWED, COMMON

EntityType = Literal[
    "threat-actor",
    "identity",
    "malware",
    "tool",
    "infrastructure",
    "vulnerability",
    "attack-pattern",
    "campaign",
    "location",
]

ObservableType = Literal[
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "url",
]

# Every verb the pairing table knows, plus the spec's common relationships. Pass B's
# tool schema restricts relationship_type to this list, so an off-vocabulary verb is a
# schema error the model corrects itself rather than something the builder rewrites.
RELATIONSHIP_VERBS: list[str] = sorted({rel for (src, rel) in ALLOWED if src != "indicator"} | COMMON)

# Fields the model must never populate: they are computed by the pipeline after the fact.
PIPELINE_ONLY_FIELDS = {"grounding_status", "verdict"}


class GroundedFields(BaseModel):
    """Evidence/grounding fields shared by every extracted item type. grounding_status
    is stripped out of the model-facing tool schemas (see _strip_pipeline_fields) and
    computed deterministically after the fact — evidence_quote is the only one of
    these two the model actually supplies."""

    evidence_quote: str = Field(
        default="",
        description="A short verbatim quote (<=25 words) copied exactly from the report text supporting this item.",
    )
    grounding_status: Literal["verified", "unverified"] = Field(
        default="unverified",
        description="Set automatically after extraction — do not populate this yourself.",
    )


class ExtractedEntity(GroundedFields):
    local_id: str = Field(description="Short unique label the model invents, e.g. 'TA1', 'MAL1'. Used only to wire up relationships later.")
    type: EntityType
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(description="1-3 sentence description grounded in the source text.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Type-specific fields, see system prompt for the allowed keys per entity type.",
    )


class ExtractedObservable(GroundedFields):
    local_id: str = Field(description="Short unique label, e.g. 'DOM1', 'IP1'.")
    observable_type: ObservableType
    value: str = Field(description="Refanged value, e.g. 'code.newcli.com' not 'code.newcli[.]com'.")
    description: str = ""


class ExtractedRelationship(GroundedFields):
    source_local_id: str
    relationship_type: str = Field(description="STIX relationship-type verb, e.g. 'uses', 'targets', 'exploits', 'located-at'.")
    target_local_id: str
    description: str = ""
    verdict: Literal["", "supported", "downgraded"] = Field(
        default="",
        description="Set by the verification pass — do not populate this yourself.",
    )


class ReportMetadata(BaseModel):
    """Document-level facts about the source report itself. Used to build the STIX
    `report` object that groups everything else and to date-stamp indicators."""

    title: str = Field(default="", description="Title of the report as printed in the document.")
    published: str = Field(
        default="",
        description="Publication date of the report as an ISO 8601 date (YYYY-MM-DD) if stated in the document; otherwise empty.",
    )
    source_url: str = Field(default="", description="URL of the report if printed in the document; otherwise empty.")
    publisher: str = Field(default="", description="Name of the organization that published the report, if stated.")


def _duplicate_local_ids(entities, observables) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for item in [*entities, *observables]:
        if item.local_id in seen:
            duplicates.append(item.local_id)
        seen.add(item.local_id)
    return sorted(set(duplicates))


class EntityExtraction(BaseModel):
    """Pass A output."""

    report: ReportMetadata = Field(default_factory=ReportMetadata)
    entities: list[ExtractedEntity]
    observables: list[ExtractedObservable] = Field(default_factory=list)

    @property
    def local_ids(self) -> list[str]:
        return [item.local_id for item in [*self.entities, *self.observables]]

    @model_validator(mode="after")
    def _check_unique_local_ids(self) -> "EntityExtraction":
        duplicates = _duplicate_local_ids(self.entities, self.observables)
        if duplicates:
            raise ValueError(f"duplicate local_id(s) used by more than one entity/observable: {duplicates}")
        return self


class RelationshipExtraction(BaseModel):
    """Pass B output. Endpoints are validated against pass A's local_ids by
    `relationship_parser`, not by the tool schema — see the note on that function."""

    relationships: list[ExtractedRelationship] = Field(default_factory=list)


def relationship_parser(local_ids: list[str]):
    """Returns a parse function for pass B that rejects relationships whose endpoints
    aren't in pass A's local_ids, so the extractor's schema-error retry makes the model
    correct them.

    Why not put the ids in the tool schema as enums? The prompt cache is prefix-based
    over (tools, system, messages), and tools come first: a per-report tool schema
    would invalidate the cached report for pass B. Keeping the tool list identical
    across passes and validating endpoints here preserves the cache and, via the retry
    loop, gives the same end result."""
    known = set(local_ids)

    def parse(payload: dict) -> RelationshipExtraction:
        result = RelationshipExtraction.model_validate(payload)
        dangling = [
            f"{r.source_local_id} -{r.relationship_type}-> {r.target_local_id}"
            for r in result.relationships
            if r.source_local_id not in known or r.target_local_id not in known
        ]
        if dangling:
            raise ValueError(
                f"relationship(s) reference a local_id that is not in the provided list: {dangling}. "
                f"Valid local_ids: {sorted(known)}"
            )
        return result

    return parse


class Verdict(BaseModel):
    """One pass-C judgement about one pass-B relationship, referenced by list index."""

    index: int = Field(description="0-based index of the relationship being judged, as listed in the prompt.")
    verdict: Literal["supported", "downgrade", "unsupported"]
    replacement_type: str = Field(
        default="",
        description="Required when verdict is 'downgrade': the weaker relationship verb the text actually supports.",
    )
    evidence_quote: str = Field(
        default="",
        description="Verbatim quote (<=25 words) from the report supporting the (possibly downgraded) relationship. Empty for 'unsupported'.",
    )


class VerificationResult(BaseModel):
    """Pass C output."""

    verdicts: list[Verdict]

    @model_validator(mode="after")
    def _check_verdicts(self) -> "VerificationResult":
        seen: set[int] = set()
        problems: list[str] = []
        for v in self.verdicts:
            if v.index in seen:
                problems.append(f"index {v.index} judged more than once")
            seen.add(v.index)
            if v.verdict == "downgrade" and not v.replacement_type:
                problems.append(f"index {v.index}: verdict 'downgrade' requires replacement_type")
            if v.verdict != "unsupported" and not v.evidence_quote.strip():
                problems.append(f"index {v.index}: verdict '{v.verdict}' requires an evidence_quote")
        if problems:
            raise ValueError("; ".join(problems))
        return self


class ExtractionResult(BaseModel):
    """The assembled IR consumed by construction and evaluation."""

    report: ReportMetadata = Field(default_factory=ReportMetadata)
    entities: list[ExtractedEntity]
    observables: list[ExtractedObservable] = Field(default_factory=list)
    relationships: list[ExtractedRelationship] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_local_id_wiring(self) -> "ExtractionResult":
        """Reject duplicate local_ids and relationships that point at unknown local_ids.
        The three-pass extractor can't produce these (pass B's endpoints are schema
        enums), but golden files and hand-edited IRs can."""
        duplicates = _duplicate_local_ids(self.entities, self.observables)
        known = {item.local_id for item in [*self.entities, *self.observables]}
        dangling = [
            f"{rel.source_local_id} -{rel.relationship_type}-> {rel.target_local_id}"
            for rel in self.relationships
            if rel.source_local_id not in known or rel.target_local_id not in known
        ]
        problems = []
        if duplicates:
            problems.append(f"duplicate local_id(s) used by more than one entity/observable: {duplicates}")
        if dangling:
            problems.append(f"relationship(s) reference a local_id that no entity or observable has: {dangling}")
        if problems:
            raise ValueError("; ".join(problems))
        return self


# --- Tool schemas -------------------------------------------------------------------

ENTITY_TOOL_NAME = "record_entities"
RELATIONSHIP_TOOL_NAME = "record_relationships"
VERDICT_TOOL_NAME = "record_verdicts"


def _strip_pipeline_fields(schema: dict) -> dict:
    """Remove pipeline-only fields from the model-facing schema entirely, rather than
    relying on a prose instruction, so an off-vocabulary value can't burn a retry on a
    self-inflicted schema error."""
    for definition in schema.get("$defs", {}).values():
        for field in PIPELINE_ONLY_FIELDS:
            definition.get("properties", {}).pop(field, None)
    for field in PIPELINE_ONLY_FIELDS:
        schema.get("properties", {}).pop(field, None)
    return schema


def entity_tool_schema() -> dict:
    return {
        "name": ENTITY_TOOL_NAME,
        "description": "Record all threat intelligence entities and observables extracted from the report, plus the report's own metadata.",
        "input_schema": _strip_pipeline_fields(EntityExtraction.model_json_schema()),
    }


def relationship_tool_schema() -> dict:
    """Fixed across reports (see relationship_parser for why endpoints aren't enums)."""
    return {
        "name": RELATIONSHIP_TOOL_NAME,
        "description": "Record every relationship the report states between the listed entities and observables.",
        "input_schema": {
            "type": "object",
            "properties": {
                "relationships": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_local_id": {"type": "string", "description": "A local_id from the provided list."},
                            "relationship_type": {"type": "string", "enum": RELATIONSHIP_VERBS},
                            "target_local_id": {"type": "string", "description": "A local_id from the provided list."},
                            "description": {"type": "string"},
                            "evidence_quote": {
                                "type": "string",
                                "description": "A short verbatim quote (<=25 words) copied exactly from the report text supporting this relationship.",
                            },
                        },
                        "required": ["source_local_id", "relationship_type", "target_local_id", "evidence_quote"],
                    },
                }
            },
            "required": ["relationships"],
        },
    }


def verdict_tool_schema() -> dict:
    schema = _strip_pipeline_fields(VerificationResult.model_json_schema())
    # Constrain replacement_type to the same verb list pass B used.
    schema["$defs"]["Verdict"]["properties"]["replacement_type"]["enum"] = ["", *RELATIONSHIP_VERBS]
    return {
        "name": VERDICT_TOOL_NAME,
        "description": "Record a verdict for every numbered relationship: supported, downgrade (with the weaker verb the text actually supports), or unsupported.",
        "input_schema": schema,
    }
