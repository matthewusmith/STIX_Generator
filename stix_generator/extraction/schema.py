"""Intermediate representation (IR) for the extraction step.

The LLM's job stops here: identify entities, observables, and relationships
from the source text. Turning this IR into schema-valid STIX 2.1 objects
(assigning real IDs, building patterns, choosing required properties) is
handled deterministically in stix_generator.construction — not by the model.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

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


class GroundedFields(BaseModel):
    """Evidence/grounding fields shared by every extracted item type. grounding_status
    is stripped out of the model-facing tool schema (see extraction_tool_schema) and
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
    local_id: str = Field(description="Short unique label the model invents, e.g. 'TA1', 'MAL1'. Used only to wire up relationships below.")
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
    relationship_type: str = Field(description="STIX relationship-type verb, e.g. 'uses', 'targets', 'exploits', 'located-at', 'indicates'.")
    target_local_id: str
    description: str = ""


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


class ExtractionResult(BaseModel):
    report: ReportMetadata = Field(default_factory=ReportMetadata)
    entities: list[ExtractedEntity]
    observables: list[ExtractedObservable] = Field(default_factory=list)
    relationships: list[ExtractedRelationship] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_local_id_wiring(self) -> "ExtractionResult":
        """Reject duplicate local_ids and relationships that point at unknown local_ids.
        Raising here (rather than patching or dropping in the builder) routes the problem
        back through the extractor's schema-error retry, so the model fixes its own wiring
        instead of the pipeline silently losing relationships."""
        seen: set[str] = set()
        duplicates: list[str] = []
        for item in [*self.entities, *self.observables]:
            if item.local_id in seen:
                duplicates.append(item.local_id)
            seen.add(item.local_id)

        dangling = [
            f"{rel.source_local_id} -{rel.relationship_type}-> {rel.target_local_id}"
            for rel in self.relationships
            if rel.source_local_id not in seen or rel.target_local_id not in seen
        ]

        problems = []
        if duplicates:
            problems.append(f"duplicate local_id(s) used by more than one entity/observable: {sorted(set(duplicates))}")
        if dangling:
            problems.append(f"relationship(s) reference a local_id that no entity or observable has: {dangling}")
        if problems:
            raise ValueError("; ".join(problems))
        return self


EXTRACTION_TOOL_NAME = "record_extraction"


def extraction_tool_schema() -> dict:
    """JSON schema for the Claude tool-use call that produces an ExtractionResult."""
    schema = ExtractionResult.model_json_schema()
    # grounding_status must never be model-supplied (see GroundedFields) — strip it from
    # what the model can see entirely, rather than relying on a prose instruction, so an
    # off-vocabulary value can't burn a retry on a self-inflicted schema error.
    for definition in schema.get("$defs", {}).values():
        definition.get("properties", {}).pop("grounding_status", None)
    return {
        "name": EXTRACTION_TOOL_NAME,
        "description": "Record all threat intelligence entities, observables, and relationships extracted from the report.",
        "input_schema": schema,
    }
