"""Intermediate representation (IR) for the extraction step.

The LLM's job stops here: identify entities, observables, and relationships
from the source text. Turning this IR into schema-valid STIX 2.1 objects
(assigning real IDs, building patterns, choosing required properties) is
handled deterministically in stix_generator.construction — not by the model.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

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


class ExtractedEntity(BaseModel):
    local_id: str = Field(description="Short unique label the model invents, e.g. 'TA1', 'MAL1'. Used only to wire up relationships below.")
    type: EntityType
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(description="1-3 sentence description grounded in the source text.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Type-specific fields, see system prompt for the allowed keys per entity type.",
    )
    evidence_quote: str = Field(
        default="",
        description="A short verbatim quote (<=25 words) copied exactly from the report text supporting this item.",
    )
    grounding_status: Literal["verified", "unverified"] = Field(
        default="unverified",
        description="Set automatically after extraction — do not populate this yourself.",
    )


class ExtractedObservable(BaseModel):
    local_id: str = Field(description="Short unique label, e.g. 'DOM1', 'IP1'.")
    observable_type: ObservableType
    value: str = Field(description="Refanged value, e.g. 'code.newcli.com' not 'code.newcli[.]com'.")
    description: str = ""
    evidence_quote: str = Field(
        default="",
        description="A short verbatim quote (<=25 words) copied exactly from the report text supporting this item.",
    )
    grounding_status: Literal["verified", "unverified"] = Field(
        default="unverified",
        description="Set automatically after extraction — do not populate this yourself.",
    )


class ExtractedRelationship(BaseModel):
    source_local_id: str
    relationship_type: str = Field(description="STIX relationship-type verb, e.g. 'uses', 'targets', 'exploits', 'located-at', 'indicates'.")
    target_local_id: str
    description: str = ""
    evidence_quote: str = Field(
        default="",
        description="A short verbatim quote (<=25 words) copied exactly from the report text supporting this item.",
    )
    grounding_status: Literal["verified", "unverified"] = Field(
        default="unverified",
        description="Set automatically after extraction — do not populate this yourself.",
    )


class ExtractionResult(BaseModel):
    entities: list[ExtractedEntity]
    observables: list[ExtractedObservable] = Field(default_factory=list)
    relationships: list[ExtractedRelationship] = Field(default_factory=list)


EXTRACTION_TOOL_NAME = "record_extraction"


def extraction_tool_schema() -> dict:
    """JSON schema for the Claude tool-use call that produces an ExtractionResult."""
    schema = ExtractionResult.model_json_schema()
    return {
        "name": EXTRACTION_TOOL_NAME,
        "description": "Record all threat intelligence entities, observables, and relationships extracted from the report.",
        "input_schema": schema,
    }
