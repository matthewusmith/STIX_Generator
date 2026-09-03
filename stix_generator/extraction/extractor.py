"""Calls Claude to turn raw report text into an ExtractionResult (the IR).

Three passes (see schema.py):
  A. entities + observables + report metadata      (optionally followed by a critic re-read)
  B. relationships over pass A's local_ids         (endpoints are schema enums)
  C. a verdict per relationship                    (supported / downgrade / unsupported)

All passes share the same tool list, system prompt, and cached report block so passes
B and C hit the prompt cache for everything up to the per-pass instruction.
"""

import os
from typing import Callable, TypeVar

from anthropic import Anthropic
from pydantic import BaseModel, ValidationError

from stix_generator.extraction.grounding import verify_grounding
from stix_generator.extraction.prompts import (
    CRITIC_INSTRUCTION,
    PASS_A_INSTRUCTION,
    SYSTEM_PROMPT,
    pass_b_instruction,
    pass_c_instruction,
    report_block,
)
from stix_generator.extraction.schema import (
    ENTITY_TOOL_NAME,
    RELATIONSHIP_TOOL_NAME,
    VERDICT_TOOL_NAME,
    EntityExtraction,
    ExtractedRelationship,
    ExtractionResult,
    VerificationResult,
    entity_tool_schema,
    relationship_parser,
    relationship_tool_schema,
    verdict_tool_schema,
)

DEFAULT_MODEL = os.environ.get("STIX_GENERATOR_MODEL", "claude-sonnet-5")
MAX_ATTEMPTS = 3
MAX_TOKENS_CEILING = 32000
PASS_MAX_TOKENS = {"A": 16000, "B": 8000, "C": 8000}

T = TypeVar("T", bound=BaseModel)


def _usage_note(response) -> str:
    u = getattr(response, "usage", None)
    if u is None:
        return ""
    cached = getattr(u, "cache_read_input_tokens", 0) or 0
    return f"(in={u.input_tokens} cached={cached} out={u.output_tokens})"


def _request(
    client: Anthropic,
    model: str,
    tools: list[dict],
    tool_name: str,
    messages: list[dict],
    max_tokens: int,
    parse: Callable[[dict], T],
    label: str,
) -> tuple[T, str]:
    """Runs one logical request against `messages`, retrying on truncation or
    schema-validation failure. Appends the assistant turn to `messages` on success
    (so a caller can continue the conversation) and returns (parsed, tool_use_id)."""
    current_max_tokens = max_tokens
    start_len = len(messages)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = client.messages.create(
            model=model,
            max_tokens=current_max_tokens,
            system=SYSTEM_PROMPT,
            tools=tools,
            tool_choice={"type": "tool", "name": tool_name},
            messages=messages,
        )

        tool_use_blocks = [block for block in response.content if block.type == "tool_use"]
        if not tool_use_blocks:
            raise RuntimeError(f"{label}: model did not call {tool_name}; stop_reason={response.stop_reason}")
        tool_use = tool_use_blocks[0]

        # A truncated tool call can still be syntactically valid JSON (a trailing array
        # just never gets written and falls back to its default), so check stop_reason
        # before validation — a passing schema check proves nothing about completeness.
        if response.stop_reason == "max_tokens":
            if attempt == MAX_ATTEMPTS or current_max_tokens >= MAX_TOKENS_CEILING:
                raise RuntimeError(
                    f"{label}: truncated at {current_max_tokens} output tokens on every attempt. "
                    f"This report may need chunking, or raise MAX_TOKENS_CEILING in {__name__}."
                )
            current_max_tokens = min(current_max_tokens * 2, MAX_TOKENS_CEILING)
            print(f"      {label} attempt {attempt} truncated; retrying with max_tokens={current_max_tokens}...")
            del messages[start_len:]
            continue

        try:
            parsed = parse(tool_use.input)
        except (ValidationError, ValueError) as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            print(f"      {label} attempt {attempt} failed schema validation, asking model to correct...")
            messages.append({"role": "assistant", "content": response.content})
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use.id,
                            "content": f"Your input did not match the required schema:\n{exc}\nCall {tool_name} again with corrected input.",
                            "is_error": True,
                        }
                    ],
                }
            )
            continue

        print(f"      {label} done {_usage_note(response)}")
        messages.append({"role": "assistant", "content": response.content})
        return parsed, tool_use.id

    raise RuntimeError("unreachable")


def _fresh_messages(report_text: str, instruction: str) -> list[dict]:
    return [{"role": "user", "content": [report_block(report_text), {"type": "text", "text": instruction}]}]


def apply_verdicts(
    relationships: list[ExtractedRelationship], verification: VerificationResult
) -> tuple[list[ExtractedRelationship], list[str]]:
    """Pure function: applies pass C verdicts to pass B relationships. Unsupported ones are
    dropped, downgrades get the replacement verb, and the verifier's quote replaces the
    extractor's so grounding checks the judgement that actually kept the item."""
    notes: list[str] = []
    by_index = {v.index: v for v in verification.verdicts}
    kept: list[ExtractedRelationship] = []
    for i, rel in enumerate(relationships):
        verdict = by_index.get(i)
        if verdict is None:
            notes.append(f"[{i}] {rel.source_local_id} -{rel.relationship_type}-> {rel.target_local_id}: no verdict returned; kept unverified.")
            kept.append(rel)
            continue
        if verdict.verdict == "unsupported":
            notes.append(f"[{i}] {rel.source_local_id} -{rel.relationship_type}-> {rel.target_local_id}: unsupported; dropped.")
            continue
        update = {"evidence_quote": verdict.evidence_quote}
        if verdict.verdict == "downgrade":
            notes.append(
                f"[{i}] {rel.source_local_id} -{rel.relationship_type}-> {rel.target_local_id}: "
                f"downgraded to '{verdict.replacement_type}'."
            )
            update["relationship_type"] = verdict.replacement_type
            update["verdict"] = "downgraded"
        else:
            update["verdict"] = "supported"
        kept.append(rel.model_copy(update=update))
    return kept, notes


def extract(
    report_text: str,
    model: str = DEFAULT_MODEL,
    enable_critic: bool = False,
    enable_verifier: bool = True,
) -> tuple[ExtractionResult, list[str]]:
    """Returns (result, warnings). warnings holds grounding warnings plus pass C notes.

    enable_critic adds one extra call after pass A that re-reads the entity draft.
    enable_verifier=False skips pass C (two-pass mode), useful for A/B measurement."""
    client = Anthropic()
    # Identical tool list on every call: tools are the first segment of the cache prefix,
    # so any per-pass difference here would defeat caching of the report block.
    tools = [entity_tool_schema(), relationship_tool_schema(), verdict_tool_schema()]

    # --- Pass A ---------------------------------------------------------------
    messages = _fresh_messages(report_text, PASS_A_INSTRUCTION)
    entities, tool_use_id = _request(
        client, model, tools, ENTITY_TOOL_NAME, messages, PASS_MAX_TOKENS["A"],
        EntityExtraction.model_validate, "pass A",
    )

    if enable_critic:
        messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": tool_use_id, "content": "Draft recorded."},
                    {"type": "text", "text": CRITIC_INSTRUCTION},
                ],
            }
        )
        try:
            entities, _ = _request(
                client, model, tools, ENTITY_TOOL_NAME, messages, PASS_MAX_TOKENS["A"],
                EntityExtraction.model_validate, "critic",
            )
        except Exception as exc:  # noqa: BLE001
            # The critic is an additive check on an already-valid draft; its failure
            # shouldn't turn a successful extraction into a total one.
            print(f"      critic pass failed ({exc}); keeping pre-critic draft.")

    relationships: list[ExtractedRelationship] = []
    notes: list[str] = []

    # --- Pass B ---------------------------------------------------------------
    local_ids = entities.local_ids
    if local_ids:
        messages = _fresh_messages(report_text, pass_b_instruction(entities.entities, entities.observables))
        rel_result, _ = _request(
            client, model, tools, RELATIONSHIP_TOOL_NAME, messages, PASS_MAX_TOKENS["B"],
            relationship_parser(local_ids), "pass B",
        )
        relationships = rel_result.relationships

    # --- Pass C ---------------------------------------------------------------
    if relationships and enable_verifier:
        n = len(relationships)

        def parse_verdicts(payload: dict) -> VerificationResult:
            result = VerificationResult.model_validate(payload)
            bad = [v.index for v in result.verdicts if not 0 <= v.index < n]
            if bad:
                raise ValueError(f"verdict index(es) out of range 0..{n - 1}: {bad}")
            return result

        messages = _fresh_messages(
            report_text, pass_c_instruction(relationships, entities.entities, entities.observables)
        )
        verification, _ = _request(
            client, model, tools, VERDICT_TOOL_NAME, messages, PASS_MAX_TOKENS["C"], parse_verdicts, "pass C"
        )
        relationships, notes = apply_verdicts(relationships, verification)

    result = ExtractionResult(
        report=entities.report,
        entities=entities.entities,
        observables=entities.observables,
        relationships=relationships,
    )
    result, grounding_warnings = verify_grounding(result, report_text)
    return result, [*notes, *grounding_warnings]
