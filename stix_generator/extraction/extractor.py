"""Calls Claude to turn raw report text into an ExtractionResult (the IR)."""

import os

from anthropic import Anthropic
from pydantic import ValidationError

from stix_generator.extraction.grounding import verify_grounding
from stix_generator.extraction.prompts import SYSTEM_PROMPT, build_critic_user_message, build_user_prompt
from stix_generator.extraction.schema import (
    EXTRACTION_TOOL_NAME,
    ExtractionResult,
    extraction_tool_schema,
)

DEFAULT_MODEL = os.environ.get("STIX_GENERATOR_MODEL", "claude-sonnet-5")
MAX_ATTEMPTS = 3
MAX_TOKENS_CEILING = 32000


def _request_extraction(
    client: Anthropic,
    model: str,
    tools: list[dict],
    tool_choice: dict,
    messages: list[dict],
    max_tokens: int,
) -> tuple[ExtractionResult, str]:
    """Runs one logical extraction request against `messages`, retrying on truncation
    or schema-validation failure. Appends the assistant turn to `messages` on success
    (so a caller can continue the conversation, e.g. for a critic pass) and returns
    (result, tool_use_id)."""
    current_max_tokens = max_tokens

    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = client.messages.create(
            model=model,
            max_tokens=current_max_tokens,
            system=SYSTEM_PROMPT,
            tools=tools,
            tool_choice=tool_choice,
            messages=messages,
        )

        tool_use_blocks = [block for block in response.content if block.type == "tool_use"]
        if not tool_use_blocks:
            raise RuntimeError(f"Model did not call {EXTRACTION_TOOL_NAME}; stop_reason={response.stop_reason}")

        tool_use = tool_use_blocks[0]

        # A truncated tool call can still be syntactically valid JSON (e.g. a trailing
        # array just never gets written and falls back to its schema default), so this
        # check has to happen before validation — a passing schema check proves nothing
        # about completeness if the response was cut off mid-generation.
        if response.stop_reason == "max_tokens":
            if attempt == MAX_ATTEMPTS or current_max_tokens >= MAX_TOKENS_CEILING:
                raise RuntimeError(
                    f"Extraction truncated at {current_max_tokens} output tokens on every attempt "
                    f"(stop_reason=max_tokens). This report may need chunking, or raise "
                    f"MAX_TOKENS_CEILING in {__name__}."
                )
            current_max_tokens = min(current_max_tokens * 2, MAX_TOKENS_CEILING)
            print(
                f"      extraction attempt {attempt} was truncated (stop_reason=max_tokens) "
                f"before finishing; retrying with max_tokens={current_max_tokens}..."
            )
            continue

        try:
            result = ExtractionResult.model_validate(tool_use.input)
            messages.append({"role": "assistant", "content": response.content})
            return result, tool_use.id
        except ValidationError as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            print(f"      extraction attempt {attempt} failed schema validation, asking model to correct...")
            messages.append({"role": "assistant", "content": response.content})
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use.id,
                            "content": f"Your input did not match the required schema:\n{exc}\n"
                            "Call record_extraction again with corrected input.",
                            "is_error": True,
                        }
                    ],
                }
            )

    raise RuntimeError("unreachable")


def extract(
    report_text: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 16000,
    enable_critic: bool = False,
) -> tuple[ExtractionResult, list[str]]:
    """Returns (result, grounding_warnings). Set enable_critic=True to run one extra
    Claude call (roughly doubling this function's API cost) that re-checks the draft
    for hallucinations and omissions before returning."""
    client = Anthropic()
    tools = [extraction_tool_schema()]
    tool_choice = {"type": "tool", "name": EXTRACTION_TOOL_NAME}
    messages = [{"role": "user", "content": build_user_prompt(report_text)}]

    result, tool_use_id = _request_extraction(client, model, tools, tool_choice, messages, max_tokens)

    if enable_critic:
        print("      running critic pass...")
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": "Draft recorded.",
                    },
                    {
                        "type": "text",
                        "text": build_critic_user_message(report_text),
                    },
                ],
            }
        )
        result, _ = _request_extraction(client, model, tools, tool_choice, messages, max_tokens)

    return verify_grounding(result, report_text)
