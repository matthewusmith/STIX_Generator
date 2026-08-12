"""Calls Claude to turn raw report text into an ExtractionResult (the IR)."""

import os

from anthropic import Anthropic
from pydantic import ValidationError

from stix_generator.extraction.prompts import SYSTEM_PROMPT, build_user_prompt
from stix_generator.extraction.schema import (
    EXTRACTION_TOOL_NAME,
    ExtractionResult,
    extraction_tool_schema,
)

DEFAULT_MODEL = os.environ.get("STIX_GENERATOR_MODEL", "claude-sonnet-5")
MAX_ATTEMPTS = 3
MAX_TOKENS_CEILING = 32000


def extract(report_text: str, model: str = DEFAULT_MODEL, max_tokens: int = 16000) -> ExtractionResult:
    client = Anthropic()
    tools = [extraction_tool_schema()]
    tool_choice = {"type": "tool", "name": EXTRACTION_TOOL_NAME}
    messages = [{"role": "user", "content": build_user_prompt(report_text)}]
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
            messages = [{"role": "user", "content": build_user_prompt(report_text)}]
            continue

        try:
            return ExtractionResult.model_validate(tool_use.input)
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
