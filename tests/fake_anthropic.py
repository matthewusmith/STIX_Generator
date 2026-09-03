"""A stand-in for anthropic.Anthropic that replays scripted tool_use responses, so the
three-pass orchestration can be exercised without network access or an API key."""

import copy
from types import SimpleNamespace


class FakeClient:
    def __init__(self, scripted: list[dict]):
        """scripted: list of dicts, one per API call in order. Keys:
        tool (str), input (dict), stop_reason (default 'end_turn')."""
        self._scripted = list(scripted)
        self.calls: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        # Snapshot: the extractor mutates its messages list after the call returns.
        self.calls.append(copy.deepcopy(kwargs))
        if not self._scripted:
            raise AssertionError(f"unexpected API call #{len(self.calls)}: tool_choice={kwargs.get('tool_choice')}")
        step = self._scripted.pop(0)
        expected = kwargs["tool_choice"]["name"]
        assert step["tool"] == expected, f"call #{len(self.calls)} expected tool {expected}, script had {step['tool']}"
        block = SimpleNamespace(type="tool_use", id=f"toolu_{len(self.calls)}", name=step["tool"], input=step["input"])
        usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=step.get("cached", 0))
        return SimpleNamespace(content=[block], stop_reason=step.get("stop_reason", "end_turn"), usage=usage)
