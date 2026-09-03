import pytest

from stix_generator.extraction import extractor
from stix_generator.extraction.schema import ENTITY_TOOL_NAME, RELATIONSHIP_TOOL_NAME, VERDICT_TOOL_NAME
from tests.fake_anthropic import FakeClient

REPORT = (
    "APT Example used the Hermes Agent framework to scan targets. "
    "Hermes Agent contacted api.example.com to reach the model. "
    "The actor targeted CVE-2024-0001 on exposed hosts."
)

PASS_A = {
    "report": {"title": "Example Report", "published": "2026-01-15"},
    "entities": [
        {"local_id": "TA1", "type": "threat-actor", "name": "APT Example", "description": "An actor.",
         "evidence_quote": "APT Example used the Hermes Agent framework"},
        {"local_id": "TOOL1", "type": "tool", "name": "Hermes Agent", "description": "Agent framework.",
         "evidence_quote": "Hermes Agent framework to scan targets"},
        {"local_id": "VULN1", "type": "vulnerability", "name": "CVE-2024-0001", "description": "A CVE.",
         "properties": {"cve_id": "CVE-2024-0001"}, "evidence_quote": "targeted CVE-2024-0001"},
    ],
    "observables": [
        {"local_id": "DOM1", "observable_type": "domain-name", "value": "api.example.com",
         "evidence_quote": "contacted api.example.com"},
    ],
}

PASS_B = {
    "relationships": [
        {"source_local_id": "TA1", "relationship_type": "uses", "target_local_id": "TOOL1",
         "evidence_quote": "APT Example used the Hermes Agent framework"},
        {"source_local_id": "TA1", "relationship_type": "exploits", "target_local_id": "VULN1",
         "evidence_quote": "The actor targeted CVE-2024-0001"},
        {"source_local_id": "TOOL1", "relationship_type": "communicates-with", "target_local_id": "DOM1",
         "evidence_quote": "Hermes Agent contacted api.example.com"},
        {"source_local_id": "VULN1", "relationship_type": "related-to", "target_local_id": "DOM1",
         "evidence_quote": "not really in the text"},
    ]
}

PASS_C = {
    "verdicts": [
        {"index": 0, "verdict": "supported", "evidence_quote": "APT Example used the Hermes Agent framework"},
        {"index": 1, "verdict": "downgrade", "replacement_type": "targets",
         "evidence_quote": "The actor targeted CVE-2024-0001"},
        {"index": 2, "verdict": "supported", "evidence_quote": "Hermes Agent contacted api.example.com"},
        {"index": 3, "verdict": "unsupported"},
    ]
}


def _install(monkeypatch, client):
    monkeypatch.setattr(extractor, "Anthropic", lambda: client)


def test_three_passes_assemble_and_apply_verdicts(monkeypatch):
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
        {"tool": VERDICT_TOOL_NAME, "input": PASS_C},
    ])
    _install(monkeypatch, client)

    result, warnings = extractor.extract(REPORT, model="fake")

    assert len(client.calls) == 3
    assert result.report.title == "Example Report"
    assert [e.local_id for e in result.entities] == ["TA1", "TOOL1", "VULN1"]

    rels = {(r.source_local_id, r.target_local_id): r for r in result.relationships}
    assert len(rels) == 3, "unsupported relationship should be dropped"
    assert rels[("TA1", "VULN1")].relationship_type == "targets"
    assert rels[("TA1", "VULN1")].verdict == "downgraded"
    assert rels[("TA1", "TOOL1")].verdict == "supported"
    assert all(r.grounding_status == "verified" for r in result.relationships)
    assert any("unsupported; dropped" in w for w in warnings)
    assert any("downgraded to 'targets'" in w for w in warnings)


def test_every_call_shares_tools_and_system_for_cache(monkeypatch):
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
        {"tool": VERDICT_TOOL_NAME, "input": PASS_C},
    ])
    _install(monkeypatch, client)
    extractor.extract(REPORT, model="fake")

    tool_lists = [c["tools"] for c in client.calls]
    systems = [c["system"] for c in client.calls]
    assert all(t == tool_lists[0] for t in tool_lists)
    assert all(s == systems[0] for s in systems)
    for call in client.calls:
        first_block = call["messages"][0]["content"][0]
        assert first_block["cache_control"] == {"type": "ephemeral"}
        assert "--- BEGIN REPORT ---" in first_block["text"]


def test_pass_b_dangling_endpoint_triggers_correction(monkeypatch):
    bad = {"relationships": [dict(PASS_B["relationships"][0], target_local_id="NOPE")]}
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": bad},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
        {"tool": VERDICT_TOOL_NAME, "input": PASS_C},
    ])
    _install(monkeypatch, client)
    result, _ = extractor.extract(REPORT, model="fake")

    assert len(client.calls) == 4
    correction = client.calls[2]["messages"][-1]["content"][0]
    assert correction["type"] == "tool_result" and correction["is_error"]
    assert "NOPE" in correction["content"]
    assert len(result.relationships) == 3


def test_no_verifier_keeps_pass_b_as_is(monkeypatch):
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
    ])
    _install(monkeypatch, client)
    result, warnings = extractor.extract(REPORT, model="fake", enable_verifier=False)
    assert len(client.calls) == 2
    assert len(result.relationships) == 4
    assert all(r.verdict == "" for r in result.relationships)
    assert any("not found in source text" in w for w in warnings)


def test_pass_c_missing_index_is_rejected(monkeypatch):
    partial = {"verdicts": PASS_C["verdicts"][:2] + [{"index": 9, "verdict": "supported", "evidence_quote": "x"}]}
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
        {"tool": VERDICT_TOOL_NAME, "input": partial},
        {"tool": VERDICT_TOOL_NAME, "input": PASS_C},
    ])
    _install(monkeypatch, client)
    result, _ = extractor.extract(REPORT, model="fake")
    assert len(client.calls) == 4
    assert len(result.relationships) == 3


def test_critic_runs_in_same_conversation_as_pass_a(monkeypatch):
    client = FakeClient([
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": ENTITY_TOOL_NAME, "input": PASS_A},
        {"tool": RELATIONSHIP_TOOL_NAME, "input": PASS_B},
        {"tool": VERDICT_TOOL_NAME, "input": PASS_C},
    ])
    _install(monkeypatch, client)
    extractor.extract(REPORT, model="fake", enable_critic=True)
    critic_messages = client.calls[1]["messages"]
    assert critic_messages[1]["role"] == "assistant"
    assert critic_messages[2]["content"][0]["type"] == "tool_result"
