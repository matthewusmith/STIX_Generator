import json

from stix_generator.construction.builder import build_bundle
from stix_generator.evaluation.scoring import score_extraction
from stix_generator.extraction.schema import ExtractionResult
from stix_generator.validation.validator import validate_bundle


def test_golden_builds_valid_bundle_with_stable_ids(golden_dict):
    g = ExtractionResult.model_validate(golden_dict)
    b1, _ = build_bundle(g)
    b2, _ = build_bundle(g)
    ids1 = {o["id"] for o in json.loads(b1.serialize())["objects"]}
    ids2 = {o["id"] for o in json.loads(b2.serialize())["objects"]}
    assert ids1 == ids2
    validation = validate_bundle(b1.serialize(pretty=True))
    assert validation["is_valid"], validation["errors"]


def test_bundle_has_report_wrapping_everything(golden_dict):
    g = ExtractionResult.model_validate(golden_dict)
    bundle, _ = build_bundle(g)
    objs = json.loads(bundle.serialize())["objects"]
    reports = [o for o in objs if o["type"] == "report"]
    assert len(reports) == 1
    others = {o["id"] for o in objs if o["type"] != "report" and o["id"] != reports[0]["created_by_ref"]}
    assert set(reports[0]["object_refs"]) == others


def test_scoring_golden_against_itself_is_perfect(golden_dict):
    g = ExtractionResult.model_validate(golden_dict)
    card = score_extraction(g, g)
    assert card.entities_overall.f1 == 1.0
    assert card.observables_overall.f1 == 1.0
    assert card.relationships_overall.f1 == 1.0
    assert card.relationships_conditional.f1 == 1.0


def test_conditional_score_separates_missing_endpoint_from_missing_link(golden_dict):
    g = ExtractionResult.model_validate(golden_dict)
    pred = json.loads(json.dumps(golden_dict))
    # Drop one entity: relationships touching it become overall-FN but not conditional-FN.
    dropped = pred["entities"].pop()
    pred["relationships"] = [
        r for r in pred["relationships"]
        if dropped["local_id"] not in (r["source_local_id"], r["target_local_id"])
    ]
    # Change one surviving verb: an overall-FN+FP *and* a conditional-FN+FP with a verb mismatch.
    pred["relationships"][0]["relationship_type"] = "related-to"
    p = ExtractionResult.model_validate(pred)
    card = score_extraction(g, p)
    assert card.relationships_conditional.fn == 1
    assert card.relationships_conditional.fp == 1
    assert card.relationships_overall.fn > card.relationships_conditional.fn
    assert len(card.verb_mismatches) == 1
