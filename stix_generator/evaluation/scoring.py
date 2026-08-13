"""Precision/recall/F1 scoring: compares a predicted ExtractionResult against a
hand-verified gold ExtractionResult (see data/golden/).

Entities are matched by type + fuzzy name/alias similarity (exact string match would
undercount — the model may phrase a name slightly differently than the gold label).
Observables match on exact normalized value. Relationships are scored by resolving
both sides through the entity/observable matches above, so a relationship error
downstream of an entity-matching error is counted honestly rather than double-penalized.
"""

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from stix_generator.extraction.schema import ExtractedEntity, ExtractedObservable, ExtractionResult
from stix_generator.extraction.text_normalize import normalize_for_matching

NAME_MATCH_THRESHOLD = 0.85


def _normalize_name(text: str) -> str:
    text = normalize_for_matching(text)
    text = re.sub(r"[^\w\s]", "", text)
    return text.strip()


def _name_similarity(names_a: list[str], names_b: list[str]) -> float:
    best = 0.0
    for a in names_a:
        na = _normalize_name(a)
        if not na:
            continue
        for b in names_b:
            nb = _normalize_name(b)
            if not nb:
                continue
            ratio = SequenceMatcher(None, na, nb).ratio()
            best = max(best, ratio)
    return best


def _greedy_match(pairs: list[tuple[int, int, float]]) -> list[tuple[int, int]]:
    """pairs: (gold_idx, pred_idx, score), already filtered by threshold. Assigns
    highest-scoring pairs first, each index used at most once."""
    used_gold: set[int] = set()
    used_pred: set[int] = set()
    matches = []
    for gold_idx, pred_idx, _score in sorted(pairs, key=lambda p: p[2], reverse=True):
        if gold_idx in used_gold or pred_idx in used_pred:
            continue
        used_gold.add(gold_idx)
        used_pred.add(pred_idx)
        matches.append((gold_idx, pred_idx))
    return matches


@dataclass
class CategoryScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class ScoreCard:
    entities_overall: CategoryScore
    entities_by_type: dict[str, CategoryScore]
    observables_overall: CategoryScore
    observables_by_type: dict[str, CategoryScore]
    relationships_overall: CategoryScore
    type_confusions: list[tuple[str, str, str]] = field(default_factory=list)
    unmatched_gold: dict[str, list[str]] = field(default_factory=dict)
    unmatched_pred: dict[str, list[str]] = field(default_factory=dict)


def _bump(by_type: dict[str, CategoryScore], key: str, attr: str) -> None:
    by_type.setdefault(key, CategoryScore())
    setattr(by_type[key], attr, getattr(by_type[key], attr) + 1)


def _overall(by_type: dict[str, CategoryScore]) -> CategoryScore:
    return CategoryScore(
        tp=sum(s.tp for s in by_type.values()),
        fp=sum(s.fp for s in by_type.values()),
        fn=sum(s.fn for s in by_type.values()),
    )


def _match_entities(gold: list[ExtractedEntity], pred: list[ExtractedEntity]):
    candidates = [
        (gi, pi, score)
        for gi, g in enumerate(gold)
        for pi, p in enumerate(pred)
        if g.type == p.type
        for score in [_name_similarity([g.name, *g.aliases], [p.name, *p.aliases])]
        if score >= NAME_MATCH_THRESHOLD
    ]
    matches = _greedy_match(candidates)
    matched_gold = {gi for gi, _ in matches}
    matched_pred = {pi for _, pi in matches}
    leftover_gold = [gi for gi in range(len(gold)) if gi not in matched_gold]
    leftover_pred = [pi for pi in range(len(pred)) if pi not in matched_pred]

    # Diagnostic-only pass over what's left, ignoring type — surfaces misclassifications
    # (e.g. "malware" vs "tool") as distinct from true misses/hallucinations, without
    # changing the headline counts: a wrong type is still an FN + an FP above.
    confusion_candidates = [
        (gi, pi, score)
        for gi in leftover_gold
        for pi in leftover_pred
        for score in [_name_similarity([gold[gi].name, *gold[gi].aliases], [pred[pi].name, *pred[pi].aliases])]
        if score >= NAME_MATCH_THRESHOLD
    ]
    type_confusions = [
        (gold[gi].local_id, pred[pi].local_id, f"{gold[gi].type} -> {pred[pi].type}")
        for gi, pi in _greedy_match(confusion_candidates)
    ]

    by_type: dict[str, CategoryScore] = {}
    for gi, _pi in matches:
        _bump(by_type, gold[gi].type, "tp")
    for gi in leftover_gold:
        _bump(by_type, gold[gi].type, "fn")
    for pi in leftover_pred:
        _bump(by_type, pred[pi].type, "fp")

    return matches, type_confusions, by_type, leftover_gold, leftover_pred


def _match_observables(gold: list[ExtractedObservable], pred: list[ExtractedObservable]):
    candidates = [
        (gi, pi, 1.0)
        for gi, g in enumerate(gold)
        for pi, p in enumerate(pred)
        if g.observable_type == p.observable_type
        and normalize_for_matching(g.value) == normalize_for_matching(p.value)
    ]
    matches = _greedy_match(candidates)
    matched_gold = {gi for gi, _ in matches}
    matched_pred = {pi for _, pi in matches}
    leftover_gold = [gi for gi in range(len(gold)) if gi not in matched_gold]
    leftover_pred = [pi for pi in range(len(pred)) if pi not in matched_pred]

    by_type: dict[str, CategoryScore] = {}
    for gi, _pi in matches:
        _bump(by_type, gold[gi].observable_type, "tp")
    for gi in leftover_gold:
        _bump(by_type, gold[gi].observable_type, "fn")
    for pi in leftover_pred:
        _bump(by_type, pred[pi].observable_type, "fp")

    return matches, by_type, leftover_gold, leftover_pred


def _match_relationships(gold_rels, pred_rels, gold_to_pred_id: dict[str, str]) -> CategoryScore:
    consumed_pred: set[int] = set()
    tp = fn = 0
    for g in gold_rels:
        mapped_source = gold_to_pred_id.get(g.source_local_id)
        mapped_target = gold_to_pred_id.get(g.target_local_id)
        found = None
        if mapped_source and mapped_target:
            for idx, p in enumerate(pred_rels):
                if idx in consumed_pred:
                    continue
                if (
                    p.source_local_id == mapped_source
                    and p.target_local_id == mapped_target
                    and p.relationship_type.lower() == g.relationship_type.lower()
                ):
                    found = idx
                    break
        if found is not None:
            consumed_pred.add(found)
            tp += 1
        else:
            fn += 1
    fp = len(pred_rels) - len(consumed_pred)
    return CategoryScore(tp=tp, fp=fp, fn=fn)


def score_extraction(gold: ExtractionResult, predicted: ExtractionResult) -> ScoreCard:
    entity_matches, type_confusions, entities_by_type, leftover_gold_e, leftover_pred_e = _match_entities(
        gold.entities, predicted.entities
    )
    obs_matches, observables_by_type, leftover_gold_o, leftover_pred_o = _match_observables(
        gold.observables, predicted.observables
    )

    gold_to_pred_id: dict[str, str] = {
        gold.entities[gi].local_id: predicted.entities[pi].local_id for gi, pi in entity_matches
    }
    gold_to_pred_id.update(
        {gold.observables[gi].local_id: predicted.observables[pi].local_id for gi, pi in obs_matches}
    )

    relationships_overall = _match_relationships(gold.relationships, predicted.relationships, gold_to_pred_id)

    return ScoreCard(
        entities_overall=_overall(entities_by_type),
        entities_by_type=entities_by_type,
        observables_overall=_overall(observables_by_type),
        observables_by_type=observables_by_type,
        relationships_overall=relationships_overall,
        type_confusions=type_confusions,
        unmatched_gold={
            "entities": [gold.entities[gi].local_id for gi in leftover_gold_e],
            "observables": [gold.observables[gi].local_id for gi in leftover_gold_o],
        },
        unmatched_pred={
            "entities": [predicted.entities[pi].local_id for pi in leftover_pred_e],
            "observables": [predicted.observables[pi].local_id for pi in leftover_pred_o],
        },
    )


def _print_category(label: str, score: CategoryScore, by_type: dict[str, CategoryScore] | None = None) -> None:
    print(
        f"  {label}: P={score.precision:.2f} R={score.recall:.2f} F1={score.f1:.2f} "
        f"(tp={score.tp} fp={score.fp} fn={score.fn})"
    )
    for type_name in sorted(by_type or {}):
        s = by_type[type_name]
        print(f"    {type_name}: P={s.precision:.2f} R={s.recall:.2f} F1={s.f1:.2f} (tp={s.tp} fp={s.fp} fn={s.fn})")


def print_scorecard(scorecard: ScoreCard) -> None:
    print("Entities:")
    _print_category("overall", scorecard.entities_overall, scorecard.entities_by_type)
    print("Observables:")
    _print_category("overall", scorecard.observables_overall, scorecard.observables_by_type)
    print("Relationships:")
    _print_category("overall", scorecard.relationships_overall)

    if scorecard.type_confusions:
        print("\nType confusions (name matched, type didn't — still counted as FN+FP above, not a wash):")
        for gold_id, pred_id, transition in scorecard.type_confusions:
            print(f"  {gold_id} vs {pred_id}: {transition}")

    missed = scorecard.unmatched_gold["entities"] + scorecard.unmatched_gold["observables"]
    if missed:
        print("\nMissed (in gold, not in prediction):")
        for local_id in missed:
            print(f"  {local_id}")

    hallucinated = scorecard.unmatched_pred["entities"] + scorecard.unmatched_pred["observables"]
    if hallucinated:
        print("\nHallucinated (in prediction, not in gold):")
        for local_id in hallucinated:
            print(f"  {local_id}")
