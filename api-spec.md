# STIX Workbench — API contract

A thin HTTP layer over the existing package. Nothing in `stix_generator/` changes; every
endpoint is a call into code that already exists. FastAPI + a background task runner is enough —
no queue broker until you have concurrent users.

Base URL: `/api`. All bodies JSON unless noted.

---

## Data shapes

`ExtractionIR` is exactly `stix_generator.extraction.schema.ExtractionResult` — the same shape
already written to `<out>.extraction.json` and read from `data/golden/`. Do not invent a
different wire format; `ExtractionResult.model_validate()` on the way in and
`.model_dump()` on the way out.

```
ExtractionIR {
  report:        { title, published, source_url, publisher }
  entities:      [{ local_id, type, name, aliases[], description, properties{},
                    evidence_quote, grounding_status }]
  observables:   [{ local_id, observable_type, value, description,
                    evidence_quote, grounding_status }]
  relationships: [{ source_local_id, relationship_type, target_local_id, description,
                    evidence_quote, grounding_status, verdict }]
}
```

`RunStatus`: `queued | loading | pass_a | critic | pass_b | pass_c | building | validating | ready | failed`

The UI's rail states map onto these: `rejected` and `truncated` are `failed` with a `failure` code.

---

## POST /api/runs

Multipart upload. Starts the pipeline in a background task and returns immediately.

```
file:        .pdf | .txt | .md   (required)
model:       str   = STIX_GENERATOR_MODEL default
critic:      bool  = false        # extractor.extract(enable_critic=)
verifier:    bool  = true         # extractor.extract(enable_verifier=)
golden_id:   str?                 # score against this gold file on completion
```

→ `201 { run_id, status: "queued" }`

Reject unsupported suffixes **before** queueing, mirroring `ingestion.loader.load_report`:
→ `415 { error: "unsupported_format", detail: "Unsupported report format: .docx" }`

Server work, in order: save upload → `load_report()` → `extract()` → `build_bundle()` →
`validate_bundle()` → write `<out>.json`, `<out>.extraction.json`.

## GET /api/runs

→ `200 { runs: [{ run_id, filename, status, created_at, counts{entities,observables,relationships},
        unverified, schema_errors, f1?, failure? }] }`

This is the rail. Poll every 2s while any run is non-terminal.

## GET /api/runs/{run_id}

→ `200 {
  run_id, filename, status, config{model,critic,verifier},
  usage[ { pass: "A"|"critic"|"B"|"C", input, cached, output, ms } ],   # from extractor._usage_note
  extraction: ExtractionIR,
  warnings: [str],          # pass-C notes + grounding warnings, as returned by extract()
  build_warnings: [str],    # from build_bundle()
  validation: { is_valid, errors[], warnings[] },
  bundle_path, extraction_path
}`

`404` if unknown, `409 { status }` if not `ready` and the caller asked for `extraction`.

## GET /api/runs/{run_id}/text

→ `200 { text }` — the plain text from `load_report()`.

The source pane needs this to highlight `evidence_quote`. Cache it client-side; it does not change.

## PUT /api/runs/{run_id}/extraction

The whole corrected IR, as the workbench holds it in memory.

```
{ extraction: ExtractionIR }
```

Server: `ExtractionResult.model_validate(...)` — its `_check_local_id_wiring` validator already
rejects duplicate `local_id`s and dangling relationship endpoints, which is exactly the
integrity check the editor needs. Then re-run `verify_grounding()` against the stored report
text so edited quotes get an honest `grounding_status`, and persist.

→ `200 { extraction, warnings }`  (warnings = fresh grounding warnings)
→ `422 { error: "invalid_ir", detail: "<pydantic message>" }`

## POST /api/runs/{run_id}/golden

Promote the current corrected IR to a gold file.

```
{ name?: str }   # default: report stem
```

→ `201 { golden_id, path: "data/golden/<name>.json" }`

## GET /api/runs/{run_id}/score?golden_id=…

`scoring.score_extraction(gold, predicted)` on the saved IR — no API call, no re-extraction.

→ `200 {
  entities: { overall{p,r,f1,tp,fp,fn}, by_type{...} },
  observables: { overall, by_type },
  relationships: { overall },
  verb_mismatches: [[endpoints, gold_verb, pred_verb]],
  type_confusions: [[gold_id, pred_id, transition]],
  unmatched_gold: { entities[], observables[] },
  unmatched_pred: { entities[], observables[] }
}`

## POST /api/runs/{run_id}/rebuild

Re-run `build_bundle()` + `validate_bundle()` on the corrected IR without touching the model.

→ `200 { validation, build_warnings, bundle_path }`

## GET /api/vocab

Static reference the editor's dropdowns need, served from the source of truth rather than
duplicated in JS (the workbench currently hardcodes these — replace on wiring):

→ `200 {
  entity_types: [...],            # schema.EntityType
  observable_types: [...],        # schema.ObservableType
  relationship_verbs: [...],      # schema.RELATIONSHIP_VERBS
  allowed_pairings: { "threat-actor|uses": ["attack-pattern", ...] },   # relationships.ALLOWED
  common: [...],                  # relationships.COMMON
  property_vocabs: { roles: [...], malware_types: [...] }               # vocab.PROPERTY_VOCABS
}`

## GET /api/golden

→ `200 { golden: [{ golden_id, name, path, counts }] }`

---

## Notes for whoever builds it

- **Long extraction, short request.** `extract()` is 20–60s across three passes. Everything is
  a background task keyed by `run_id`; the client polls `GET /api/runs`.
- **Cost is per run, not per request.** Guard `POST /api/runs` behind whatever auth you use —
  each call spends real API budget. `PUT .../extraction`, `/score` and `/rebuild` are free.
- **Never let the UI construct STIX.** The workbench edits the IR only. Bundles come from
  `construction.builder`, so ID determinism (UUIDv5) and vocab normalization stay in one place.
- **Grounding is server-side.** The client can preview a match, but `grounding_status` is only
  ever set by `grounding.verify_grounding()` against the stored text.
- **Concurrency.** One writer per run. If two analysts open the same run, last-write-wins is
  acceptable for now; add an `etag` on `GET` and require `If-Match` on `PUT` when it isn't.
