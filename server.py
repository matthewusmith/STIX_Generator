"""Local HTTP server for the STIX Workbench UI.

Serves the workbench and exposes the pipeline over HTTP. Nothing in stix_generator/
is modified — every endpoint is a thin call into code that already exists.

Run:
    .venv\\Scripts\\pip.exe install fastapi uvicorn python-multipart
    .venv\\Scripts\\python.exe server.py

Then open http://localhost:8000 and drop a report on the rail.
"""

import json
import shutil
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse

from stix_generator.construction.builder import build_bundle
from stix_generator.extraction.extractor import DEFAULT_MODEL, extract
from stix_generator.extraction.schema import (
    RELATIONSHIP_VERBS,
    EntityType,
    ExtractionResult,
    ObservableType,
)
from stix_generator.extraction.grounding import verify_grounding
from stix_generator.evaluation.scoring import score_extraction
from stix_generator.ingestion.loader import load_report
from stix_generator.stix.relationships import ALLOWED, COMMON
from stix_generator.stix.vocab import PROPERTY_VOCABS
from stix_generator.validation.validator import validate_bundle

load_dotenv()

ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / "data" / "reports"
OUTPUT = ROOT / "data" / "output"
GOLDEN = ROOT / "data" / "golden"
UI_FILE = ROOT / "STIX Workbench (standalone).html"
SUPPORTED = {".pdf", ".txt", ".md"}

for d in (UPLOADS, OUTPUT, GOLDEN):
    d.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="STIX Workbench")

# run_id -> dict. In-memory is fine for a single-analyst local tool; the IR and bundle
# are also written to disk, so a restart loses status but never work.
RUNS: dict[str, dict] = {}
LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set(run_id: str, **fields) -> None:
    with LOCK:
        RUNS[run_id].update(fields)


def _summary(run: dict) -> dict:
    ir = run.get("extraction")
    return {
        "run_id": run["run_id"],
        "filename": run["filename"],
        "status": run["status"],
        "created_at": run["created_at"],
        "config": run["config"],
        "failure": run.get("failure"),
        "counts": {
            "entities": len(ir["entities"]) if ir else 0,
            "observables": len(ir.get("observables", [])) if ir else 0,
            "relationships": len(ir.get("relationships", [])) if ir else 0,
        },
        "unverified": run.get("unverified", 0),
        "schema_errors": len(run.get("validation", {}).get("errors", [])),
    }


def _pipeline(run_id: str) -> None:
    """Background worker: the same four stages as stix_generator.pipeline.run."""
    run = RUNS[run_id]
    report_path = Path(run["report_path"])
    try:
        _set(run_id, status="loading")
        text = load_report(report_path)
        _set(run_id, text=text)

        _set(run_id, status="extracting")
        result, warnings = extract(
            text,
            model=run["config"]["model"],
            enable_critic=run["config"]["critic"],
            enable_verifier=run["config"]["verifier"],
        )

        ir = result.model_dump()
        unverified = sum(
            1
            for group in ("entities", "observables", "relationships")
            for item in ir.get(group, [])
            if item.get("grounding_status") != "verified"
        )

        extraction_path = OUTPUT / f"{report_path.stem}.extraction.json"
        extraction_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

        _set(run_id, status="building", extraction=ir, warnings=warnings, unverified=unverified,
             extraction_path=str(extraction_path))

        bundle, build_warnings = build_bundle(result)
        bundle_json = bundle.serialize(pretty=True)

        _set(run_id, status="validating")
        validation = validate_bundle(bundle_json)

        bundle_path = OUTPUT / f"{report_path.stem}.json"
        bundle_path.write_text(bundle_json, encoding="utf-8")

        _set(run_id, status="ready", build_warnings=build_warnings, validation=validation,
             bundle_path=str(bundle_path))
    except Exception as exc:  # noqa: BLE001
        code = "truncated" if "truncated" in str(exc).lower() else "failed"
        _set(run_id, status="failed", failure={"code": code, "detail": str(exc)},
             traceback=traceback.format_exc())


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "model": DEFAULT_MODEL}


@app.post("/api/runs", status_code=201)
async def create_run(
    file: UploadFile = File(...),
    model: str = Form(DEFAULT_MODEL),
    critic: bool = Form(False),
    verifier: bool = Form(True),
) -> dict:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED:
        # Mirrors ingestion.loader.load_report, but before we spend an API call.
        raise HTTPException(
            status_code=415,
            detail={"error": "unsupported_format", "detail": f"Unsupported report format: {suffix}"},
        )

    run_id = uuid.uuid4().hex[:12]
    dest = UPLOADS / f"{Path(file.filename).stem}{suffix}"
    with dest.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)

    RUNS[run_id] = {
        "run_id": run_id,
        "filename": dest.name,
        "report_path": str(dest),
        "status": "queued",
        "created_at": _now(),
        "config": {"model": model, "critic": critic, "verifier": verifier},
    }
    threading.Thread(target=_pipeline, args=(run_id,), daemon=True).start()
    return {"run_id": run_id, "status": "queued"}


@app.get("/api/runs")
def list_runs() -> dict:
    return {"runs": [_summary(r) for r in sorted(RUNS.values(), key=lambda r: r["created_at"], reverse=True)]}


def _require(run_id: str) -> dict:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="unknown run_id")
    return run


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict:
    run = _require(run_id)
    return {
        **_summary(run),
        "extraction": run.get("extraction"),
        "warnings": run.get("warnings", []),
        "build_warnings": run.get("build_warnings", []),
        "validation": run.get("validation", {"is_valid": None, "errors": [], "warnings": []}),
        "bundle_path": run.get("bundle_path"),
        "extraction_path": run.get("extraction_path"),
    }


@app.get("/api/runs/{run_id}/text")
def get_text(run_id: str) -> dict:
    run = _require(run_id)
    if "text" not in run:
        raise HTTPException(status_code=409, detail={"status": run["status"]})
    return {"text": run["text"]}


@app.put("/api/runs/{run_id}/extraction")
def put_extraction(run_id: str, body: dict) -> dict:
    """Accept the corrected IR. ExtractionResult's own validator rejects duplicate
    local_ids and dangling endpoints, and grounding is recomputed server-side so an
    edited quote gets an honest status."""
    run = _require(run_id)
    try:
        result = ExtractionResult.model_validate(body.get("extraction", body))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=422, content={"error": "invalid_ir", "detail": str(exc)})

    result, warnings = verify_grounding(result, run.get("text", ""))
    ir = result.model_dump()
    _set(run_id, extraction=ir, warnings=warnings)
    if run.get("extraction_path"):
        Path(run["extraction_path"]).write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return {"extraction": ir, "warnings": warnings}


@app.post("/api/runs/{run_id}/rebuild")
def rebuild(run_id: str) -> dict:
    run = _require(run_id)
    result = ExtractionResult.model_validate(run["extraction"])
    bundle, build_warnings = build_bundle(result)
    bundle_json = bundle.serialize(pretty=True)
    validation = validate_bundle(bundle_json)
    if run.get("bundle_path"):
        Path(run["bundle_path"]).write_text(bundle_json, encoding="utf-8")
    _set(run_id, build_warnings=build_warnings, validation=validation)
    return {"validation": validation, "build_warnings": build_warnings, "bundle_path": run.get("bundle_path")}


@app.post("/api/runs/{run_id}/golden", status_code=201)
def save_golden(run_id: str, body: dict | None = None) -> dict:
    run = _require(run_id)
    name = (body or {}).get("name") or Path(run["filename"]).stem
    path = GOLDEN / f"{name}.json"
    path.write_text(json.dumps(run["extraction"], indent=2), encoding="utf-8")
    return {"golden_id": name, "path": str(path.relative_to(ROOT))}


@app.get("/api/runs/{run_id}/score")
def score(run_id: str, golden_id: str) -> dict:
    run = _require(run_id)
    gold_path = GOLDEN / f"{golden_id}.json"
    if not gold_path.exists():
        raise HTTPException(status_code=404, detail=f"no gold file at {gold_path}")
    gold = ExtractionResult.model_validate_json(gold_path.read_text(encoding="utf-8"))
    predicted = ExtractionResult.model_validate(run["extraction"])
    card = score_extraction(gold, predicted)

    def cat(s):
        return {"p": s.precision, "r": s.recall, "f1": s.f1, "tp": s.tp, "fp": s.fp, "fn": s.fn}

    return {
        "entities": {"overall": cat(card.entities_overall),
                     "by_type": {k: cat(v) for k, v in card.entities_by_type.items()}},
        "observables": {"overall": cat(card.observables_overall),
                        "by_type": {k: cat(v) for k, v in card.observables_by_type.items()}},
        "relationships": {"overall": cat(card.relationships_overall)},
        "verb_mismatches": getattr(card, "verb_mismatches", []),
        "type_confusions": card.type_confusions,
        "unmatched_gold": card.unmatched_gold,
        "unmatched_pred": card.unmatched_pred,
    }


@app.get("/api/golden")
def list_golden() -> dict:
    return {"golden": [{"golden_id": p.stem, "path": str(p.relative_to(ROOT))} for p in sorted(GOLDEN.glob("*.json"))]}


@app.get("/api/vocab")
def vocab() -> dict:
    """Served from the source of truth so the editor's dropdowns can't drift."""
    return {
        "entity_types": list(EntityType.__args__),
        "observable_types": list(ObservableType.__args__),
        "relationship_verbs": RELATIONSHIP_VERBS,
        "allowed_pairings": {f"{src}|{rel}": sorted(targets) for (src, rel), targets in ALLOWED.items()},
        "common": sorted(COMMON),
        "property_vocabs": {prop: values for prop, (_name, values) in PROPERTY_VOCABS.items()},
    }


@app.get("/")
def ui() -> FileResponse:
    if not UI_FILE.exists():
        raise HTTPException(status_code=404, detail=f"put the workbench HTML at {UI_FILE.name}")
    return FileResponse(UI_FILE)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
