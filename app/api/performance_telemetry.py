from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, RLock, Thread
from time import monotonic, perf_counter_ns
from typing import Any, Literal
from uuid import uuid4
import atexit
import json
import logging
import math
import os
import time


PerformanceKind = Literal["LLM Reasoning", "RAG Retrieval", "Embedding", "Retry/Repair"]
PerformanceStatus = Literal["Healthy", "Slow", "Failed", "Not Run"]
PerformanceOutcome = Literal["Success", "Failed"]

PERFORMANCE_DEFAULT_YEAR = 2026
PERFORMANCE_EXECUTION_POINT_TOTAL = 36
CONFIGURED_LLM_MODEL = "qwen3:14b"

ENV_ENABLED = "PERFORMANCE_TELEMETRY_ENABLED"
ENV_MAX_EVENTS = "PERFORMANCE_TELEMETRY_MAX_EVENTS"
ENV_QUEUE_SIZE = "PERFORMANCE_TELEMETRY_QUEUE_SIZE"
ENV_FLUSH_INTERVAL = "PERFORMANCE_TELEMETRY_FLUSH_INTERVAL_SECONDS"
ENV_BATCH_SIZE = "PERFORMANCE_TELEMETRY_BATCH_SIZE"
ENV_DEFAULT_YEAR = "PERFORMANCE_TELEMETRY_DEFAULT_YEAR"

DEFAULT_MAX_EVENTS = 5000
DEFAULT_QUEUE_SIZE = 10000
DEFAULT_FLUSH_INTERVAL_SECONDS = 0.5
DEFAULT_BATCH_SIZE = 100
SAFE_GENERATION_PARAMETER_KEYS = frozenset({
    "temperature",
    "top_p",
    "top_k",
    "num_predict",
    "num_ctx",
    "repeat_penalty",
    "seed",
    "stop",
})
SAFE_TOP_LEVEL_REQUEST_KEYS = frozenset({"stream", "format", "keep_alive"})
OLLAMA_DURATION_KEYS = frozenset({
    "total_duration",
    "load_duration",
    "prompt_eval_duration",
    "eval_duration",
})

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PerformanceOperation:
    id: str
    section: str
    operation: str
    kind: PerformanceKind
    source_file: str
    source_function: str
    slow_threshold_ms: float
    description: str


def _slow_threshold(kind: PerformanceKind) -> float:
    thresholds: dict[PerformanceKind, float] = {
        "LLM Reasoning": 60000.0,
        "Retry/Repair": 45000.0,
        "Embedding": 30000.0,
        "RAG Retrieval": 15000.0,
    }
    return thresholds[kind]


def _operation(
    operation_id: str,
    section: str,
    operation: str,
    kind: PerformanceKind,
    source_file: str,
    source_function: str,
    description: str,
) -> PerformanceOperation:
    return PerformanceOperation(
        id=operation_id,
        section=section,
        operation=operation,
        kind=kind,
        source_file=source_file,
        source_function=source_function,
        slow_threshold_ms=_slow_threshold(kind),
        description=description,
    )


EXECUTION_POINTS: tuple[PerformanceOperation, ...] = (
    _operation("rag.kb_rebuild", "RAG Infrastructure", "Knowledge-base embedding and rebuild", "Embedding", "app/rag/build_knowledge_base.py", "rebuild_if_needed", "Measures conditional knowledge-base rebuilds and embedding refreshes."),
    _operation("rag.shared_chroma_query", "RAG Infrastructure", "Shared Chroma semantic query", "RAG Retrieval", "app/rag/chroma_client.py", "ChromaClient.query", "Measures shared Chroma collection semantic queries."),
    _operation("rag.api_query", "RAG Infrastructure", "Generic RAG query endpoint", "RAG Retrieval", "app/api/routes_rag.py", "query", "Measures the generic RAG query endpoint execution."),
    _operation("assets.role_chroma", "Asset Inventory & CIA", "Chroma-based asset-role detection", "RAG Retrieval", "app/api/routes_assets_inventory.py", "_rag_detect_role_from_chroma", "Measures Chroma-based role detection during asset assignment."),
    _operation("threats.cve_format", "Threats & Vulnerabilities", "LLM CVE formatting", "LLM Reasoning", "app/api/routes_threat_vulnerabilities.py", "_ollama_format_cve", "Measures local LLM CVE summary formatting."),
    _operation("threats.mitigation_generate", "Threats & Vulnerabilities", "LLM mitigation generation", "LLM Reasoning", "app/api/routes_threat_vulnerabilities.py", "_generate_mitigations_with_existing_helpers", "Measures generated mitigation recommendations."),
    _operation("risk_eval.monitoring_fields", "Risk Evaluation & Treatment", "Generate monitoring justification and recommended action", "LLM Reasoning", "app/api/routes_risk_evaluation_treatment.py", "_ask_llama3_for_monitoring_fields", "Measures generation of monitoring justification and recommended action fields."),
    _operation("risk_eval.monitoring_justification", "Risk Evaluation & Treatment", "Generate monitoring justification", "LLM Reasoning", "app/api/routes_risk_evaluation_treatment.py", "_ask_llama3_for_monitoring_justification", "Measures standalone monitoring justification generation."),
    _operation("annex.rank_control_query_embed", "Annex A & SoA", "Control-query embedding for CVE ranking", "Embedding", "app/api/routes_annex_a_soa.py", "_rank_cves_for_control", "Measures the control profile query embedding used to rank CVEs."),
    _operation("annex.rank_cve_candidate_embed", "Annex A & SoA", "Candidate CVE embedding for control ranking", "Embedding", "app/api/routes_annex_a_soa.py", "_rank_cves_for_control", "Measures candidate CVE text embedding during control ranking."),
    _operation("annex.infer_controls_embed", "Annex A & SoA", "CVE embedding for inferred-control matching", "Embedding", "app/api/routes_annex_a_soa.py", "_infer_controls_from_cves", "Measures CVE description embedding before inferred-control matching."),
    _operation("annex.catalog_batch_embed", "Annex A & SoA", "Batch ISO-control catalog embeddings", "Embedding", "app/api/routes_annex_a_soa.py", "build_or_load_embeddings", "Measures ISO-control catalog batch embedding generation."),
    _operation("annex.retrieve_controls", "Annex A & SoA", "Relevant ISO-control retrieval", "RAG Retrieval", "app/api/routes_annex_a_soa.py", "retrieve_controls", "Measures relevant ISO-control retrieval from embedded records."),
    _operation("annex.control_info", "Annex A & SoA", "LLM control-information generation", "LLM Reasoning", "app/api/routes_annex_a_soa.py", "_generate_control_info_with_llama3", "Measures generation of control domain, concern, and justification."),
    _operation("annex.row_justification_primary", "Annex A & SoA", "Annex-row justification primary reasoning", "LLM Reasoning", "app/api/routes_annex_a_soa.py", "_generate_annex_row_justification_with_llm", "Measures primary Annex-row justification reasoning."),
    _operation("annex.row_justification_json_retry", "Annex A & SoA", "Annex-row JSON retry", "Retry/Repair", "app/api/routes_annex_a_soa.py", "_generate_annex_row_justification_with_llm", "Measures retry prompts after invalid Annex-row JSON."),
    _operation("annex.row_justification_repair", "Annex A & SoA", "Annex-row repair prompt", "Retry/Repair", "app/api/routes_annex_a_soa.py", "_generate_annex_row_justification_with_llm", "Measures repair prompts for malformed Annex-row responses."),
    _operation("annex.row_justification_simple", "Annex A & SoA", "Annex-row simplified fallback prompt", "Retry/Repair", "app/api/routes_annex_a_soa.py", "_generate_annex_row_justification_with_llm", "Measures simplified fallback prompts for Annex-row generation."),
    _operation("annex.select_controls", "Annex A & SoA", "LLM selection of controls from retrieved candidates", "LLM Reasoning", "app/api/routes_annex_a_soa.py", "ask_llama3_for_controls", "Measures LLM selection of controls from retrieved candidates."),
    _operation("action_plan.retrieve_controls", "Action Plan & Implementation", "Query embedding and relevant ISO-control retrieval", "RAG Retrieval", "app/api/routes_action_plan_implementation.py", "_retrieve_relevant_iso_controls", "Measures query embedding and ISO-control retrieval for action planning."),
    _operation("action_plan.treatment_primary", "Action Plan & Implementation", "Treatment-action primary reasoning", "LLM Reasoning", "app/api/routes_action_plan_implementation.py", "_generate_treatment_action_with_llama3", "Measures primary treatment-action reasoning."),
    _operation("action_plan.treatment_repair", "Action Plan & Implementation", "Treatment-action repair prompt", "Retry/Repair", "app/api/routes_action_plan_implementation.py", "_generate_treatment_action_with_llama3", "Measures treatment-action repair prompts."),
    _operation("action_plan.evidence_recommendations", "Action Plan & Implementation", "Evidence recommendations", "LLM Reasoning", "app/api/routes_action_plan_implementation.py", "_generate_evidence_recommendations_with_llama3", "Measures action-plan evidence recommendation generation."),
    _operation("action_plan.evidence_description", "Action Plan & Implementation", "Meaningful evidence-description generation", "LLM Reasoning", "app/api/routes_action_plan_implementation.py", "_generate_meaningful_evidence_desc_with_llama3", "Measures meaningful evidence-description generation."),
    _operation("action_plan.implementation_steps", "Action Plan & Implementation", "Technical implementation-step generation", "LLM Reasoning", "app/api/routes_action_plan_implementation.py", "_generate_real_implementation_steps_with_llm", "Measures technical implementation-step generation."),
    _operation("monitoring.user_behavior_action", "Monitoring & Improvement", "User-behavior monitoring-action reasoning", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_user_behavior_monitoring_action_with_llama3", "Measures user-behavior monitoring-action reasoning."),
    _operation("monitoring.real_steps", "Monitoring & Improvement", "Technical monitoring-step generation", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_real_monitoring_steps_with_llm", "Measures technical monitoring-step generation."),
    _operation("monitoring.evidence_description", "Monitoring & Improvement", "Individual evidence-description generation", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_evidence_desc_with_llama3", "Measures individual monitoring evidence-description generation."),
    _operation("monitoring.bulk_evidence_descriptions", "Monitoring & Improvement", "Bulk evidence-description generation", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_bulk_evidence_descs_with_llama3", "Measures bulk monitoring evidence-description generation."),
    _operation("monitoring.justification", "Monitoring & Improvement", "Monitoring-justification reasoning", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_monitoring_justification_with_llama3", "Measures monitoring-justification reasoning."),
    _operation("monitoring.query_embedding", "Monitoring & Improvement", "Query embedding for ISO-control retrieval", "Embedding", "app/api/routes_monitoring_improvement.py", "_retrieve_relevant_iso_controls", "Measures monitoring query embedding for ISO-control retrieval."),
    _operation("monitoring.record_embedding", "Monitoring & Improvement", "Knowledge-record embedding/cache population", "Embedding", "app/api/routes_monitoring_improvement.py", "_retrieve_relevant_iso_controls", "Measures knowledge-record embedding and cache population."),
    _operation("monitoring.retrieve_controls", "Monitoring & Improvement", "Relevant ISO-control retrieval and ranking", "RAG Retrieval", "app/api/routes_monitoring_improvement.py", "_retrieve_relevant_iso_controls", "Measures monitoring ISO-control retrieval and ranking."),
    _operation("monitoring.action_primary", "Monitoring & Improvement", "Monitoring-action primary reasoning", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_monitoring_action_with_llama3", "Measures primary monitoring-action reasoning."),
    _operation("monitoring.action_repair", "Monitoring & Improvement", "Monitoring-action repair prompt", "Retry/Repair", "app/api/routes_monitoring_improvement.py", "_generate_monitoring_action_with_llama3", "Measures monitoring-action repair prompts."),
    _operation("monitoring.evidence_recommendations", "Monitoring & Improvement", "Monitoring evidence recommendations", "LLM Reasoning", "app/api/routes_monitoring_improvement.py", "_generate_evidence_recommendations_with_llama3", "Measures monitoring evidence recommendation generation."),
)

OPERATION_CATALOG: dict[str, PerformanceOperation] = {operation.id: operation for operation in EXECUTION_POINTS}
EXECUTION_POINT_BY_ID = OPERATION_CATALOG


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", "disabled"}


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


def _float_env(name: str, default: float, minimum: float = 0.05) -> float:
    try:
        parsed = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not math.isfinite(parsed):
        return default
    return max(minimum, parsed)


PERFORMANCE_TELEMETRY_ENABLED = _bool_env(ENV_ENABLED, True)
PERFORMANCE_TELEMETRY_DEFAULT_YEAR = _int_env(ENV_DEFAULT_YEAR, PERFORMANCE_DEFAULT_YEAR, minimum=2000)
PERFORMANCE_TELEMETRY_MAX_EVENTS = _int_env(ENV_MAX_EVENTS, DEFAULT_MAX_EVENTS)
PERFORMANCE_TELEMETRY_QUEUE_SIZE = _int_env(ENV_QUEUE_SIZE, DEFAULT_QUEUE_SIZE)
PERFORMANCE_TELEMETRY_FLUSH_INTERVAL_SECONDS = _float_env(
    ENV_FLUSH_INTERVAL,
    DEFAULT_FLUSH_INTERVAL_SECONDS,
)
PERFORMANCE_TELEMETRY_BATCH_SIZE = _int_env(ENV_BATCH_SIZE, DEFAULT_BATCH_SIZE)


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()
DATA_WORK_DIR = BASE_DIR / "data" / "work"

_event_queue: Queue[dict[str, Any]] = Queue(maxsize=PERFORMANCE_TELEMETRY_QUEUE_SIZE)
_state_lock = RLock()
_file_lock = RLock()
_writer_started = False
_writer_thread: Thread | None = None
_shutdown_requested = Event()
_dropped_event_count = 0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime | None = None) -> str:
    dt = value or _utc_now()
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _work_dir(year: int) -> Path:
    return DATA_WORK_DIR / str(year)


def resolve_telemetry_year(year: int | None = None) -> int:
    if year is not None:
        try:
            return int(year)
        except (TypeError, ValueError):
            return PERFORMANCE_TELEMETRY_DEFAULT_YEAR
    return PERFORMANCE_TELEMETRY_DEFAULT_YEAR


def _telemetry_file(year: int) -> Path:
    return _work_dir(year) / "PerformanceTelemetry.json"


def _blank_telemetry_data(year: int) -> dict[str, Any]:
    return {
        "meta": {
            "name": "Performance_Telemetry",
            "version": 1,
            "year": int(year),
            "max_events": PERFORMANCE_TELEMETRY_MAX_EVENTS,
        },
        "events": [],
    }


def _backup_malformed_file(path: Path) -> None:
    if not path.exists():
        return
    backup_path = path.with_name(f"{path.name}.malformed.{uuid4().hex}.bak")
    try:
        path.replace(backup_path)
    except Exception as exc:
        logger.warning("[Performance telemetry] Failed to back up malformed file: %s", exc)


def _read_telemetry_data(year: int) -> dict[str, Any]:
    path = _telemetry_file(year)
    if not path.exists():
        return _blank_telemetry_data(year)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[Performance telemetry] Malformed telemetry file backed up: %s", exc)
        _backup_malformed_file(path)
        return _blank_telemetry_data(year)

    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        logger.warning("[Performance telemetry] Invalid telemetry structure backed up.")
        _backup_malformed_file(path)
        return _blank_telemetry_data(year)

    meta = data.get("meta")
    if not isinstance(meta, dict):
        data["meta"] = _blank_telemetry_data(year)["meta"]
    data["meta"]["name"] = "Performance_Telemetry"
    data["meta"]["version"] = 1
    data["meta"]["year"] = int(year)
    data["meta"]["max_events"] = PERFORMANCE_TELEMETRY_MAX_EVENTS
    return data


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
    try:
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_path.replace(path)
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


def _duration_ms_from_ns(start_ns: int, end_ns: int) -> float:
    duration_ms = (max(0, end_ns - start_ns)) / 1_000_000
    if not math.isfinite(duration_ms):
        return 0.0
    return round(max(0.0, duration_ms), 3)


def _clean_duration(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0:
        return None
    return round(parsed, 3)


def _clean_tokens(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _camel_case(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _model_identity(model: str | None, provider: str | None = "Ollama") -> dict[str, Any]:
    normalized = str(model or "").strip()
    family_source = normalized.split(":", 1)[0].strip()
    model_tag = normalized.split(":", 1)[1].strip() if ":" in normalized else None
    family_lower = family_source.lower()

    if family_lower == "qwen3":
        model_family = "Qwen3"
    elif family_lower.startswith("qwen") and family_lower[4:].replace(".", "", 1).isdigit():
        model_family = f"Qwen{family_lower[4:]}"
    elif family_lower == "nomic-embed-text":
        model_family = "Nomic Embed Text"
    else:
        model_family = family_source.replace("-", " ").title() if family_source else None

    parameter_size = None
    if model_tag:
        compact_tag = model_tag.lower().replace(" ", "")
        if compact_tag.endswith("b") and compact_tag[:-1].replace(".", "", 1).isdigit():
            parameter_size = f"{compact_tag[:-1]}B".upper()

    return {
        "provider": provider if normalized else None,
        "model": normalized or None,
        "model_family": model_family,
        "model_tag": model_tag,
        "parameter_size": parameter_size,
    }


def safe_llm_configuration(*, model: str, payload: dict[str, Any]) -> dict[str, Any]:
    safe_config = _model_identity(model)
    safe_parameters: dict[str, Any] = {}

    options = payload.get("options") if isinstance(payload, dict) else None
    if isinstance(options, dict):
        for key in SAFE_GENERATION_PARAMETER_KEYS:
            if key in options:
                safe_parameters[key] = options.get(key)

    if isinstance(payload, dict):
        for key in SAFE_TOP_LEVEL_REQUEST_KEYS:
            if key in payload:
                safe_parameters[key] = payload.get(key)

    safe_config["generation_parameters"] = safe_parameters
    return safe_config


def safe_embedding_configuration(*, model: str, provider: str = "Ollama") -> dict[str, Any]:
    safe_config = _model_identity(model, provider=provider)
    safe_config["generation_parameters"] = {}
    return safe_config


def _clean_generation_parameters(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = SAFE_GENERATION_PARAMETER_KEYS | SAFE_TOP_LEVEL_REQUEST_KEYS
    return {key: value.get(key) for key in allowed if key in value}


def _clean_model_configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    cleaned = _model_identity(str(value.get("model") or ""))
    for key in ("provider", "model_family", "model_tag", "parameter_size"):
        if key in value and (isinstance(value.get(key), str) or value.get(key) is None):
            cleaned[key] = value.get(key)
    cleaned["generation_parameters"] = _clean_generation_parameters(value.get("generation_parameters"))
    return cleaned


def _model_configuration_from_event(event: dict[str, Any]) -> dict[str, Any]:
    raw_configuration = event.get("model_configuration")
    if isinstance(raw_configuration, dict):
        return _clean_model_configuration(raw_configuration)
    return _clean_model_configuration({
        "provider": event.get("provider"),
        "model": event.get("model"),
        "model_family": event.get("model_family"),
        "model_tag": event.get("model_tag"),
        "parameter_size": event.get("parameter_size"),
        "generation_parameters": event.get("generation_parameters"),
    })


def _ns_to_ms(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0:
        return None
    return round(parsed / 1_000_000, 3)


def _ollama_metrics_from_response(response_data: Any) -> dict[str, Any]:
    if not isinstance(response_data, dict):
        return {}
    metrics: dict[str, Any] = {}
    if isinstance(response_data.get("model"), str) and response_data.get("model"):
        metrics["model"] = response_data["model"]
    if isinstance(response_data.get("done_reason"), str):
        metrics["done_reason"] = response_data["done_reason"]

    prompt_tokens = _clean_tokens(response_data.get("prompt_eval_count"))
    completion_tokens = _clean_tokens(response_data.get("eval_count"))
    if prompt_tokens is not None:
        metrics["prompt_tokens"] = prompt_tokens
    if completion_tokens is not None:
        metrics["completion_tokens"] = completion_tokens
    if prompt_tokens is not None or completion_tokens is not None:
        metrics["total_tokens"] = (prompt_tokens or 0) + (completion_tokens or 0)

    for key in OLLAMA_DURATION_KEYS:
        converted = _ns_to_ms(response_data.get(key))
        if converted is not None:
            metrics[f"ollama_{key}_ms"] = converted
    return metrics


def _validate_event(event: Any) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None

    operation_id = event.get("operation_id")
    if not isinstance(operation_id, str) or operation_id not in OPERATION_CATALOG:
        return None

    outcome = event.get("outcome")
    if outcome not in {"Success", "Failed"}:
        return None

    duration_ms = _clean_duration(event.get("duration_ms"))
    if duration_ms is None:
        return None

    started_at = event.get("started_at")
    if not isinstance(started_at, str) or not started_at:
        return None

    error_type = event.get("error_type")
    if outcome == "Success":
        error_type = None
    elif not isinstance(error_type, str) or not error_type:
        return None

    model_configuration = _model_configuration_from_event(event)
    prompt_tokens = _clean_tokens(event.get("prompt_tokens"))
    completion_tokens = _clean_tokens(event.get("completion_tokens"))
    total_tokens = _clean_tokens(event.get("total_tokens"))
    if total_tokens is None and (prompt_tokens is not None or completion_tokens is not None):
        total_tokens = (prompt_tokens or 0) + (completion_tokens or 0)
    ollama_metrics = {
        "ollama_total_duration_ms": _clean_duration(event.get("ollama_total_duration_ms")),
        "ollama_load_duration_ms": _clean_duration(event.get("ollama_load_duration_ms")),
        "ollama_prompt_eval_duration_ms": _clean_duration(event.get("ollama_prompt_eval_duration_ms")),
        "ollama_eval_duration_ms": _clean_duration(event.get("ollama_eval_duration_ms")),
    }
    done_reason = event.get("done_reason")

    cleaned_event = {
        "event_id": str(event.get("event_id") or uuid4()),
        "operation_id": operation_id,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "outcome": outcome,
        "error_type": error_type,
        "provider": model_configuration.get("provider"),
        "model": model_configuration.get("model"),
        "model_family": model_configuration.get("model_family"),
        "model_tag": model_configuration.get("model_tag"),
        "parameter_size": model_configuration.get("parameter_size"),
        "generation_parameters": model_configuration.get("generation_parameters", {}),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }
    cleaned_event.update(ollama_metrics)
    cleaned_event["done_reason"] = done_reason if isinstance(done_reason, str) else None
    return cleaned_event


def _write_event_batch(events: list[dict[str, Any]]) -> None:
    if not events:
        return
    valid_events = []
    for item in events:
        event = _validate_event(item)
        if event is None:
            continue
        if isinstance(item, dict):
            event["_year"] = int(item.get("_year") or PERFORMANCE_DEFAULT_YEAR)
        valid_events.append(event)
    if not valid_events:
        return

    year_to_events: dict[int, list[dict[str, Any]]] = {}
    for event in valid_events:
        year_to_events.setdefault(int(event.pop("_year", PERFORMANCE_DEFAULT_YEAR)), []).append(event)

    with _file_lock:
        for year, year_events in year_to_events.items():
            data = _read_telemetry_data(year)
            existing_events = [
                event
                for event in (_validate_event(item) for item in data.get("events", []))
                if event is not None
            ]
            existing_events.extend(year_events)
            data = _blank_telemetry_data(year)
            data["events"] = existing_events[-PERFORMANCE_TELEMETRY_MAX_EVENTS:]
            _atomic_write_json(_telemetry_file(year), data)


def _writer_loop() -> None:
    while not _shutdown_requested.is_set() or not _event_queue.empty():
        batch: list[dict[str, Any]] = []
        try:
            first = _event_queue.get(timeout=PERFORMANCE_TELEMETRY_FLUSH_INTERVAL_SECONDS)
            batch.append(first)
        except Empty:
            continue

        while len(batch) < PERFORMANCE_TELEMETRY_BATCH_SIZE:
            try:
                batch.append(_event_queue.get_nowait())
            except Empty:
                break

        try:
            _write_event_batch(batch)
        except Exception as exc:
            logger.warning("[Performance telemetry] Failed to write telemetry batch: %s", exc)
        finally:
            for _ in batch:
                _event_queue.task_done()


def start_performance_writer() -> None:
    global _writer_started, _writer_thread
    if not PERFORMANCE_TELEMETRY_ENABLED:
        return
    with _state_lock:
        if _writer_started:
            return
        _shutdown_requested.clear()
        _writer_thread = Thread(
            target=_writer_loop,
            name="performance-telemetry-writer",
            daemon=True,
        )
        _writer_thread.start()
        _writer_started = True


def record_event_safe(event: dict[str, Any]) -> None:
    global _dropped_event_count
    if not PERFORMANCE_TELEMETRY_ENABLED:
        return

    try:
        if _validate_event(event) is None:
            return
        start_performance_writer()
        _event_queue.put_nowait(event)
    except Full:
        with _state_lock:
            _dropped_event_count += 1
    except Exception as exc:
        logger.warning("[Performance telemetry] Failed to enqueue telemetry event: %s", exc)


class PerformanceSpan:
    def __init__(
        self,
        year: int | None,
        operation_id: str,
        model_configuration: dict[str, Any] | None = None,
        llm_configuration: dict[str, Any] | None = None,
    ):
        self.year = resolve_telemetry_year(year)
        self.operation_id = operation_id
        self.started_at = _utc_iso()
        self.start_ns = 0
        self.total_tokens: int | None = None
        self.prompt_tokens: int | None = None
        self.completion_tokens: int | None = None
        self.ollama_total_duration_ms: float | None = None
        self.ollama_load_duration_ms: float | None = None
        self.ollama_prompt_eval_duration_ms: float | None = None
        self.ollama_eval_duration_ms: float | None = None
        self.done_reason: str | None = None
        self.model_configuration = _clean_model_configuration(
            model_configuration if model_configuration is not None else llm_configuration
        )

    def __enter__(self) -> PerformanceSpan:
        self.start_ns = perf_counter_ns()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: Any) -> bool:
        end_ns = perf_counter_ns()
        outcome: PerformanceOutcome = "Failed" if exc_type is not None else "Success"
        error_type = exc_type.__name__ if exc_type is not None else None
        event = {
            "event_id": str(uuid4()),
            "operation_id": self.operation_id,
            "started_at": self.started_at,
            "duration_ms": _duration_ms_from_ns(self.start_ns, end_ns),
            "outcome": outcome,
            "error_type": error_type,
            "model_configuration": self.model_configuration,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "ollama_total_duration_ms": self.ollama_total_duration_ms,
            "ollama_load_duration_ms": self.ollama_load_duration_ms,
            "ollama_prompt_eval_duration_ms": self.ollama_prompt_eval_duration_ms,
            "ollama_eval_duration_ms": self.ollama_eval_duration_ms,
            "done_reason": self.done_reason,
            "_year": self.year,
        }
        try:
            record_event_safe(event)
        except Exception as telemetry_exc:
            logger.warning("[Performance telemetry] Span recording failed: %s", telemetry_exc)
        return False

    def set_total_tokens(self, total_tokens: int | None) -> None:
        cleaned = _clean_tokens(total_tokens)
        if cleaned is not None:
            self.total_tokens = cleaned

    def set_ollama_metrics(self, response_data: dict[str, Any] | None) -> None:
        metrics = _ollama_metrics_from_response(response_data)
        response_model = metrics.get("model")
        if isinstance(response_model, str) and response_model:
            self.model_configuration = {
                **self.model_configuration,
                **_model_identity(response_model),
                "generation_parameters": self.model_configuration.get("generation_parameters", {}),
            }
        prompt_tokens = _clean_tokens(metrics.get("prompt_tokens"))
        completion_tokens = _clean_tokens(metrics.get("completion_tokens"))
        if prompt_tokens is not None:
            self.prompt_tokens = prompt_tokens
        if completion_tokens is not None:
            self.completion_tokens = completion_tokens
        total_tokens = _clean_tokens(metrics.get("total_tokens"))
        if total_tokens is not None:
            self.total_tokens = total_tokens
        for attr in (
            "ollama_total_duration_ms",
            "ollama_load_duration_ms",
            "ollama_prompt_eval_duration_ms",
            "ollama_eval_duration_ms",
        ):
            cleaned_duration = _clean_duration(metrics.get(attr))
            if cleaned_duration is not None:
                setattr(self, attr, cleaned_duration)
        done_reason = metrics.get("done_reason")
        if isinstance(done_reason, str):
            self.done_reason = done_reason


def performance_span(
    year: int | None,
    operation_id: str,
    model_configuration: dict[str, Any] | None = None,
    llm_configuration: dict[str, Any] | None = None,
) -> PerformanceSpan:
    return PerformanceSpan(
        year=year,
        operation_id=operation_id,
        model_configuration=model_configuration,
        llm_configuration=llm_configuration,
    )


def flush_performance_telemetry(timeout_seconds: float | None = None) -> None:
    if not PERFORMANCE_TELEMETRY_ENABLED:
        return
    start_performance_writer()
    if timeout_seconds is None:
        _event_queue.join()
        return

    deadline = monotonic() + max(0.0, timeout_seconds)
    while _event_queue.unfinished_tasks and monotonic() < deadline:
        time.sleep(0.01)


def shutdown_performance_writer() -> None:
    if not PERFORMANCE_TELEMETRY_ENABLED:
        return
    _shutdown_requested.set()
    flush_performance_telemetry(timeout_seconds=2.0)


def reset_performance_telemetry(year: int) -> Path:
    resolved_year = resolve_telemetry_year(year)
    flush_performance_telemetry(timeout_seconds=1.0)
    with _file_lock:
        path = _telemetry_file(resolved_year)
        _atomic_write_json(path, _blank_telemetry_data(resolved_year))
    return path


def _events_for_dashboard(year: int) -> list[dict[str, Any]]:
    flush_performance_telemetry(timeout_seconds=1.0)
    with _file_lock:
        data = _read_telemetry_data(year)
    return [
        event
        for event in (_validate_event(item) for item in data.get("events", []))
        if event is not None
    ]


def _p95(values: list[float]) -> float | None:
    # Deterministic nearest-rank P95: ceil(0.95 * n) - 1 on ascending values.
    if not values:
        return None
    sorted_values = sorted(values)
    index = math.ceil(0.95 * len(sorted_values)) - 1
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def _status_for(operation: PerformanceOperation, events: list[dict[str, Any]]) -> PerformanceStatus:
    if not events:
        return "Not Run"
    if events[-1]["outcome"] == "Failed":
        return "Failed"
    p95_value = _p95([event["duration_ms"] for event in events])
    if p95_value is not None and p95_value > operation.slow_threshold_ms:
        return "Slow"
    return "Healthy"


def _dashboard_generation_parameters(value: Any) -> dict[str, Any]:
    return {_camel_case(key): item for key, item in _clean_generation_parameters(value).items()}


def _configuration_sort_key(event: dict[str, Any]) -> str:
    identity = {
        "provider": event.get("provider"),
        "model": event.get("model"),
        "model_family": event.get("model_family"),
        "model_tag": event.get("model_tag"),
        "parameter_size": event.get("parameter_size"),
        "generation_parameters": _clean_generation_parameters(event.get("generation_parameters")),
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)


def _observed_configurations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    configurations: dict[str, dict[str, Any]] = {}
    for event in events:
        if not event.get("model") and not event.get("provider") and not event.get("generation_parameters"):
            continue
        key = _configuration_sort_key(event)
        if key not in configurations:
            configurations[key] = {
                "provider": event.get("provider"),
                "model": event.get("model"),
                "modelFamily": event.get("model_family"),
                "modelTag": event.get("model_tag"),
                "parameterSize": event.get("parameter_size"),
                "generationParameters": _dashboard_generation_parameters(event.get("generation_parameters")),
                "callCount": 0,
            }
        configurations[key]["callCount"] += 1
    return sorted(
        configurations.values(),
        key=lambda item: (-int(item["callCount"]), str(item.get("model") or "")),
    )


def _record_to_dashboard(operation: PerformanceOperation, events: list[dict[str, Any]]) -> dict[str, Any]:
    durations = [event["duration_ms"] for event in events]
    call_count = len(events)
    success_count = sum(1 for event in events if event["outcome"] == "Success")
    failure_count = sum(1 for event in events if event["outcome"] == "Failed")
    total_duration = round(sum(durations), 3)
    average_duration = round(total_duration / call_count, 3) if call_count else None
    p95_duration = _p95(durations)
    last_event = events[-1] if events else None
    last_generation_parameters = (
        _dashboard_generation_parameters(last_event.get("generation_parameters"))
        if last_event
        else {}
    )

    return {
        "id": operation.id,
        "section": operation.section,
        "operation": operation.operation,
        "kind": operation.kind,
        "sourceFile": operation.source_file,
        "sourceFunction": operation.source_function,
        "callCount": call_count,
        "successCount": success_count,
        "failureCount": failure_count,
        "lastDurationMs": last_event["duration_ms"] if last_event else None,
        "averageDurationMs": average_duration,
        "p95DurationMs": round(p95_duration, 3) if p95_duration is not None else None,
        "totalDurationMs": total_duration,
        "status": _status_for(operation, events),
        "lastRunAt": last_event["started_at"] if last_event else None,
        "description": operation.description,
        "provider": last_event.get("provider") if last_event else None,
        "model": last_event.get("model") if last_event else None,
        "modelFamily": last_event.get("model_family") if last_event else None,
        "modelTag": last_event.get("model_tag") if last_event else None,
        "parameterSize": last_event.get("parameter_size") if last_event else None,
        "generationParameters": last_generation_parameters,
        "promptTokens": last_event.get("prompt_tokens") if last_event else None,
        "completionTokens": last_event.get("completion_tokens") if last_event else None,
        "totalTokens": last_event.get("total_tokens") if last_event else None,
        "ollamaTotalDurationMs": last_event.get("ollama_total_duration_ms") if last_event else None,
        "ollamaLoadDurationMs": last_event.get("ollama_load_duration_ms") if last_event else None,
        "ollamaPromptEvalDurationMs": last_event.get("ollama_prompt_eval_duration_ms") if last_event else None,
        "ollamaEvalDurationMs": last_event.get("ollama_eval_duration_ms") if last_event else None,
        "doneReason": last_event.get("done_reason") if last_event else None,
        "observedConfigurations": _observed_configurations(events),
    }


def _average_for_kind(records: list[dict[str, Any]], kind: PerformanceKind) -> float | None:
    values = [
        record["averageDurationMs"]
        for record in records
        if record["kind"] == kind and record["averageDurationMs"] is not None
    ]
    if not values:
        return None
    return round(sum(values) / len(values), 3)


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    p95_values = [
        record["p95DurationMs"]
        for record in records
        if record["p95DurationMs"] is not None
    ]
    records_with_average = [
        record
        for record in records
        if record["averageDurationMs"] is not None
    ]
    slowest = max(
        records_with_average,
        key=lambda record: record["averageDurationMs"],
        default=None,
    )
    return {
        "totalExecutionPoints": PERFORMANCE_EXECUTION_POINT_TOTAL,
        "totalObservedDurationMs": round(sum(record["totalDurationMs"] for record in records), 3),
        "averageLlmDurationMs": _average_for_kind(records, "LLM Reasoning"),
        "averageRagDurationMs": _average_for_kind(records, "RAG Retrieval"),
        "p95DurationMs": round(max(p95_values), 3) if p95_values else None,
        "slowestOperationId": slowest["id"] if slowest else None,
    }


def _section_summaries(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = []
    sections = list(dict.fromkeys(operation.section for operation in EXECUTION_POINTS))
    for section in sections:
        section_records = [record for record in records if record["section"] == section]
        summaries.append({
            "section": section,
            "executionPointCount": len(section_records),
            "callCount": sum(record["callCount"] for record in section_records),
            "successCount": sum(record["successCount"] for record in section_records),
            "failureCount": sum(record["failureCount"] for record in section_records),
            "totalDurationMs": round(sum(record["totalDurationMs"] for record in section_records), 3),
        })
    return summaries


def _model_summaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    catalog_order = {operation.id: index for index, operation in enumerate(EXECUTION_POINTS)}
    configured_identity = _model_identity(CONFIGURED_LLM_MODEL)

    for event in events:
        if not event.get("model"):
            continue
        identity = {
            "provider": event.get("provider"),
            "model": event.get("model"),
            "model_family": event.get("model_family"),
            "model_tag": event.get("model_tag"),
            "parameter_size": event.get("parameter_size"),
        }
        key = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
        if key not in grouped:
            grouped[key] = {
                "provider": identity["provider"],
                "model": identity["model"],
                "modelFamily": identity["model_family"],
                "modelTag": identity["model_tag"],
                "parameterSize": identity["parameter_size"],
                "configured": False,
                "durations": [],
                "totalTokens": 0,
                "operationIds": set(),
            }
        grouped[key]["durations"].append(event["duration_ms"])
        grouped[key]["totalTokens"] += event.get("total_tokens") or 0
        grouped[key]["operationIds"].add(event["operation_id"])

    summaries = []
    for item in grouped.values():
        durations = item.pop("durations")
        operation_ids = sorted(
            item.pop("operationIds"),
            key=lambda operation_id: catalog_order.get(operation_id, len(catalog_order)),
        )
        call_count = len(durations)
        summaries.append({
            **item,
            "callCount": call_count,
            "averageDurationMs": round(sum(durations) / call_count, 3) if call_count else None,
            "p95DurationMs": round(_p95(durations), 3) if durations else None,
            "operationIds": operation_ids,
        })

    summaries = sorted(
        summaries,
        key=lambda item: (-int(item["callCount"]), str(item.get("model") or "")),
    )
    configured_index = next(
        (
            index
            for index, item in enumerate(summaries)
            if item.get("model") == configured_identity["model"]
        ),
        None,
    )
    if configured_index is None:
        summaries.insert(0, {
            "provider": configured_identity["provider"],
            "model": configured_identity["model"],
            "modelFamily": configured_identity["model_family"],
            "modelTag": configured_identity["model_tag"],
            "parameterSize": configured_identity["parameter_size"],
            "configured": True,
            "callCount": 0,
            "averageDurationMs": None,
            "p95DurationMs": None,
            "totalTokens": 0,
            "operationIds": [],
        })
    else:
        configured_summary = summaries.pop(configured_index)
        configured_summary["configured"] = True
        summaries.insert(0, configured_summary)
    return summaries


def get_performance_dashboard(year: int) -> dict[str, Any]:
    events = _events_for_dashboard(year)
    by_operation: dict[str, list[dict[str, Any]]] = {operation.id: [] for operation in EXECUTION_POINTS}
    for event in events:
        by_operation.setdefault(event["operation_id"], []).append(event)

    dashboard_records = [
        _record_to_dashboard(operation, by_operation.get(operation.id, []))
        for operation in EXECUTION_POINTS
    ]
    return {
        "success": True,
        "year": int(year),
        "generatedAt": _utc_iso(),
        "sourceFile": f"data/work/{year}/PerformanceTelemetry.json",
        "telemetryEnabled": PERFORMANCE_TELEMETRY_ENABLED,
        "droppedEventCount": _dropped_event_count,
        "catalogCoverage": {
            "represented": len(dashboard_records),
            "total": PERFORMANCE_EXECUTION_POINT_TOTAL,
        },
        "summary": _summary(dashboard_records),
        "modelSummaries": _model_summaries(events),
        "records": dashboard_records,
        "sectionSummaries": _section_summaries(dashboard_records),
    }


def catalog_as_dicts() -> list[dict[str, Any]]:
    return [asdict(operation) for operation in EXECUTION_POINTS]


atexit.register(shutdown_performance_writer)
