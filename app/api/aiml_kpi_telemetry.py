from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import json
import math


AIML_KPI_BUCKETS = {
    "role_model_training_runs",
    "role_prediction_events",
    "cia_prediction_events",
    "behavior_model_training_runs",
    "behavior_prediction_events",
    "manual_correction_events",
    "rag_events",
    "llm_events",
}

def _blank_rag_llm_counters() -> dict:
    return {
        "rag_query_count": 0,
        "rag_success_count": 0,
        "rag_failure_count": 0,
        "llm_reasoning_calls": 0,
        "llm_total_tokens": 0,
    }


def _blank_human_trust_counters() -> dict:
    return {
        "manual_role_corrections": 0,
        "manual_risk_corrections": 0,
        "evaluated_role_predictions": 0,
        "overridden_role_predictions": 0,
        "predictions_with_confidence": 0,
        "low_confidence_predictions": 0,
    }


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _aiml_kpi_inputs_file(year: int) -> Path:
    return _work_dir(year) / "AIMLKPIInputs.json"


def _blank_aiml_kpi_inputs(year: int) -> dict:
    return {
        "meta": {
            "year": year,
            "name": "AI_ML_KPI_Inputs",
            "version": 1,
        },
        "role_model_training_runs": [],
        "role_prediction_events": [],
        "cia_prediction_events": [],
        "behavior_model_training_runs": [],
        "behavior_prediction_events": [],
        "manual_correction_events": [],
        "rag_events": [],
        "llm_events": [],
        "rag_llm_counters": _blank_rag_llm_counters(),
        "human_trust_counters": _blank_human_trust_counters(),
    }


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        try:
            return value.relative_to(BASE_DIR).as_posix()
        except Exception:
            return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _int_counter(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _float_value(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _clean_counter_block(counters: dict, blank: dict) -> bool:
    changed = False
    for key, default_value in blank.items():
        if key not in counters:
            counters[key] = default_value
            changed = True
            continue

        clean_value = _int_counter(counters.get(key))
        if counters.get(key) != clean_value:
            counters[key] = clean_value
            changed = True
    return changed


def _ensure_rag_llm_counters(data: dict) -> bool:
    counters = data.get("rag_llm_counters")
    if not isinstance(counters, dict):
        data["rag_llm_counters"] = _blank_rag_llm_counters()
        return True

    return _clean_counter_block(counters, _blank_rag_llm_counters())


def _text(value: Any) -> str:
    return str(value or "").strip()


def role_prediction_quality_counts(events: list[dict]) -> dict:
    counts = {
        "evaluated_role_predictions": 0,
        "overridden_role_predictions": 0,
        "predictions_with_confidence": 0,
        "low_confidence_predictions": 0,
    }

    for event in events:
        if not isinstance(event, dict):
            continue

        is_override = event.get("is_override")
        if isinstance(is_override, bool):
            counts["evaluated_role_predictions"] += 1
            if is_override:
                counts["overridden_role_predictions"] += 1
        else:
            predicted_role = _text(event.get("predicted_role")).lower()
            final_role = _text(event.get("final_role")).lower()
            if predicted_role and final_role:
                counts["evaluated_role_predictions"] += 1
                if predicted_role != final_role:
                    counts["overridden_role_predictions"] += 1

        confidence = _float_value(event.get("confidence"))
        if confidence is not None:
            counts["predictions_with_confidence"] += 1
            if confidence < 0.60:
                counts["low_confidence_predictions"] += 1

    return counts


def _seed_human_trust_counters(data: dict) -> dict:
    counters = _blank_human_trust_counters()

    manual_events = data.get("manual_correction_events", [])
    if isinstance(manual_events, list):
        for event in manual_events:
            if not isinstance(event, dict):
                continue
            correction_type = _text(event.get("correction_type")).lower()
            if correction_type == "role":
                counters["manual_role_corrections"] += 1
            elif correction_type == "risk":
                counters["manual_risk_corrections"] += 1

    role_events = data.get("role_prediction_events", [])
    if isinstance(role_events, list):
        counts = role_prediction_quality_counts(role_events)
        counters.update(counts)

    return counters


def _ensure_human_trust_counters(data: dict) -> bool:
    counters = data.get("human_trust_counters")
    if not isinstance(counters, dict):
        data["human_trust_counters"] = _seed_human_trust_counters(data)
        return True

    return _clean_counter_block(counters, _blank_human_trust_counters())


def ensure_aiml_kpi_inputs(year: int) -> dict:
    path = _aiml_kpi_inputs_file(year)
    blank = _blank_aiml_kpi_inputs(year)

    if not path.exists():
        _atomic_write_json(path, blank)
        return blank

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = blank

    if not isinstance(data, dict):
        data = blank

    changed = False
    if not isinstance(data.get("meta"), dict):
        data["meta"] = blank["meta"]
        changed = True

    for bucket in AIML_KPI_BUCKETS:
        if not isinstance(data.get(bucket), list):
            data[bucket] = []
            changed = True

    if _ensure_rag_llm_counters(data):
        changed = True

    if _ensure_human_trust_counters(data):
        changed = True

    if changed:
        _atomic_write_json(path, data)

    return data


def append_aiml_kpi_events(year: int, bucket: str, events: list[dict]) -> int:
    if bucket not in AIML_KPI_BUCKETS:
        raise ValueError(f"Unknown AIML KPI telemetry bucket: {bucket}")

    clean_events = []
    for event in events:
        if not isinstance(event, dict):
            continue
        clean_event = _json_safe(event)
        if not isinstance(clean_event, dict):
            continue
        clean_event.setdefault("created_at", _now_iso())
        clean_events.append(clean_event)

    if not clean_events:
        return 0

    data = ensure_aiml_kpi_inputs(year)
    data[bucket].extend(clean_events)
    _atomic_write_json(_aiml_kpi_inputs_file(year), data)
    return len(clean_events)


def append_aiml_kpi_event(year: int, bucket: str, event: dict) -> int:
    return append_aiml_kpi_events(year, bucket, [event])


def increment_rag_counter(year: int, success: bool) -> None:
    data = ensure_aiml_kpi_inputs(year)
    counters = data["rag_llm_counters"]

    counters["rag_query_count"] = _int_counter(counters.get("rag_query_count")) + 1
    if success:
        counters["rag_success_count"] = _int_counter(counters.get("rag_success_count")) + 1
    else:
        counters["rag_failure_count"] = _int_counter(counters.get("rag_failure_count")) + 1

    _atomic_write_json(_aiml_kpi_inputs_file(year), data)


def increment_llm_counter(year: int, total_tokens: int | None = None) -> None:
    data = ensure_aiml_kpi_inputs(year)
    counters = data["rag_llm_counters"]

    counters["llm_reasoning_calls"] = _int_counter(counters.get("llm_reasoning_calls")) + 1
    tokens = _int_counter(total_tokens)
    if tokens:
        counters["llm_total_tokens"] = _int_counter(counters.get("llm_total_tokens")) + tokens

    _atomic_write_json(_aiml_kpi_inputs_file(year), data)


def safe_increment_rag_counter(year: int, success: bool) -> None:
    try:
        increment_rag_counter(year, success)
    except Exception as exc:
        print(f"[AIML KPI telemetry] Failed to increment RAG counter: {exc}")


def safe_increment_llm_counter(year: int, total_tokens: int | None = None) -> None:
    try:
        increment_llm_counter(year, total_tokens)
    except Exception as exc:
        print(f"[AIML KPI telemetry] Failed to increment LLM counter: {exc}")


def increment_manual_correction_counter(year: int, correction_type: str) -> None:
    data = ensure_aiml_kpi_inputs(year)
    counters = data["human_trust_counters"]
    correction_key = _text(correction_type).lower()

    if correction_key == "role":
        counters["manual_role_corrections"] = _int_counter(counters.get("manual_role_corrections")) + 1
    elif correction_key == "risk":
        counters["manual_risk_corrections"] = _int_counter(counters.get("manual_risk_corrections")) + 1
    else:
        raise ValueError(f"Unknown manual correction type: {correction_type}")

    _atomic_write_json(_aiml_kpi_inputs_file(year), data)


def increment_role_prediction_quality_counters(year: int, events: list[dict]) -> None:
    counts = role_prediction_quality_counts(events)
    if not any(counts.values()):
        return

    data = ensure_aiml_kpi_inputs(year)
    counters = data["human_trust_counters"]
    for key, value in counts.items():
        counters[key] = _int_counter(counters.get(key)) + _int_counter(value)

    _atomic_write_json(_aiml_kpi_inputs_file(year), data)


def safe_increment_manual_correction_counter(year: int, correction_type: str) -> None:
    try:
        increment_manual_correction_counter(year, correction_type)
    except Exception as exc:
        print(f"[AIML KPI telemetry] Failed to increment manual correction counter: {exc}")


def safe_increment_role_prediction_quality_counters(year: int, events: list[dict]) -> None:
    try:
        increment_role_prediction_quality_counters(year, events)
    except Exception as exc:
        print(f"[AIML KPI telemetry] Failed to increment role prediction quality counters: {exc}")


def ollama_total_tokens(response_data: dict | None) -> int | None:
    if not isinstance(response_data, dict):
        return None

    prompt_tokens = _int_counter(response_data.get("prompt_eval_count"))
    completion_tokens = _int_counter(response_data.get("eval_count"))
    if prompt_tokens or completion_tokens:
        return prompt_tokens + completion_tokens

    for key in ("total_tokens", "tokens"):
        value = _int_counter(response_data.get(key))
        if value:
            return value

    return None
