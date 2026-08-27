from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable
import csv
import json
import math

from fastapi import APIRouter, HTTPException, Query

from app.api.aiml_kpi_telemetry import role_prediction_quality_counts


router = APIRouter(prefix="/api/aiml-dashboard", tags=["aiml-dashboard"])


KPI_GROUPS = [
    {
        "group": "Core ML",
        "json_key": "core_ml",
        "metrics": [
            ("role_prediction_accuracy_pct", "Role Prediction Accuracy (%)", "emerald"),
            ("cia_prediction_accuracy_pct", "CIA Prediction Accuracy (%)", "emerald"),
            ("f1_score_role_model", "F1 Score (Role Model)", "emerald"),
            ("model_accuracy_pct", "Model Accuracy (%)", "emerald"),
        ],
    },
    {
        "group": "ML-based UABV",
        "json_key": "ml_based_uabv",
        "metrics": [
            ("behavior_model_accuracy_pct", "Behavior Model Accuracy (%)", "amber"),
            ("high_risk_user_percentage_pct", "High-Risk User Percentage (%)", "amber"),
            ("score_difference_ml_vs_rule", "Score Difference (ML vs Rule)", "amber"),
            ("top_contributing_feature_distribution_pct", "Top Contributing Feature Distribution (%)", "amber"),
        ],
    },
    {
        "group": "RAG Performance",
        "json_key": "rag_performance",
        "metrics": [
            ("rag_query_count", "RAG Query Count", "rose"),
            ("retrieval_success_rate_pct", "Retrieval Success Rate (%)", "rose"),
        ],
    },
    {
        "group": "LLM Performance",
        "json_key": "llm_performance",
        "metrics": [
            ("reasoning_calls", "Reasoning Calls", "sky"),
            ("total_tokens", "Total Tokens", "sky"),
        ],
    },
    {
        "group": "Human-in-the-Loop",
        "json_key": "human_in_the_loop",
        "metrics": [
            ("manual_role_corrections", "Manual Role Corrections", "amber"),
            ("manual_risk_corrections", "Manual Risk Corrections", "amber"),
        ],
    },
    {
        "group": "Trust & Reliability",
        "json_key": "trust_reliability",
        "metrics": [
            ("override_rate_pct", "Override Rate (%)", "rose"),
            ("low_confidence_predictions_pct", "Low Confidence Predictions (%)", "rose"),
        ],
    },
]

MetricCalculator = Callable[[dict, int], dict | None]


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _aiml_dashboard_file(year: int) -> Path:
    return _work_dir(year) / "AIMLDashboard.json"


def _aiml_inputs_file(year: int) -> Path:
    return _work_dir(year) / "AIMLKPIInputs.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventory.json"


def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _feature_importance_file() -> Path:
    return BASE_DIR / "data" / "ml" / "models" / "feature_importance.csv"


def _ml_dir() -> Path:
    return BASE_DIR / "data" / "ml"


def _rel(path: Path) -> str:
    try:
        return path.relative_to(BASE_DIR).as_posix()
    except Exception:
        return str(path)


def _read_json(path: Path, label: str | None = None) -> Any:
    name = label or path.name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"{name} is not valid JSON: {e}") from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read {name}: {e}") from e


def _read_json_if_exists(path: Path) -> Any:
    if not path.exists():
        return None
    return _read_json(path)


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _blank_dashboard_data(year: int) -> dict:
    return {
        "meta": {
            "name": "AI_ML_KPI_History",
            "description": "Historical KPI snapshots for the AI/ML dashboard.",
            "year": year,
        },
        "latest_snapshot_id": "",
        "snapshots": [],
    }


def _blank_inputs_data(year: int) -> dict:
    return {
        "meta": {
            "year": year,
            "name": "AI_ML_KPI_Inputs",
            "version": 2,
        },
        "role_model_training_runs": [],
        "role_prediction_events": [],
        "cia_prediction_events": [],
        "behavior_model_training_runs": [],
        "behavior_prediction_events": [],
        "manual_correction_events": [],
        "rag_events": [],
        "llm_events": [],
        "rag_llm_counters": {
            "rag_query_count": 0,
            "rag_success_count": 0,
            "rag_failure_count": 0,
            "llm_reasoning_calls": 0,
            "llm_total_tokens": 0,
        },
        "human_trust_counters": {
            "manual_role_corrections": 0,
            "manual_risk_corrections": 0,
            "evaluated_role_predictions": 0,
            "overridden_role_predictions": 0,
            "predictions_with_confidence": 0,
            "low_confidence_predictions": 0,
        },
    }


def _load_dashboard_data(year: int) -> dict:
    path = _aiml_dashboard_file(year)
    if not path.exists():
        return _blank_dashboard_data(year)

    data = _read_json(path, "AIMLDashboard.json")
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="AIMLDashboard.json must contain a JSON object.")

    data.setdefault("meta", _blank_dashboard_data(year)["meta"])
    data.setdefault("latest_snapshot_id", "")
    if not isinstance(data.get("snapshots"), list):
        data["snapshots"] = []
    if _migrate_dashboard_structure(data):
        _atomic_write_json(path, data)
    return data


def _seed_human_trust_counters_from_events(data: dict) -> dict:
    counters = {
        "manual_role_corrections": 0,
        "manual_risk_corrections": 0,
        "evaluated_role_predictions": 0,
        "overridden_role_predictions": 0,
        "predictions_with_confidence": 0,
        "low_confidence_predictions": 0,
    }

    manual_events = data.get("manual_correction_events", [])
    if isinstance(manual_events, list):
        for event in manual_events:
            if not isinstance(event, dict):
                continue
            correction_type = str(event.get("correction_type") or "").strip().lower()
            if correction_type == "role":
                counters["manual_role_corrections"] += 1
            elif correction_type == "risk":
                counters["manual_risk_corrections"] += 1

    role_events = data.get("role_prediction_events", [])
    if isinstance(role_events, list):
        counters.update(role_prediction_quality_counts(role_events))

    return counters


def _load_or_create_inputs_data(year: int) -> dict:
    path = _aiml_inputs_file(year)
    if not path.exists():
        data = _blank_inputs_data(year)
        _atomic_write_json(path, data)
        return data

    data = _read_json(path, "AIMLKPIInputs.json")
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="AIMLKPIInputs.json must contain a JSON object.")

    changed = False
    blank = _blank_inputs_data(year)
    data.setdefault("meta", blank["meta"])
    if not isinstance(data.get("meta"), dict):
        data["meta"] = deepcopy(blank["meta"])
        changed = True
    meta_version = _number(data["meta"].get("version")) or 0
    if int(meta_version) < 2:
        data["meta"]["version"] = 2
        changed = True
    for key, value in blank.items():
        if key == "meta":
            continue
        if isinstance(value, list) and (key not in data or not isinstance(data.get(key), list)):
            data[key] = value
            changed = True
        elif isinstance(value, dict):
            if not isinstance(data.get(key), dict):
                data[key] = (
                    _seed_human_trust_counters_from_events(data)
                    if key == "human_trust_counters"
                    else value
                )
                changed = True
            else:
                for nested_key, nested_value in value.items():
                    parsed = _number(data[key].get(nested_key))
                    clean_value = int(parsed) if parsed is not None and parsed >= 0 else nested_value
                    if data[key].get(nested_key) != clean_value:
                        data[key][nested_key] = clean_value
                        changed = True

    latest_role_run = _latest_item(_events(data, "role_model_training_runs"))
    if isinstance(latest_role_run, dict):
        has_accuracy = any(
            _number(latest_role_run.get(name)) is not None
            for name in ("accuracy_pct", "accuracy_percent", "accuracy")
        )
        if not has_accuracy:
            role_accuracy_proxy = _telemetry_role_accuracy(data, year)
            if role_accuracy_proxy:
                latest_role_run["accuracy_pct"] = role_accuracy_proxy.get("value")
                latest_role_run["accuracy_source"] = "role_prediction_events_proxy"
                notes = latest_role_run.get("notes")
                if not isinstance(notes, list):
                    notes = []
                    latest_role_run["notes"] = notes
                proxy_note = (
                    "Role model accuracy was backfilled from current role prediction events "
                    "because the original training run did not store accuracy_pct."
                )
                if proxy_note not in notes:
                    notes.append(proxy_note)
                changed = True

    if changed:
        _atomic_write_json(path, data)
    return data


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _now_local() -> datetime:
    return datetime.now().astimezone()


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        if math.isfinite(float(value)):
            return float(value)
        return None
    if isinstance(value, str):
        text = value.strip().replace("%", "")
        if not text:
            return None
        try:
            parsed = float(text)
            return parsed if math.isfinite(parsed) else None
        except Exception:
            return None
    return None


def _rounded(value: float, digits: int = 2) -> float:
    rounded = round(float(value), digits)
    return int(rounded) if rounded.is_integer() else rounded


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _events(data: dict, key: str) -> list[dict]:
    raw = data.get(key, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _rag_llm_counters(data: dict) -> dict:
    raw = data.get("rag_llm_counters", {})
    if not isinstance(raw, dict):
        return {}

    counters: dict[str, int] = {}
    for key in (
        "rag_query_count",
        "rag_success_count",
        "rag_failure_count",
        "llm_reasoning_calls",
        "llm_total_tokens",
    ):
        parsed = _number(raw.get(key))
        counters[key] = int(parsed) if parsed is not None and parsed >= 0 else 0
    return counters


def _human_trust_counters(data: dict) -> dict:
    raw = data.get("human_trust_counters", {})
    if not isinstance(raw, dict):
        return {}

    counters: dict[str, int] = {}
    for key in (
        "manual_role_corrections",
        "manual_risk_corrections",
        "evaluated_role_predictions",
        "overridden_role_predictions",
        "predictions_with_confidence",
        "low_confidence_predictions",
    ):
        parsed = _number(raw.get(key))
        counters[key] = int(parsed) if parsed is not None and parsed >= 0 else 0
    return counters


def _latest_item(items: list[dict]) -> dict | None:
    if not items:
        return None

    def sort_key(item: dict) -> tuple[datetime, str]:
        dt = (
            _parse_datetime(item.get("created_at"))
            or _parse_datetime(item.get("generated_at"))
            or _parse_datetime(item.get("timestamp"))
            or datetime.min
        )
        return dt, str(item.get("run_id") or item.get("event_id") or "")

    return sorted(items, key=sort_key)[-1]


def _metric(
    value: Any,
    *,
    computed: bool,
    source: str,
    method: str,
    formula: str = "",
    source_files: list[str] | None = None,
    inputs: dict | None = None,
    notes: list[str] | None = None,
    fallback_reason: str = "",
    extra: dict | None = None,
) -> dict:
    calculation = {
        "method": method,
        "formula": formula,
        "source_files": source_files or [],
        "inputs": inputs or {},
        "notes": notes or [],
    }
    if fallback_reason:
        calculation["fallback_reason"] = fallback_reason
    if extra:
        calculation.update(extra)

    return {
        "value": value,
        "computed": computed,
        "source": source,
        "calculation": calculation,
    }


KPI_MODAL_TEXT = {
    "role_prediction_accuracy_pct": {
        "meaning": "This measures how often the ML-predicted asset role matched the final selected role.",
        "formula": "Correct predictions / Total evaluated predictions * 100. A prediction is counted as correct when the ML-predicted role is the same as the final selected role.",
    },
    "model_accuracy_pct": {
        "meaning": "This shows the latest measured accuracy indicator for the role model used in asset role classification.",
        "formula": "If role training telemetry stores accuracy_pct, the dashboard uses that latest model-accuracy value. Otherwise, it uses current evaluated role prediction accuracy as the role-model accuracy indicator.",
    },
    "cia_prediction_accuracy_pct": {
        "meaning": "This measures how often CIA predictions were correct. If true CIA telemetry is missing, the dashboard may use CIA coverage as an estimate.",
        "formula": "Correct CIA predictions / Total CIA predictions * 100. If CIA prediction telemetry is unavailable, the fallback checks how many assets have a usable CIA rating.",
    },
    "f1_score_role_model": {
        "meaning": "This summarizes role model balance across role classes, accounting for both missed roles and incorrect role assignments.",
        "formula": "For each role class, the dashboard builds true positives, false positives, and false negatives from ML-predicted role versus final selected role. Precision = true positives / predicted positives. Recall = true positives / actual positives. Per-role F1 = 2 * precision * recall / (precision + recall). The displayed value is the macro average across role classes.",
    },
    "behavior_model_accuracy_pct": {
        "meaning": "This shows the latest measured accuracy of the user behavior risk model during training or evaluation.",
        "formula": "The user behavior dataset is split into stratified training and test sets. Numeric behavior features are median-imputed, labels are encoded, and a Random Forest classifier predicts the held-out test rows. Accuracy = correct test predictions / total test predictions * 100.",
    },
    "high_risk_user_percentage_pct": {
        "meaning": "This shows the percentage of user behavior records classified as high risk.",
        "formula": "High-risk user behavior records / Total user behavior records * 100",
    },
    "score_difference_ml_vs_rule": {
        "meaning": "This compares ML behavior scoring with rule-based scoring. A larger value means the ML model and rules disagree more.",
        "formula": "Average absolute difference between ML score and rule score",
    },
    "top_contributing_feature_distribution_pct": {
        "meaning": "This shows how much the most influential behavior feature contributes compared with the full feature-importance distribution.",
        "formula": "Top feature importance / Sum of feature importances * 100. Feature importance comes from the latest behavior model training telemetry.",
    },
    "rag_query_count": {
        "meaning": "This counts how many RAG retrieval requests were run by the application.",
        "formula": "Count of RAG retrieval requests",
    },
    "retrieval_success_rate_pct": {
        "meaning": "This measures how often RAG retrieval returned usable results.",
        "formula": "Successful RAG retrievals / Total RAG retrieval requests * 100",
    },
    "reasoning_calls": {
        "meaning": "This counts successful LLM reasoning calls made by the application.",
        "formula": "Count of successful LLM reasoning calls",
    },
    "total_tokens": {
        "meaning": "This is the total token volume reported by successful LLM calls.",
        "formula": "Sum of reported LLM tokens",
    },
    "manual_role_corrections": {
        "meaning": "This counts how many asset roles were manually changed by a user.",
        "formula": "Count of manual asset role corrections",
    },
    "manual_risk_corrections": {
        "meaning": "This counts how many risk values were manually changed by a user.",
        "formula": "Count of manual risk corrections",
    },
    "override_rate_pct": {
        "meaning": "This measures how often the final selected role was different from the ML-predicted role. Higher values mean model output is being corrected more often.",
        "formula": "Role predictions changed by user / Total evaluated role predictions * 100",
    },
    "low_confidence_predictions_pct": {
        "meaning": "This shows the percentage of ML role predictions below the confidence threshold of 0.60. Higher values mean the model is less certain for more assets.",
        "formula": "Low-confidence role predictions / Role predictions with confidence score * 100",
    },
}


INPUT_LABELS = {
    "correct_predictions": "Correct predictions",
    "total_predictions": "Total evaluated predictions",
    "matching_predictions": "ML predictions matching final value",
    "evaluated_assets": "Assets evaluated",
    "assets_with_cia_rating": "Assets with CIA rating",
    "total_assets": "Total assets",
    "evaluated_predictions": "Evaluated predictions",
    "macro_f1": "Macro F1 score",
    "run_id": "Training run",
    "accuracy_pct": "Model accuracy",
    "accuracy_source": "Accuracy source",
    "server_accuracy_pct": "Server model accuracy",
    "workstation_accuracy_pct": "Workstation model accuracy",
    "total_behavior_predictions": "Total behavior predictions",
    "total_user_behavior_records": "Total user behavior records",
    "high_risk_users": "High-risk user behavior records",
    "compared_behavior_predictions": "Behavior predictions compared",
    "compared_user_behavior_records": "User behavior records compared",
    "feature_count": "Features included",
    "top_feature": "Top contributing feature",
    "top_feature_contribution_pct": "Top feature contribution (%)",
    "total_feature_importance_pct": "Total normalized feature importance (%)",
    "rag_query_count": "Total RAG retrieval requests",
    "rag_success_count": "Successful RAG retrievals",
    "rag_failure_count": "Failed RAG retrievals",
    "successful_retrievals": "Successful RAG retrievals",
    "evaluated_rag_queries": "Evaluated RAG retrieval requests",
    "llm_reasoning_calls": "Successful LLM reasoning calls",
    "llm_total_tokens": "Total LLM tokens",
    "llm_events": "LLM events",
    "llm_events_with_token_counts": "LLM events with token counts",
    "manual_role_corrections": "Manual asset role corrections",
    "manual_risk_corrections": "Manual risk corrections",
    "manual_corrections": "Manual corrections",
    "correction_type": "Correction type",
    "overridden_role_predictions": "Role predictions changed by user",
    "evaluated_role_predictions": "Total evaluated role predictions",
    "overridden_predictions": "Role predictions changed by user",
    "low_confidence_predictions": "Low-confidence role predictions",
    "predictions_with_confidence": "Role predictions with confidence score",
    "override_records": "Risk records manually overridden",
    "total_risk_records": "Total risk records",
    "previous_value": "Latest available KPI value",
    "previous_generated_at": "Latest available snapshot date",
    "latest_available_kpi_value": "Latest available KPI value",
    "latest_available_snapshot_date": "Latest available snapshot date",
    "latest_available_source": "Latest available data source",
}


RATIO_INPUTS = {
    "role_prediction_accuracy_pct": (
        ["correct_predictions", "matching_predictions"],
        ["total_predictions", "evaluated_assets"],
    ),
    "model_accuracy_pct": (
        ["correct_predictions", "matching_predictions"],
        ["total_predictions", "evaluated_assets"],
    ),
    "cia_prediction_accuracy_pct": (
        ["correct_predictions", "assets_with_cia_rating"],
        ["total_predictions", "total_assets"],
    ),
    "behavior_model_accuracy_pct": (
        ["accuracy_pct"],
        [],
    ),
    "high_risk_user_percentage_pct": (
        ["high_risk_users"],
        ["total_behavior_predictions", "total_user_behavior_records"],
    ),
    "retrieval_success_rate_pct": (
        ["rag_success_count", "successful_retrievals"],
        ["rag_query_count", "evaluated_rag_queries"],
    ),
    "override_rate_pct": (
        ["overridden_role_predictions", "overridden_predictions", "override_records"],
        ["evaluated_role_predictions", "evaluated_predictions", "total_risk_records"],
    ),
    "low_confidence_predictions_pct": (
        ["low_confidence_predictions"],
        ["predictions_with_confidence"],
    ),
}
COUNT_INPUTS = {
    "rag_query_count": ["rag_query_count", "rag_events"],
    "reasoning_calls": ["llm_reasoning_calls", "llm_events"],
    "total_tokens": ["llm_total_tokens"],
    "manual_role_corrections": ["manual_role_corrections", "manual_corrections"],
    "manual_risk_corrections": ["manual_risk_corrections", "manual_corrections"],
}


def _readable_input_label(key: str) -> str:
    text = str(key or "").strip()
    if text in INPUT_LABELS:
        return INPUT_LABELS[text]

    normalized = "".join(ch for ch in text.lower() if ch.isalnum())
    if normalized:
        for raw_key, label in INPUT_LABELS.items():
            raw_normalized = "".join(ch for ch in str(raw_key).lower() if ch.isalnum())
            label_normalized = "".join(ch for ch in str(label).lower() if ch.isalnum())
            if normalized == raw_normalized or normalized == label_normalized:
                return label

    words = []
    current = ""
    for ch in text.replace("-", " ").replace("_", " "):
        if ch.isupper() and current and not current[-1].isupper():
            words.append(current)
            current = ch
        else:
            current += ch
    if current:
        words.append(current)
    rebuilt = " ".join(part.strip() for part in words if part.strip())
    return rebuilt.title() if rebuilt else text


def _readable_source_value(value: Any) -> Any:
    text = str(value or "").strip()
    if not text:
        return value

    mapping = {
        "telemetry": "Current telemetry",
        "previous_snapshot": "Previous snapshot history",
        "table_fallback": "Current table fallback",
        "not_available": "Not available",
        "reset_audit": "Reset audit snapshot",
        "role_prediction_events_proxy": "Current role prediction events proxy",
        "current_role_prediction_events_proxy": "Current role prediction events proxy",
    }

    normalized = text.lower()
    if normalized in mapping:
        return mapping[normalized]
    return text.replace("_", " ").strip().title()


def _format_modal_value(value: Any, metric_key: str | None = None) -> str:
    if value is None or value == "":
        return "NA"
    if isinstance(value, float):
        text = f"{value:.4f}".rstrip("0").rstrip(".")
    else:
        text = str(value)
    if metric_key and metric_key.endswith("_pct") and text != "NA":
        return f"{text}%"
    return text


def _first_existing_input(inputs: dict, keys: list[str]) -> tuple[str, Any] | tuple[None, None]:
    for key in keys:
        if key in inputs and inputs.get(key) is not None:
            return key, inputs.get(key)
    return None, None


def _metric_number(metric: dict) -> float | None:
    if not isinstance(metric, dict):
        return None
    value = metric.get("value")
    if isinstance(value, dict):
        numeric_values = [
            _number(item)
            for item in value.values()
            if _number(item) is not None
        ]
        return max(numeric_values) if numeric_values else None
    value = _number(metric.get("value"))
    return value


def _top_feature_info(metric: dict, inputs: dict | None = None) -> tuple[str, float | None]:
    inputs = inputs or {}
    input_feature = str(inputs.get("top_feature") or "").strip()
    input_share = _number(inputs.get("top_feature_contribution_pct"))
    if input_feature or input_share is not None:
        return input_feature, input_share

    value = metric.get("value") if isinstance(metric, dict) else None
    if not isinstance(value, dict):
        return "", None

    numeric_items = []
    for feature, share in value.items():
        numeric_share = _number(share)
        if numeric_share is not None:
            numeric_items.append((str(feature), numeric_share))

    if not numeric_items:
        return "", None

    return max(numeric_items, key=lambda item: item[1])


def _feature_distribution_items(metric: dict) -> list[tuple[str, float]]:
    value = metric.get("value") if isinstance(metric, dict) else None
    if not isinstance(value, dict):
        return []

    items = []
    for feature, share in value.items():
        numeric_share = _number(share)
        if numeric_share is not None:
            items.append((str(feature), numeric_share))

    return sorted(items, key=lambda item: item[1], reverse=True)


def _feature_distribution_summary(metric: dict) -> str:
    items = _feature_distribution_items(metric)
    if not items:
        return ""
    return ", ".join(
        f"{feature}: {_format_modal_value(share, 'top_contributing_feature_distribution_pct')}"
        for feature, share in items
    )


def _percent_quality(value: float | None, *, high_is_good: bool = True) -> str:
    if value is None:
        return "The dashboard does not have enough current data to judge this KPI yet."
    if high_is_good:
        if value >= 90:
            return "This is a strong result and suggests the related model or workflow is performing well."
        if value >= 75:
            return "This is a usable result, but there is still room to improve consistency."
        if value >= 50:
            return "This is a moderate result and should be reviewed for possible tuning or better input data."
        return "This is a weak result and suggests the related model or workflow needs attention."
    if value <= 5:
        return "This is a low rate, which is generally a good sign for this KPI."
    if value <= 20:
        return "This is a moderate rate and should be watched over time."
    return "This is a high rate and should be reviewed because it may indicate trust or quality issues."


def _count_quality(value: float | None, zero_message: str, nonzero_message: str) -> str:
    if value is None:
        return "The dashboard does not have enough current data to judge this KPI yet."
    if value == 0:
        return zero_message
    return nonzero_message


def _input_number(inputs: dict, keys: list[str]) -> tuple[str | None, float | None]:
    key, value = _first_existing_input(inputs, keys)
    return key, _number(value)


def _input_count_text(inputs: dict, keys: list[str]) -> str:
    key, value = _first_existing_input(inputs, keys)
    if not key:
        return ""
    return f"{_readable_input_label(key)} is {_format_modal_value(value)}"


def _ratio_activity_text(inputs: dict, numerator_keys: list[str], denominator_keys: list[str]) -> str:
    numerator_key, numerator = _input_number(inputs, numerator_keys)
    denominator_key, denominator = _input_number(inputs, denominator_keys)
    if not numerator_key or not denominator_key or denominator is None:
        return ""
    misses = None
    if numerator is not None:
        misses = max(denominator - numerator, 0)
    sentence = (
        f"In the current data, {_readable_input_label(numerator_key)} is "
        f"{_format_modal_value(numerator)} and {_readable_input_label(denominator_key)} is "
        f"{_format_modal_value(denominator)}."
    )
    if misses is not None:
        sentence += f" That leaves {_format_modal_value(misses)} records that did not meet this KPI condition."
    return sentence


def _modal_meaning(metric_key: str, metric: dict) -> str:
    value = _metric_number(metric)
    displayed = _format_modal_value(metric.get("value"), metric_key)
    calculation = metric.get("calculation", {}) if isinstance(metric.get("calculation"), dict) else {}
    inputs = calculation.get("inputs", {}) if isinstance(calculation.get("inputs"), dict) else {}
    carried_context = ""

    if metric.get("source") == "previous_snapshot":
        previous_generated_at = calculation.get("previous_generated_at") or inputs.get("latest_available_snapshot_date")
        previous_text = f" from {previous_generated_at}" if previous_generated_at else ""
        carried_context = (
            f"This uses the latest available KPI data{previous_text} because current telemetry was missing. "
        )

    if metric.get("source") == "not_available":
        return (
            "No usable data is available for this KPI yet. The system has not captured enough telemetry, previous "
            "snapshot history, or fallback table data to measure this part of AI/ML performance."
        )

    if metric_key == "role_prediction_accuracy_pct":
        activity = _ratio_activity_text(
            inputs,
            ["correct_predictions", "matching_predictions"],
            ["total_predictions", "evaluated_assets"],
        )
        return (
            f"{carried_context}{displayed} role prediction accuracy means the role model matched the final selected asset role at that rate. "
            f"{activity} The goal is to make asset role assignment reliable enough to support CIA rating, risk analysis, "
            f"and downstream ISO workflow decisions with less manual correction. {_percent_quality(value)}"
        )
    if metric_key == "model_accuracy_pct":
        if "accuracy_pct" in inputs and "run_id" in inputs:
            accuracy_source = _readable_source_value(inputs.get("accuracy_source")) if inputs.get("accuracy_source") else ""
            source_text = f" The accuracy source was {accuracy_source}." if accuracy_source else ""
            return (
                f"{carried_context}{displayed} model accuracy means the latest role-model evaluation ran at that accuracy level for asset role classification. "
                f"{_input_count_text(inputs, ['run_id'])}. {_input_count_text(inputs, ['accuracy_pct'])}.{source_text} "
                "The goal is to show whether the trained role model itself is learning role classes well enough before we trust it in live assignment workflows. "
                f"{_percent_quality(value)}"
            )
        activity = _ratio_activity_text(
            inputs,
            ["correct_predictions", "matching_predictions"],
            ["total_predictions", "evaluated_assets"],
        )
        return (
            f"{carried_context}{displayed} model accuracy is currently being estimated from evaluated role prediction outcomes because stored role-training accuracy was not available. "
            f"{activity} The goal is to keep a usable model-quality signal available for the role model even when dedicated training telemetry is missing. "
            f"{_percent_quality(value)}"
        )
    if metric_key == "cia_prediction_accuracy_pct":
        activity = _ratio_activity_text(
            inputs,
            ["correct_predictions", "assets_with_cia_rating"],
            ["total_predictions", "total_assets"],
        )
        return (
            f"{carried_context}{displayed} CIA prediction accuracy means CIA outcomes were matched or covered at that rate. "
            f"{activity} The goal is to keep confidentiality, integrity, and availability classification consistent "
            f"before risk scoring depends on it. {_percent_quality(value)}"
        )
    if metric_key == "f1_score_role_model":
        if value is None:
            return "The F1 score is not available yet. It will become meaningful after role prediction or training telemetry exists."
        activity = _input_count_text(inputs, ["evaluated_predictions", "total_predictions"])
        activity = f" {activity}." if activity else ""
        return (
            f"{carried_context}An F1 score of {_format_modal_value(value)} is a class-balanced role model quality signal. "
            "It penalizes both false role assignments and missed role assignments, so it is more useful than accuracy when role classes are uneven. "
            f"{activity} The goal is for every asset role class, not only the most common ones, to be predicted reliably. "
            f"{_percent_quality(value * 100)}"
        )
    if metric_key == "behavior_model_accuracy_pct":
        activity = _input_count_text(inputs, ["accuracy_pct"])
        activity = f" {activity}." if activity else ""
        return (
            f"{carried_context}{displayed} behavior model accuracy means the user-behavior model predicted held-out behavior-risk labels correctly at that rate. "
            f"{activity} This reflects how well the model generalizes from training behavior records to unseen behavior records, which matters for UABV risk detection. "
            f"{_percent_quality(value)}"
        )
    if metric_key == "average_behavior_risk_score":
        if value is None:
            return "The average behavior risk score is not available yet."
        if value >= 0.75:
            level = "a high-risk behavior profile overall."
        elif value >= 0.50:
            level = "a moderate-risk behavior profile overall."
        else:
            level = "a lower-risk behavior profile overall."
        activity = _input_count_text(inputs, ["total_behavior_predictions", "total_user_behavior_records"])
        activity = f" {activity}." if activity else ""
        return (
            f"{carried_context}The average behavior risk score is {_format_modal_value(value)}, which indicates {level} "
            f"{activity} The goal is to summarize whether user behavior activity is trending toward normal behavior or elevated UABV risk."
        )
    if metric_key == "high_risk_user_percentage_pct":
        activity = _ratio_activity_text(
            inputs,
            ["high_risk_users"],
            ["total_behavior_predictions", "total_user_behavior_records"],
        )
        return (
            f"{carried_context}{displayed} of user behavior records are currently high risk. "
            f"{activity} The goal is to show how much monitored activity is being pushed into the highest risk band. "
            f"{_percent_quality(value, high_is_good=False)}"
        )
    if metric_key == "score_difference_ml_vs_rule":
        activity = _input_count_text(inputs, ["compared_behavior_predictions", "compared_user_behavior_records"])
        activity = f" {activity}." if activity else ""
        return (
            f"{carried_context}The ML-vs-rule score difference is {_format_modal_value(value)}. "
            "Lower values mean the ML scoring and rule-based scoring are more aligned; higher values mean they disagree more. "
            f"{activity} The goal is to detect when model behavior is drifting away from the transparent rule baseline."
        )
    if metric_key == "top_contributing_feature_distribution_pct":
        top_feature, top_share = _top_feature_info(metric, inputs)
        feature_text = top_feature or "the strongest behavior feature"
        share_text = _format_modal_value(top_share, metric_key) if top_share is not None else displayed
        return (
            f"{carried_context}{share_text} top contributing feature distribution means {feature_text} is the strongest behavior signal in the model. "
            "This percentage is its share of the normalized feature-importance distribution. A high value means one behavior feature is driving much of the model's decision pattern. "
            "The goal is to understand whether UABV decisions are balanced across behavior signals or dominated by one input feature."
        )
    if metric_key == "rag_query_count":
        return (
            f"{carried_context}The dashboard recorded {_format_modal_value(value)} RAG retrieval requests. "
            "This measures retrieval workload across assistant actions that need knowledge-base context. The goal is to understand how often the app depends on RAG instead of only static form data or prompt logic."
        )
    if metric_key == "retrieval_success_rate_pct":
        activity = _ratio_activity_text(
            inputs,
            ["rag_success_count", "successful_retrievals"],
            ["rag_query_count", "evaluated_rag_queries"],
        )
        return (
            f"{carried_context}{displayed} retrieval success means RAG returned usable context at that rate. "
            f"{activity} The goal is for knowledge retrieval to consistently provide supporting controls, risks, or guidance for assistant responses. "
            f"{_percent_quality(value)}"
        )
    if metric_key == "reasoning_calls":
        return (
            f"{carried_context}The app recorded {_format_modal_value(value)} successful LLM reasoning calls. "
            "This reflects reasoning workload and feature usage volume, not direct answer quality. The goal is to track how often forms rely on local LLM reasoning for recommendations, explanations, or generated content."
        )
    if metric_key == "total_tokens":
        return (
            f"{carried_context}The app recorded {_format_modal_value(value)} LLM tokens. "
            "This reflects approximate LLM workload and can explain latency, memory pressure, and model-serving cost. The goal is to watch whether model usage is growing faster than the value produced by assistant actions."
        )
    if metric_key == "manual_role_corrections":
        if carried_context and value == 0:
            return carried_context + "No manual role corrections were recorded in the latest available KPI data. That means users had not needed to change model-assisted asset role decisions in that measurement window."
        return _count_quality(
            value,
            "No manual role corrections are recorded in current telemetry. That means users have not needed to change model-assisted asset role decisions in this snapshot, which is a good trust signal if role prediction activity exists.",
            f"{carried_context}{_format_modal_value(value)} manual role corrections are recorded. This means users changed asset role decisions after model-assisted assignment, so these corrections are useful feedback for improving role prediction quality.",
        )
    if metric_key == "manual_risk_corrections":
        if carried_context and value == 0:
            return carried_context + "No manual risk corrections were recorded in the latest available KPI data. That means users had not needed to change risk values in that measurement window."
        return _count_quality(
            value,
            "No manual risk corrections are recorded in current telemetry. That means users have not needed to change risk values in this snapshot, which is a good reliability signal if risk analysis activity exists.",
            f"{carried_context}{_format_modal_value(value)} manual risk corrections are recorded. This means users changed risk decisions after analysis, so the risk model or rule output should be reviewed against those human decisions.",
        )
    if metric_key == "override_rate_pct":
        activity = _ratio_activity_text(
            inputs,
            ["overridden_role_predictions", "overridden_predictions", "override_records"],
            ["evaluated_role_predictions", "evaluated_predictions", "total_risk_records"],
        )
        return (
            f"{carried_context}{displayed} override rate means final role decisions differed from the ML-predicted role at that rate. "
            f"{activity} The goal is to measure user trust in model output: lower override rates usually mean model suggestions are fitting the workflow better. "
            f"{_percent_quality(value, high_is_good=False)}"
        )
    if metric_key == "low_confidence_predictions_pct":
        activity = _ratio_activity_text(
            inputs,
            ["low_confidence_predictions"],
            ["predictions_with_confidence"],
        )
        return (
            f"{carried_context}{displayed} low-confidence predictions means that share of ML role predictions fell below the 0.60 confidence threshold. "
            f"{activity} The goal is to identify where the model is uncertain and where human review or more training data is most valuable. "
            f"{_percent_quality(value, high_is_good=False)}"
        )

    text = KPI_MODAL_TEXT.get(metric_key, {})
    return text.get("meaning", "This KPI summarizes the related AI/ML dashboard signal.")


def _named_ratio_formula(metric_key: str, inputs: dict) -> str | None:
    ratio_config = RATIO_INPUTS.get(metric_key)
    if not ratio_config:
        return None
    numerator_key, _numerator = _first_existing_input(inputs, ratio_config[0])
    denominator_key, _denominator = _first_existing_input(inputs, ratio_config[1])
    if numerator_key and denominator_key:
        return f"{_readable_input_label(numerator_key)} / {_readable_input_label(denominator_key)} * 100"
    return None


def _modal_how_computed(metric_key: str, metric: dict) -> str:
    calculation = metric.get("calculation", {}) if isinstance(metric, dict) else {}
    inputs = calculation.get("inputs", {}) if isinstance(calculation.get("inputs"), dict) else {}
    carried_prefix = ""

    if metric.get("source") == "previous_snapshot":
        carried_prefix = (
            "Current telemetry was missing, so Displayed value was set from Latest available KPI value "
            "in Latest available snapshot date. "
        )
    if metric.get("source") == "not_available":
        return "No calculation was run because the dashboard could not find telemetry, a previous value, or table fallback data."

    if metric_key == "role_prediction_accuracy_pct":
        return carried_prefix + (
            "Correct predictions / Total evaluated predictions * 100. Correct predictions counts records where the ML-predicted role matched the final selected role. "
            "Total evaluated predictions counts records where both the model prediction and final selected role were available."
        )
    if metric_key == "cia_prediction_accuracy_pct":
        return carried_prefix + (
            "Correct CIA predictions / Total CIA predictions * 100. If direct CIA prediction telemetry is not available, "
            "Assets with CIA rating / Total assets * 100 is used as a fallback coverage estimate."
        )
    if metric_key == "f1_score_role_model":
        return carried_prefix + (
            "Macro F1 score is calculated from role-class precision and recall. For each role class, the system compares ML-predicted role with final selected role, "
            "then builds true positives, false positives, and false negatives. Precision = true positives / predicted positives. "
            "Recall = true positives / actual positives. Per-role F1 = 2 * precision * recall / (precision + recall). "
            "The displayed Macro F1 score is the average of the per-role F1 values, so smaller role classes still affect the result."
        )
    if metric_key == "model_accuracy_pct":
        if "run_id" in inputs and "accuracy_pct" in inputs:
            return carried_prefix + (
                "The dashboard reads the latest role model training run from AIMLKPIInputs.json and uses its stored Model accuracy value. "
                "When available, this is the direct role-model accuracy metric captured for that run."
            )
        return carried_prefix + (
            "Stored role model training accuracy was not available, so the dashboard used Correct predictions / Total evaluated predictions * 100 from current role prediction telemetry as the role-model accuracy indicator."
        )
    if metric_key == "behavior_model_accuracy_pct":
        return carried_prefix + (
            "Model accuracy is calculated on the held-out Test split. The behavior training pipeline median-imputes numeric behavior features, encodes the risk label, "
            "trains the Model algorithm, then predicts the held-out test rows. Model accuracy = correctly predicted test rows / total test rows * 100."
        )

    named_ratio = _named_ratio_formula(metric_key, inputs)
    if named_ratio:
        return carried_prefix + named_ratio

    for key in COUNT_INPUTS.get(metric_key, []):
        if key in inputs:
            return carried_prefix + f"The dashboard uses {_readable_input_label(key)} as the displayed count."

    if metric_key == "average_behavior_risk_score":
        total_key, _total = _first_existing_input(inputs, ["total_behavior_predictions", "total_user_behavior_records"])
        total_label = _readable_input_label(total_key) if total_key else "Total behavior records"
        return carried_prefix + f"Sum of behavior risk scores / {total_label}."
    if metric_key == "score_difference_ml_vs_rule":
        total_key, _total = _first_existing_input(inputs, ["compared_behavior_predictions", "compared_user_behavior_records"])
        total_label = _readable_input_label(total_key) if total_key else "Compared behavior records"
        return carried_prefix + f"For each record, compute absolute difference between ML score and rule score, then average those differences across {total_label}."
    if metric_key == "top_contributing_feature_distribution_pct":
        return carried_prefix + (
            "Top feature contribution (%) / Total normalized feature importance (%) * 100. "
            "Top feature contribution (%) is the largest normalized feature-importance value from the latest behavior model training run. "
            "Total normalized feature importance (%) is 100 because all included feature shares are normalized to a full distribution."
        )

    return carried_prefix + (KPI_MODAL_TEXT.get(metric_key, {}).get("formula") or calculation.get("formula", ""))


def _data_used_items(metric: dict, metric_key: str) -> list[dict]:
    calculation = metric.get("calculation", {}) if isinstance(metric, dict) else {}
    inputs = calculation.get("inputs", {}) if isinstance(calculation.get("inputs"), dict) else {}

    if metric.get("source") == "previous_snapshot":
        if metric_key == "top_contributing_feature_distribution_pct":
            top_feature, top_share = _top_feature_info(metric, inputs)
            items = []
            run_id = inputs.get("run_id")
            if run_id:
                items.append({"label": "Training run", "value": run_id})
            if top_feature:
                items.append({"label": "Top contributing feature", "value": top_feature})
            if top_share is not None:
                items.append({"label": "Top feature contribution (%)", "value": _format_modal_value(top_share, metric_key)})
            feature_summary = _feature_distribution_summary(metric)
            feature_count = inputs.get("feature_count")
            if feature_summary:
                items.append({"label": "Features included", "value": feature_summary})
            elif feature_count is not None:
                items.append({"label": "Features included", "value": feature_count})
            previous_generated_at = calculation.get("previous_generated_at")
            if previous_generated_at:
                items.append({"label": "Latest available snapshot date", "value": previous_generated_at})
            source = inputs.get("latest_available_source") or calculation.get("previous_source")
            if source:
                items.append({"label": "Latest available data source", "value": _readable_source_value(source)})
            return items

        items = [
            {
                "label": _readable_input_label(str(key)),
                "value": _readable_source_value(value) if str(key) == "latest_available_source" else value,
            }
            for key, value in inputs.items()
            if key not in {"previous_source", "previous_method"}
        ]
        if not items:
            items = [{"label": "Latest available KPI value", "value": metric.get("value")}]
        previous_generated_at = calculation.get("previous_generated_at")
        has_snapshot_date = any(item.get("label") == "Latest available snapshot date" for item in items)
        if previous_generated_at and not has_snapshot_date:
            items.append({"label": "Latest available snapshot date", "value": previous_generated_at})
        return items

    if metric.get("source") == "not_available":
        return []

    if not inputs:
        inputs = {}

    if metric_key == "top_contributing_feature_distribution_pct":
        top_feature, top_share = _top_feature_info(metric, inputs)
        items = []
        run_id = inputs.get("run_id")
        if run_id:
            items.append({"label": "Training run", "value": run_id})
        if top_feature:
            items.append({"label": "Top contributing feature", "value": top_feature})
        if top_share is not None:
            items.append({"label": "Top feature contribution (%)", "value": _format_modal_value(top_share, metric_key)})
        feature_summary = _feature_distribution_summary(metric)
        feature_count = inputs.get("feature_count")
        if feature_summary:
            items.append({"label": "Features included", "value": feature_summary})
        elif feature_count is not None:
            items.append({"label": "Features included", "value": feature_count})
        return items

    items = [
        {
            "label": _readable_input_label(str(key)),
            "value": _readable_source_value(value) if str(key) == "latest_available_source" else value,
        }
        for key, value in inputs.items()
        if key not in {"previous_source", "previous_method"}
    ]
    if metric_key == "model_accuracy_pct" and "accuracy_source" in inputs:
        items = [
            {
                "label": item["label"],
                "value": _readable_source_value(item["value"])
                if item["label"] == "Accuracy Source"
                else item["value"],
            }
            for item in items
        ]
    if metric_key == "behavior_model_accuracy_pct" and "accuracy_pct" in inputs:
        items.append({"label": "Model algorithm", "value": "Random Forest classifier"})
        items.append({"label": "Test split", "value": "20% stratified hold-out"})
    if metric_key == "f1_score_role_model":
        items.append({"label": "F1 averaging method", "value": "Macro average across role classes"})
    return items


def _actual_calculation(metric: dict, metric_key: str) -> str:
    calculation = metric.get("calculation", {}) if isinstance(metric, dict) else {}
    inputs = calculation.get("inputs", {}) if isinstance(calculation.get("inputs"), dict) else {}
    value = metric.get("value")

    if metric.get("source") == "previous_snapshot":
        return f"Carried forward previous KPI value = {_format_modal_value(value, metric_key)}"
    if metric.get("source") == "not_available":
        return "No calculation was run because no usable data was available."

    ratio_config = RATIO_INPUTS.get(metric_key)
    if ratio_config:
        numerator_key, numerator = _first_existing_input(inputs, ratio_config[0])
        denominator_key, denominator = _first_existing_input(inputs, ratio_config[1])
        if numerator_key and denominator_key:
            return (
                f"{_format_modal_value(numerator)} / {_format_modal_value(denominator)} * 100 = "
                f"{_format_modal_value(value, metric_key)}"
            )
        if numerator_key and metric_key == "model_accuracy_pct":
            return f"Latest stored role model accuracy = {_format_modal_value(value, metric_key)}"
        if numerator_key and metric_key == "behavior_model_accuracy_pct":
            return f"Latest stored behavior model accuracy = {_format_modal_value(value, metric_key)}"

    for key in COUNT_INPUTS.get(metric_key, []):
        if key in inputs:
            return f"{_readable_input_label(key)} = {_format_modal_value(inputs.get(key), metric_key)}"

    if metric_key == "average_behavior_risk_score":
        total = inputs.get("total_behavior_predictions") or inputs.get("total_user_behavior_records")
        if total:
            return f"Average of {_format_modal_value(total)} behavior scores = {_format_modal_value(value)}"
    if metric_key == "score_difference_ml_vs_rule":
        total = inputs.get("compared_behavior_predictions") or inputs.get("compared_user_behavior_records")
        if total:
            return f"Average difference across {_format_modal_value(total)} compared records = {_format_modal_value(value)}"
    if metric_key == "top_contributing_feature_distribution_pct":
        total = inputs.get("feature_count")
        if total:
            return f"Top feature share across {_format_modal_value(total)} features = {_format_modal_value(value, metric_key)}"
    if metric_key == "f1_score_role_model":
        if "macro_f1" in inputs:
            return f"Latest stored macro F1 score = {_format_modal_value(value)}"
        if "evaluated_predictions" in inputs:
            return f"Macro F1 from {_format_modal_value(inputs.get('evaluated_predictions'))} evaluated predictions = {_format_modal_value(value)}"

    return f"Computed value = {_format_modal_value(value, metric_key)}"


def _enhance_metric_for_modal(group_key: str, metric_key: str, metric: dict) -> dict:
    if not isinstance(metric, dict):
        return metric
    calculation = metric.setdefault("calculation", {})
    if not isinstance(calculation, dict):
        calculation = {}
        metric["calculation"] = calculation

    calculation["what_this_means"] = _modal_meaning(metric_key, metric)
    calculation["readable_formula"] = _modal_how_computed(metric_key, metric)
    calculation["data_used"] = _data_used_items(metric, metric_key)
    calculation.pop("actual_calculation", None)
    return metric


def _has_metric_value(metric: Any) -> bool:
    if isinstance(metric, dict) and "value" in metric:
        value = metric.get("value")
    else:
        value = metric

    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().upper() != "NA"
    if isinstance(value, dict):
        return bool(value)
    return True


def _metric_value(metric: Any) -> Any:
    if not isinstance(metric, dict):
        return metric
    value = metric.get("value")
    if not isinstance(value, dict):
        return value
    numeric_items = [
        (key, item)
        for key, item in value.items()
        if isinstance(item, (int, float)) and not isinstance(item, bool)
    ]
    if not numeric_items:
        return ""
    _, top_value = max(numeric_items, key=lambda item: item[1])
    return top_value


def _metric_detail(metric: Any) -> dict:
    if not isinstance(metric, dict):
        return {
            "value": metric,
            "computed": None,
            "source": "",
            "raw_value": metric,
            "calculation": {},
        }

    return {
        "value": _metric_value(metric),
        "computed": metric.get("computed"),
        "source": metric.get("source", ""),
        "raw_value": metric.get("value"),
        "calculation": metric.get("calculation", {}),
    }


def _snapshot_for_year(data: dict, year: int) -> dict:
    snapshots = data.get("snapshots", [])
    if not isinstance(snapshots, list):
        snapshots = []

    candidates = [
        item
        for item in snapshots
        if isinstance(item, dict) and int(item.get("year") or 0) == year
    ]

    latest_snapshot_id = str(data.get("latest_snapshot_id") or "").strip()
    for item in candidates:
        if str(item.get("snapshot_id") or "").strip() == latest_snapshot_id:
            return item

    if candidates:
        return candidates[-1]

    for item in snapshots:
        if isinstance(item, dict):
            return item

    return {}


def _snapshots_newest_first(data: dict, year: int) -> list[dict]:
    snapshots = [
        item
        for item in data.get("snapshots", [])
        if isinstance(item, dict) and int(item.get("year") or 0) == year
    ]
    return list(reversed(snapshots))


def _previous_metric(data: dict, year: int, group_key: str, metric_key: str) -> tuple[dict, dict] | tuple[None, None]:
    fallback_candidate: tuple[dict, dict] | tuple[None, None] = (None, None)
    for snapshot in _snapshots_newest_first(data, year):
        metric = (
            snapshot.get("kpis", {})
            if isinstance(snapshot.get("kpis"), dict)
            else {}
        ).get(group_key, {})
        if not isinstance(metric, dict):
            continue
        candidate = metric.get(metric_key)
        if _has_metric_value(candidate):
            if fallback_candidate == (None, None):
                fallback_candidate = (candidate, snapshot)
            if not (isinstance(candidate, dict) and candidate.get("source") == "previous_snapshot"):
                return candidate, snapshot
    return fallback_candidate


def _previous_metric_inputs(previous_calculation: Any) -> dict:
    if not isinstance(previous_calculation, dict):
        return {}
    inputs = previous_calculation.get("inputs", {})
    if not isinstance(inputs, dict):
        return {}
    ignored_keys = {
        "previous_value",
        "previous_source",
        "previous_method",
        "latest_available_kpi_value",
        "latest_available_snapshot_date",
        "latest_available_source",
    }
    return {
        str(key): deepcopy(value)
        for key, value in inputs.items()
        if str(key) not in ignored_keys
    }


def _carried_forward_metric(previous_metric: dict, previous_snapshot: dict, dashboard_path: Path) -> dict:
    previous_value = previous_metric.get("value") if isinstance(previous_metric, dict) else previous_metric
    previous_source = previous_metric.get("source", "") if isinstance(previous_metric, dict) else ""
    previous_calculation = previous_metric.get("calculation", {}) if isinstance(previous_metric, dict) else {}
    previous_formula = ""
    previous_method = ""
    if isinstance(previous_calculation, dict):
        previous_formula = str(previous_calculation.get("formula") or "").strip()
        previous_method = str(previous_calculation.get("method") or "").strip()
    previous_generated_at = previous_snapshot.get("generated_at", "")
    carried_inputs = _previous_metric_inputs(previous_calculation)
    if not carried_inputs:
        carried_inputs = {"latest_available_kpi_value": previous_value}
    if previous_generated_at:
        carried_inputs["latest_available_snapshot_date"] = previous_generated_at
    if previous_source:
        carried_inputs["latest_available_source"] = previous_source
    return _metric(
        previous_value,
        computed=False,
        source="previous_snapshot",
        method="carried_forward",
        formula=previous_formula or "No new calculation was run; value carried forward from the previous snapshot.",
        source_files=[_rel(dashboard_path)],
        inputs=carried_inputs,
        fallback_reason="Current telemetry was missing, so the dashboard used the latest available KPI data from snapshot history.",
        notes=[
            "Current telemetry was missing, so the dashboard used the latest available KPI data from snapshot history.",
        ],
        extra={
            "previous_snapshot_id": previous_snapshot.get("snapshot_id", ""),
            "previous_generated_at": previous_generated_at,
            "previous_source": previous_source,
            "previous_method": previous_method,
        },
    )


def _not_available_metric() -> dict:
    return _metric(
        "NA",
        computed=False,
        source="not_available",
        method="not_available",
        fallback_reason="No telemetry, previous snapshot value, or table fallback data was available for this KPI.",
        notes=["This KPI will populate after the related ML model or page produces usable data."],
    )


def _migrate_dashboard_structure(data: dict) -> bool:
    if not isinstance(data, dict):
        return False

    snapshots = data.get("snapshots")
    if not isinstance(snapshots, list):
        return False

    changed = False
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        kpis = snapshot.get("kpis")
        if not isinstance(kpis, dict):
            continue

        core_ml = kpis.get("core_ml")
        if not isinstance(core_ml, dict):
            core_ml = {}
            kpis["core_ml"] = core_ml
            changed = True

        ml_uabv = kpis.get("ml_based_uabv")
        if not isinstance(ml_uabv, dict):
            ml_uabv = {}
            kpis["ml_based_uabv"] = ml_uabv
            changed = True

        old_behavior_metric = core_ml.get("behavior_model_accuracy_pct")
        if "behavior_model_accuracy_pct" not in ml_uabv and isinstance(old_behavior_metric, dict):
            ml_uabv["behavior_model_accuracy_pct"] = deepcopy(old_behavior_metric)
            changed = True

        if "average_behavior_risk_score" in ml_uabv:
            ml_uabv.pop("average_behavior_risk_score", None)
            changed = True

        if "model_accuracy_pct" not in core_ml:
            source_metric = core_ml.get("role_prediction_accuracy_pct")
            if isinstance(source_metric, dict):
                core_ml["model_accuracy_pct"] = deepcopy(source_metric)
            elif isinstance(old_behavior_metric, dict):
                core_ml["model_accuracy_pct"] = deepcopy(old_behavior_metric)
            else:
                core_ml["model_accuracy_pct"] = _not_available_metric()
            changed = True

        if "behavior_model_accuracy_pct" in core_ml:
            core_ml.pop("behavior_model_accuracy_pct", None)
            changed = True

    return changed


def resolve_kpi_value(
    *,
    year: int,
    inputs: dict,
    dashboard_data: dict,
    group_key: str,
    metric_key: str,
    telemetry_calculator: MetricCalculator | None,
    table_fallback_calculator: MetricCalculator | None,
) -> dict:
    if telemetry_calculator:
        metric = telemetry_calculator(inputs, year)
        if _has_metric_value(metric):
            return metric

    previous, previous_snapshot = _previous_metric(dashboard_data, year, group_key, metric_key)
    if previous is not None and previous_snapshot is not None:
        previous_source = ""
        if isinstance(previous, dict):
            previous_source = str(previous.get("source") or "").strip().lower()

        if not (
            group_key == "core_ml"
            and metric_key == "cia_prediction_accuracy_pct"
            and previous_source == "reset_audit"
        ):
            return _carried_forward_metric(previous, previous_snapshot, _aiml_dashboard_file(year))

    if table_fallback_calculator:
        metric = table_fallback_calculator(inputs, year)
        if _has_metric_value(metric):
            return metric

    return _not_available_metric()


def _prediction_pair_from_event(event: dict, predicted_key: str, final_key: str) -> tuple[str, str] | None:
    predicted = str(event.get(predicted_key) or event.get("predicted") or "").strip()
    final = str(
        event.get(final_key)
        or event.get("actual_role")
        or event.get("actual")
        or event.get("final")
        or ""
    ).strip()
    if not predicted or not final:
        return None
    return predicted, final


def _macro_f1(pairs: list[tuple[str, str]]) -> float | None:
    if not pairs:
        return None
    labels = sorted({truth for _, truth in pairs} | {pred for pred, _ in pairs})
    values = []
    for label in labels:
        tp = sum(1 for pred, truth in pairs if pred == label and truth == label)
        fp = sum(1 for pred, truth in pairs if pred == label and truth != label)
        fn = sum(1 for pred, truth in pairs if pred != label and truth == label)
        denom = (2 * tp) + fp + fn
        if denom > 0:
            values.append((2 * tp) / denom)
    if not values:
        return None
    return sum(values) / len(values)


def _role_accuracy_counts(inputs: dict) -> tuple[int, int]:
    events = _events(inputs, "role_prediction_events")
    if not events:
        return 0, 0

    evaluated = 0
    correct = 0
    for event in events:
        if isinstance(event.get("is_correct"), bool):
            evaluated += 1
            correct += 1 if event["is_correct"] else 0
            continue

        pair = _prediction_pair_from_event(event, "predicted_role", "final_role")
        if pair:
            evaluated += 1
            correct += 1 if _norm(pair[0]) == _norm(pair[1]) else 0

    return correct, evaluated


def _telemetry_role_accuracy(inputs: dict, year: int) -> dict | None:
    correct, evaluated = _role_accuracy_counts(inputs)
    if evaluated == 0:
        return None

    return _metric(
        _rounded((correct / evaluated) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="correct_predictions / total_predictions * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"correct_predictions": correct, "total_predictions": evaluated},
        notes=["Computed from current role prediction events."],
    )


def _telemetry_role_model_accuracy(inputs: dict, year: int) -> dict | None:
    latest = _latest_item(_events(inputs, "role_model_training_runs"))
    if latest:
        value = (
            _number(latest.get("accuracy_pct"))
            or _number(latest.get("accuracy_percent"))
            or _number(latest.get("accuracy"))
        )
        if value is not None:
            if value <= 1:
                value *= 100
            metric_inputs = {
                "run_id": latest.get("run_id", ""),
                "accuracy_pct": _rounded(value),
            }
            for key in ("server_accuracy_pct", "workstation_accuracy_pct"):
                extra_value = _number(latest.get(key))
                if extra_value is not None:
                    metric_inputs[key] = _rounded(extra_value)
            accuracy_source = str(latest.get("accuracy_source") or "").strip()
            if accuracy_source:
                metric_inputs["accuracy_source"] = accuracy_source
            return _metric(
                _rounded(value),
                computed=True,
                source="telemetry",
                method="current_telemetry",
                formula="latest role model evaluation accuracy",
                source_files=[_rel(_aiml_inputs_file(year))],
                inputs=metric_inputs,
                notes=["Used the latest role model training run in AIMLKPIInputs.json."],
            )

    correct, evaluated = _role_accuracy_counts(inputs)
    if evaluated == 0:
        return None

    accuracy = _rounded((correct / evaluated) * 100)
    return _metric(
        accuracy,
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="correct_predictions / total_predictions * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={
            "accuracy_pct": accuracy,
            "accuracy_source": "current_role_prediction_events_proxy",
            "correct_predictions": correct,
            "total_predictions": evaluated,
        },
        notes=[
            "No stored role model training accuracy was available, so the dashboard used current evaluated role predictions as the role-model accuracy indicator."
        ],
    )


def _telemetry_role_f1(inputs: dict, year: int) -> dict | None:
    latest = _latest_item(_events(inputs, "role_model_training_runs"))
    if latest:
        value = (
            _number(latest.get("macro_f1"))
            or _number(latest.get("f1_score"))
            or _number(latest.get("f1_score_role_model"))
        )
        if value is not None:
            return _metric(
                _rounded(value, 4),
                computed=True,
                source="telemetry",
                method="current_telemetry",
                formula="latest role model macro F1 from training telemetry",
                source_files=[_rel(_aiml_inputs_file(year))],
                inputs={"run_id": latest.get("run_id", ""), "macro_f1": value},
                notes=["Used the latest role model training run in AIMLKPIInputs.json."],
            )

    pairs = []
    for event in _events(inputs, "role_prediction_events"):
        pair = _prediction_pair_from_event(event, "predicted_role", "final_role")
        if pair:
            pairs.append((_norm(pair[0]), _norm(pair[1])))

    value = _macro_f1(pairs)
    if value is None:
        return None

    return _metric(
        _rounded(value, 4),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="macro average of per-role F1 scores",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"evaluated_predictions": len(pairs)},
        notes=["Computed from current role prediction telemetry because no training macro F1 was stored."],
    )


def _telemetry_cia_accuracy(inputs: dict, year: int) -> dict | None:
    events = _events(inputs, "cia_prediction_events")
    if not events:
        return None

    evaluated = 0
    correct = 0
    for event in events:
        if isinstance(event.get("is_correct"), bool):
            evaluated += 1
            correct += 1 if event["is_correct"] else 0
            continue

        pair = _prediction_pair_from_event(event, "predicted_cia", "final_cia")
        if pair:
            evaluated += 1
            correct += 1 if _norm(pair[0]) == _norm(pair[1]) else 0

    if evaluated == 0:
        return None

    return _metric(
        _rounded((correct / evaluated) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="correct CIA predictions / total CIA predictions * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"correct_predictions": correct, "total_predictions": evaluated},
        notes=["Computed from current CIA prediction events."],
    )


def _telemetry_behavior_accuracy(inputs: dict, year: int) -> dict | None:
    latest = _latest_item(_events(inputs, "behavior_model_training_runs"))
    if not latest:
        return None

    value = (
        _number(latest.get("accuracy_pct"))
        or _number(latest.get("accuracy_percent"))
        or _number(latest.get("accuracy"))
    )
    if value is None:
        return None
    if value <= 1:
        value *= 100

    return _metric(
        _rounded(value),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="latest behavior model evaluation accuracy",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"run_id": latest.get("run_id", ""), "accuracy_pct": value},
        notes=["Used the latest user behavior model training run in AIMLKPIInputs.json."],
    )


def _behavior_events(inputs: dict) -> list[dict]:
    return _events(inputs, "behavior_prediction_events")


def _behavior_scores(events: list[dict]) -> list[float]:
    values = []
    for event in events:
        value = (
            _number(event.get("behaviorRiskScore"))
            or _number(event.get("behavior_risk_score"))
            or _number(event.get("risk_score"))
        )
        if value is not None:
            values.append(value)
    return values


def _telemetry_average_behavior_score(inputs: dict, year: int) -> dict | None:
    events = _behavior_events(inputs)
    scores = _behavior_scores(events)
    if not scores:
        return None

    return _metric(
        _rounded(sum(scores) / len(scores), 4),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="sum(behaviorRiskScore) / total_behavior_predictions",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"total_behavior_predictions": len(scores)},
        notes=["Computed from current behavior prediction events."],
    )


def _telemetry_high_risk_user_pct(inputs: dict, year: int) -> dict | None:
    events = _behavior_events(inputs)
    scores = _behavior_scores(events)
    if not scores:
        return None

    high_risk = sum(1 for score in scores if score >= 0.60)
    return _metric(
        _rounded((high_risk / len(scores)) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="behaviorRiskScore >= 0.60 / total_behavior_predictions * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"high_risk_users": high_risk, "total_behavior_predictions": len(scores)},
        notes=["Computed from current behavior prediction events."],
    )


def _telemetry_ml_rule_difference(inputs: dict, year: int) -> dict | None:
    diffs = []
    for event in _behavior_events(inputs):
        ml_score = _number(event.get("ml_score"))
        rule_score = _number(event.get("rule_score"))
        if ml_score is not None and rule_score is not None:
            diffs.append(abs(ml_score - rule_score))

    if not diffs:
        return None

    return _metric(
        _rounded(sum(diffs) / len(diffs), 4),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="average(abs(ml_score - rule_score))",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"compared_behavior_predictions": len(diffs)},
        notes=["Computed from current behavior prediction events."],
    )


def _feature_bucket(feature: Any) -> str:
    text = _norm(feature)
    text = text.replace("num__", "").replace("cat__", "").replace("log_", "")
    mapping = [
        ("failedlogin", "failedLoginAttempts"),
        ("accessfrequency", "accessFrequency"),
        ("loginconsistency", "loginConsistency"),
        ("passwordreset", "passwordResets"),
        ("sessionduration", "sessionDuration"),
    ]
    compact = "".join(ch for ch in text if ch.isalnum())
    for token, label in mapping:
        if token in compact:
            return label
    return str(feature or "other").strip() or "other"


def _normalize_importances(raw_items: Any) -> dict[str, float]:
    counter: Counter[str] = Counter()
    if isinstance(raw_items, dict):
        iterable = raw_items.items()
    elif isinstance(raw_items, list):
        iterable = []
        for item in raw_items:
            if isinstance(item, dict):
                iterable.append((item.get("feature"), item.get("importance")))
    else:
        iterable = []

    for feature, importance in iterable:
        value = _number(importance)
        if value is not None:
            counter[_feature_bucket(feature)] += value

    total = sum(counter.values())
    if total <= 0:
        return {}

    return {
        key: _rounded((value / total) * 100)
        for key, value in sorted(counter.items(), key=lambda item: item[1], reverse=True)
    }


def _telemetry_top_feature_distribution(inputs: dict, year: int) -> dict | None:
    latest = _latest_item(_events(inputs, "behavior_model_training_runs"))
    if not latest:
        return None

    distribution = _normalize_importances(latest.get("feature_importance"))
    if not distribution:
        return None
    top_feature, top_share = max(distribution.items(), key=lambda item: item[1])

    return _metric(
        distribution,
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="feature_importance / sum(feature_importance) * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={
            "run_id": latest.get("run_id", ""),
            "top_feature": top_feature,
            "top_feature_contribution_pct": top_share,
            "total_feature_importance_pct": 100,
            "feature_count": len(distribution),
        },
        notes=["Computed from the latest behavior model feature importance telemetry."],
    )


def _telemetry_rag_query_count(inputs: dict, year: int) -> dict | None:
    counters = _rag_llm_counters(inputs)
    query_count = counters.get("rag_query_count", 0)
    if query_count > 0:
        return _metric(
            query_count,
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="rag_query_count",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={"rag_query_count": query_count},
            notes=["Computed from compact RAG counters in AIMLKPIInputs.json."],
        )

    events = _events(inputs, "rag_events")
    if not events:
        return None
    return _metric(
        len(events),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="count(rag_events)",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"rag_events": len(events)},
        notes=["Computed from current RAG telemetry events."],
    )


def _telemetry_retrieval_success_pct(inputs: dict, year: int) -> dict | None:
    counters = _rag_llm_counters(inputs)
    query_count = counters.get("rag_query_count", 0)
    success_count = counters.get("rag_success_count", 0)
    failure_count = counters.get("rag_failure_count", 0)
    evaluated = max(query_count, success_count + failure_count)
    if evaluated > 0:
        return _metric(
            _rounded((success_count / evaluated) * 100),
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="rag_success_count / rag_query_count * 100",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={
                "rag_success_count": success_count,
                "rag_failure_count": failure_count,
                "rag_query_count": query_count,
            },
            notes=["Computed from compact RAG success/failure counters in AIMLKPIInputs.json."],
        )

    events = _events(inputs, "rag_events")
    if not events:
        return None

    evaluated = 0
    success = 0
    for event in events:
        if isinstance(event.get("success"), bool):
            evaluated += 1
            success += 1 if event["success"] else 0
            continue
        retrieved = _number(event.get("retrieved_count"))
        if retrieved is not None:
            evaluated += 1
            success += 1 if retrieved > 0 else 0

    if evaluated == 0:
        return None

    return _metric(
        _rounded((success / evaluated) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="successful_retrievals / evaluated_rag_queries * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"successful_retrievals": success, "evaluated_rag_queries": evaluated},
        notes=["Computed from current RAG telemetry events."],
    )


def _telemetry_reasoning_calls(inputs: dict, year: int) -> dict | None:
    counters = _rag_llm_counters(inputs)
    reasoning_calls = counters.get("llm_reasoning_calls", 0)
    if reasoning_calls > 0:
        return _metric(
            reasoning_calls,
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="llm_reasoning_calls",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={"llm_reasoning_calls": reasoning_calls},
            notes=["Computed from compact LLM counters in AIMLKPIInputs.json."],
        )

    events = _events(inputs, "llm_events")
    if not events:
        return None
    return _metric(
        len(events),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="count(llm_events)",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"llm_events": len(events)},
        notes=["Computed from current LLM telemetry events."],
    )


def _telemetry_total_tokens(inputs: dict, year: int) -> dict | None:
    counters = _rag_llm_counters(inputs)
    reasoning_calls = counters.get("llm_reasoning_calls", 0)
    total_tokens = counters.get("llm_total_tokens", 0)
    if total_tokens > 0 or reasoning_calls > 0:
        return _metric(
            total_tokens,
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="llm_total_tokens",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={
                "llm_reasoning_calls": reasoning_calls,
                "llm_total_tokens": total_tokens,
            },
            notes=["Computed from compact LLM token counters in AIMLKPIInputs.json."],
        )

    total = 0
    counted = 0
    for event in _events(inputs, "llm_events"):
        value = (
            _number(event.get("total_tokens"))
            or _number(event.get("tokens"))
            or _number(event.get("eval_count"))
        )
        if value is not None:
            total += value
            counted += 1
    if counted == 0:
        return None

    return _metric(
        int(total),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="sum(total_tokens)",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"llm_events_with_token_counts": counted},
        notes=["Computed from current LLM telemetry events."],
    )


def _telemetry_manual_corrections(inputs: dict, year: int, correction_type: str) -> dict | None:
    counter_key = {
        "role": "manual_role_corrections",
        "risk": "manual_risk_corrections",
    }.get(correction_type)
    counters = _human_trust_counters(inputs)
    count = counters.get(counter_key or "", 0)
    if counter_key and count > 0:
        return _metric(
            count,
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula=counter_key,
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={counter_key: count},
            notes=["Computed from compact Human-in-the-loop counters in AIMLKPIInputs.json."],
        )

    events = [
        event
        for event in _events(inputs, "manual_correction_events")
        if _norm(event.get("correction_type")) == correction_type
    ]
    if not events:
        return None
    return _metric(
        len(events),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula=f"count(manual_correction_events where correction_type = {correction_type})",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"manual_corrections": len(events), "correction_type": correction_type},
        notes=["Computed from current manual correction telemetry."],
    )


def _telemetry_manual_role_corrections(inputs: dict, year: int) -> dict | None:
    return _telemetry_manual_corrections(inputs, year, "role")


def _telemetry_manual_risk_corrections(inputs: dict, year: int) -> dict | None:
    return _telemetry_manual_corrections(inputs, year, "risk")


def _telemetry_override_rate(inputs: dict, year: int) -> dict | None:
    counters = _human_trust_counters(inputs)
    evaluated_count = counters.get("evaluated_role_predictions", 0)
    override_count = counters.get("overridden_role_predictions", 0)
    if evaluated_count > 0:
        return _metric(
            _rounded((override_count / evaluated_count) * 100),
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="overridden_role_predictions / evaluated_role_predictions * 100",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={
                "overridden_role_predictions": override_count,
                "evaluated_role_predictions": evaluated_count,
            },
            notes=["Computed from compact Trust & Reliability counters in AIMLKPIInputs.json."],
        )

    events = _events(inputs, "role_prediction_events")
    if not events:
        return None

    evaluated = 0
    overrides = 0
    for event in events:
        is_override = event.get("is_override")
        if isinstance(is_override, bool):
            evaluated += 1
            overrides += 1 if is_override else 0
            continue

        pair = _prediction_pair_from_event(event, "predicted_role", "final_role")
        if pair:
            evaluated += 1
            overrides += 1 if _norm(pair[0]) != _norm(pair[1]) else 0

    if evaluated == 0:
        return None

    return _metric(
        _rounded((overrides / evaluated) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="overridden_predictions / evaluated_predictions * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"overridden_predictions": overrides, "evaluated_predictions": evaluated},
        notes=["Computed from current role prediction telemetry."],
    )


def _telemetry_low_confidence_pct(inputs: dict, year: int) -> dict | None:
    counters = _human_trust_counters(inputs)
    with_confidence = counters.get("predictions_with_confidence", 0)
    low_confidence = counters.get("low_confidence_predictions", 0)
    if with_confidence > 0:
        return _metric(
            _rounded((low_confidence / with_confidence) * 100),
            computed=True,
            source="telemetry",
            method="current_telemetry",
            formula="low_confidence_predictions / predictions_with_confidence * 100",
            source_files=[_rel(_aiml_inputs_file(year))],
            inputs={
                "low_confidence_predictions": low_confidence,
                "predictions_with_confidence": with_confidence,
            },
            notes=["Computed from compact Trust & Reliability counters in AIMLKPIInputs.json."],
        )

    confidences = []
    for event in _events(inputs, "role_prediction_events"):
        value = _number(event.get("confidence"))
        if value is not None:
            confidences.append(value)
    if not confidences:
        return None

    low = sum(1 for value in confidences if value < 0.60)
    return _metric(
        _rounded((low / len(confidences)) * 100),
        computed=True,
        source="telemetry",
        method="current_telemetry",
        formula="predictions with confidence < 0.60 / predictions with confidence * 100",
        source_files=[_rel(_aiml_inputs_file(year))],
        inputs={"low_confidence_predictions": low, "predictions_with_confidence": len(confidences)},
        notes=["Computed from current role prediction telemetry."],
    )


def _load_asset_inventory(year: int) -> dict | None:
    data = _read_json_if_exists(_asset_inventory_file(year))
    return data if isinstance(data, dict) else None


def _all_assets(inventory: dict | None) -> list[dict]:
    if not isinstance(inventory, dict):
        return []
    assets: list[dict] = []
    for key in ("assets", "hosts"):
        raw = inventory.get(key)
        if isinstance(raw, list):
            assets.extend(item for item in raw if isinstance(item, dict))
    for subnet in inventory.get("subnets", []):
        if not isinstance(subnet, dict):
            continue
        raw = subnet.get("assets")
        if not isinstance(raw, list):
            raw = subnet.get("hosts")
        if isinstance(raw, list):
            assets.extend(item for item in raw if isinstance(item, dict))
    return assets


def _first_list_value(value: Any) -> str:
    if isinstance(value, list) and value:
        return str(value[0] or "").strip()
    return str(value or "").strip()


def _asset_selected_role(asset: dict) -> str:
    detail = asset.get("detail") if isinstance(asset.get("detail"), dict) else {}
    selected = detail.get("selected_role") if isinstance(detail.get("selected_role"), dict) else {}
    return str(
        selected.get("role")
        or asset.get("role")
        or asset.get("asset_role")
        or asset.get("server_role")
        or asset.get("workstation_role")
        or ""
    ).strip()


def _asset_predicted_role(asset: dict) -> str:
    detail = asset.get("detail") if isinstance(asset.get("detail"), dict) else {}
    ml = detail.get("ml_role_prediction") if isinstance(detail.get("ml_role_prediction"), dict) else {}
    return _first_list_value(ml.get("predicted_roles") or ml.get("predicted_role"))


def _asset_role_pairs(year: int) -> list[tuple[str, str]]:
    inventory = _load_asset_inventory(year)
    pairs = []
    for asset in _all_assets(inventory):
        predicted = _asset_predicted_role(asset)
        final = _asset_selected_role(asset)
        if predicted and final:
            pairs.append((_norm(predicted), _norm(final)))
    return pairs


def _table_role_accuracy(inputs: dict, year: int) -> dict | None:
    pairs = _asset_role_pairs(year)
    if not pairs:
        return None
    correct = sum(1 for predicted, final in pairs if predicted == final)
    return _metric(
        _rounded((correct / len(pairs)) * 100),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="matching ML role predictions / evaluated assets * 100",
        source_files=[_rel(_asset_inventory_file(year))],
        inputs={"matching_predictions": correct, "evaluated_assets": len(pairs)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current table data, so it may be less accurate than saved model telemetry."],
    )


def _table_role_f1(inputs: dict, year: int) -> dict | None:
    pairs = _asset_role_pairs(year)
    value = _macro_f1(pairs)
    if value is None:
        return None
    return _metric(
        _rounded(value, 4),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="macro average of per-role F1 scores from current asset table predictions",
        source_files=[_rel(_asset_inventory_file(year))],
        inputs={"evaluated_assets": len(pairs)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current table data, so it may be less accurate than saved model telemetry."],
    )


def _table_cia_accuracy(inputs: dict, year: int) -> dict | None:
    inventory = _load_asset_inventory(year)
    assets = _all_assets(inventory)
    if not assets:
        return None

    valid = {"critical", "high", "medium", "low"}
    covered = 0
    for asset in assets:
        cia = asset.get("cia_rating") if isinstance(asset.get("cia_rating"), dict) else {}
        value = _norm(cia.get("criticality") if isinstance(cia, dict) else cia)
        if value in valid:
            covered += 1

    return _metric(
        _rounded((covered / len(assets)) * 100),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="assets with Critical/High/Medium/Low CIA rating / total assets * 100",
        source_files=[_rel(_asset_inventory_file(year))],
        inputs={"assets_with_cia_rating": covered, "total_assets": len(assets)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=[
            "No CIA prediction telemetry exists, so this is a CIA coverage proxy from the table.",
            "This is not true model accuracy.",
        ],
    )


def _risk_records(year: int) -> list[dict]:
    data = _read_json_if_exists(_risk_analysis_file(year))
    if not isinstance(data, dict):
        return []
    records = []
    for host in data.get("hosts", []):
        if not isinstance(host, dict):
            continue
        findings = host.get("findings")
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    merged = {**host, **finding}
                    records.append(merged)
        else:
            records.append(host)
    return records


def _table_behavior_events(year: int) -> list[dict]:
    result = []
    for record in _risk_records(year):
        ub = record.get("user_behavior")
        if isinstance(ub, dict):
            result.append(ub)
    return result


def _table_average_behavior_score(inputs: dict, year: int) -> dict | None:
    events = _table_behavior_events(year)
    scores = _behavior_scores(events)
    if not scores:
        return None
    return _metric(
        _rounded(sum(scores) / len(scores), 4),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="sum(behaviorRiskScore) / total_user_behavior_records",
        source_files=[_rel(_risk_analysis_file(year))],
        inputs={"total_user_behavior_records": len(scores)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current risk analysis table data."],
    )


def _table_high_risk_user_pct(inputs: dict, year: int) -> dict | None:
    events = _table_behavior_events(year)
    scores = _behavior_scores(events)
    if not scores:
        return None
    high_risk = sum(1 for score in scores if score >= 0.60)
    return _metric(
        _rounded((high_risk / len(scores)) * 100),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="behaviorRiskScore >= 0.60 / total_user_behavior_records * 100",
        source_files=[_rel(_risk_analysis_file(year))],
        inputs={"high_risk_users": high_risk, "total_user_behavior_records": len(scores)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current risk analysis table data."],
    )


def _table_ml_rule_difference(inputs: dict, year: int) -> dict | None:
    diffs = []
    for event in _table_behavior_events(year):
        ml_score = _number(event.get("ml_score"))
        rule_score = _number(event.get("rule_score"))
        if ml_score is not None and rule_score is not None:
            diffs.append(abs(ml_score - rule_score))
    if not diffs:
        return None
    return _metric(
        _rounded(sum(diffs) / len(diffs), 4),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="average(abs(ml_score - rule_score))",
        source_files=[_rel(_risk_analysis_file(year))],
        inputs={"compared_user_behavior_records": len(diffs)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current risk analysis table data."],
    )


def _table_feature_distribution(inputs: dict, year: int) -> dict | None:
    path = _feature_importance_file()
    if not path.exists():
        return None

    items = []
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                items.append({
                    "feature": row.get("feature"),
                    "importance": row.get("importance"),
                })
    except Exception:
        return None

    distribution = _normalize_importances(items)
    if not distribution:
        return None
    top_feature, top_share = max(distribution.items(), key=lambda item: item[1])

    return _metric(
        distribution,
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="feature_importance / sum(feature_importance) * 100",
        source_files=[_rel(path)],
        inputs={
            "top_feature": top_feature,
            "top_feature_contribution_pct": top_share,
            "total_feature_importance_pct": 100,
            "feature_count": len(distribution),
        },
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from the available feature importance file."],
    )


def _table_manual_role_corrections(inputs: dict, year: int) -> dict | None:
    inventory = _load_asset_inventory(year)
    assets = _all_assets(inventory)
    if not assets:
        return None
    count = 0
    for asset in assets:
        detail = asset.get("detail") if isinstance(asset.get("detail"), dict) else {}
        selected = detail.get("selected_role") if isinstance(detail.get("selected_role"), dict) else {}
        if _norm(selected.get("method")) == "manual":
            count += 1
    return _metric(
        count,
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="count(selected_role.method = manual)",
        source_files=[_rel(_asset_inventory_file(year))],
        inputs={"manual_role_corrections": count},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current asset inventory table data."],
    )


def _table_manual_risk_corrections(inputs: dict, year: int) -> dict | None:
    records = _risk_records(year)
    if not records:
        return None
    count = sum(1 for record in records if bool(record.get("override")))
    return _metric(
        count,
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="count(risk records where override is true)",
        source_files=[_rel(_risk_analysis_file(year))],
        inputs={"manual_risk_corrections": count},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current risk analysis table data."],
    )


def _table_override_rate(inputs: dict, year: int) -> dict | None:
    records = _risk_records(year)
    if not records:
        return None
    overrides = sum(1 for record in records if bool(record.get("override")))
    return _metric(
        _rounded((overrides / len(records)) * 100),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="override records / total risk records * 100",
        source_files=[_rel(_risk_analysis_file(year))],
        inputs={"override_records": overrides, "total_risk_records": len(records)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current risk analysis table data."],
    )


def _table_low_confidence_pct(inputs: dict, year: int) -> dict | None:
    inventory = _load_asset_inventory(year)
    confidences = []
    for asset in _all_assets(inventory):
        detail = asset.get("detail") if isinstance(asset.get("detail"), dict) else {}
        ml = detail.get("ml_role_prediction") if isinstance(detail.get("ml_role_prediction"), dict) else {}
        value = _number(ml.get("confidence"))
        if value is not None:
            confidences.append(value)
    if not confidences:
        return None
    low = sum(1 for value in confidences if value < 0.60)
    return _metric(
        _rounded((low / len(confidences)) * 100),
        computed=True,
        source="table_fallback",
        method="available_table_data",
        formula="ML role predictions with confidence < 0.60 / predictions with confidence * 100",
        source_files=[_rel(_asset_inventory_file(year))],
        inputs={"low_confidence_predictions": low, "predictions_with_confidence": len(confidences)},
        fallback_reason="No telemetry or previous KPI value existed.",
        notes=["This is derived from current asset inventory table data."],
    )


TELEMETRY_CALCULATORS: dict[str, dict[str, MetricCalculator]] = {
    "core_ml": {
        "role_prediction_accuracy_pct": _telemetry_role_accuracy,
        "model_accuracy_pct": _telemetry_role_model_accuracy,
        "cia_prediction_accuracy_pct": _telemetry_cia_accuracy,
        "f1_score_role_model": _telemetry_role_f1,
    },
    "ml_based_uabv": {
        "behavior_model_accuracy_pct": _telemetry_behavior_accuracy,
        "high_risk_user_percentage_pct": _telemetry_high_risk_user_pct,
        "score_difference_ml_vs_rule": _telemetry_ml_rule_difference,
        "top_contributing_feature_distribution_pct": _telemetry_top_feature_distribution,
    },
    "rag_performance": {
        "rag_query_count": _telemetry_rag_query_count,
        "retrieval_success_rate_pct": _telemetry_retrieval_success_pct,
    },
    "llm_performance": {
        "reasoning_calls": _telemetry_reasoning_calls,
        "total_tokens": _telemetry_total_tokens,
    },
    "human_in_the_loop": {
        "manual_role_corrections": _telemetry_manual_role_corrections,
        "manual_risk_corrections": _telemetry_manual_risk_corrections,
    },
    "trust_reliability": {
        "override_rate_pct": _telemetry_override_rate,
        "low_confidence_predictions_pct": _telemetry_low_confidence_pct,
    },
}


TABLE_FALLBACK_CALCULATORS: dict[str, dict[str, MetricCalculator]] = {
    "core_ml": {
        "role_prediction_accuracy_pct": _table_role_accuracy,
        "model_accuracy_pct": _table_role_accuracy,
        "cia_prediction_accuracy_pct": _table_cia_accuracy,
        "f1_score_role_model": _table_role_f1,
    },
    "ml_based_uabv": {
        "high_risk_user_percentage_pct": _table_high_risk_user_pct,
        "score_difference_ml_vs_rule": _table_ml_rule_difference,
        "top_contributing_feature_distribution_pct": _table_feature_distribution,
    },
    "human_in_the_loop": {
        "manual_role_corrections": _table_manual_role_corrections,
        "manual_risk_corrections": _table_manual_risk_corrections,
    },
    "trust_reliability": {
        "override_rate_pct": _table_override_rate,
        "low_confidence_predictions_pct": _table_low_confidence_pct,
    },
}


def _latest_previous_snapshot(data: dict, year: int) -> dict:
    snapshots = _snapshots_newest_first(data, year)
    return snapshots[0] if snapshots else {}


def _llm_display_info(raw: Any = None) -> dict:
    data = raw if isinstance(raw, dict) else {}
    return {
        "model": "Qwen3.8 27B",
        "version": "Qwen3.8 27B",
        "parameters": "27B",
        "deployment_style": "Local LLM - Llama",
    }


def _dataset_source_bucket(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"real", "actual", "live", "production"}:
        return "real"
    if text in {"synthetic", "simulated", "generated", "sample"}:
        return "synthetic"
    if text in {"true", "1", "yes"}:
        return "synthetic"
    if text in {"false", "0", "no"}:
        return "real"
    return "unknown"


def _empty_dataset_record(path: Path | None = None, note: str = "") -> dict:
    record = {
        "total_records": 0,
        "synthetic_records": 0,
        "real_records": 0,
        "unknown_records": 0,
        "source_file": _rel(path) if path else "",
        "last_modified": "",
        "notes": [],
    }
    if path and path.exists():
        record["last_modified"] = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    if note:
        record["notes"].append(note)
    return record


def _count_dataset_file(path: Path, default_source: str = "unknown") -> dict:
    if not path.exists():
        return _empty_dataset_record(path, f"Dataset file was not found: {_rel(path)}")

    record = _empty_dataset_record(path)
    source_counts = {"synthetic": 0, "real": 0, "unknown": 0}

    try:
        if path.suffix.lower() == ".parquet":
            import pandas as pd

            df = pd.read_parquet(path)
            total = int(len(df))
            source_column = next(
                (name for name in ("data_source", "record_source", "source", "is_synthetic") if name in df.columns),
                "",
            )
            if source_column:
                for value in df[source_column].tolist():
                    source_counts[_dataset_source_bucket(value)] += 1
            else:
                source_counts[_dataset_source_bucket(default_source)] = total
                record["notes"].append(
                    f"No source column was found; counted records as {default_source}."
                )
        else:
            with path.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []
                source_column = next(
                    (name for name in ("data_source", "record_source", "source", "is_synthetic") if name in fieldnames),
                    "",
                )
                total = 0
                for row in reader:
                    total += 1
                    bucket = _dataset_source_bucket(row.get(source_column)) if source_column else _dataset_source_bucket(default_source)
                    source_counts[bucket] += 1
                if not source_column:
                    record["notes"].append(
                        f"No source column was found; counted records as {default_source}."
                    )

        record.update({
            "total_records": total,
            "synthetic_records": source_counts["synthetic"],
            "real_records": source_counts["real"],
            "unknown_records": source_counts["unknown"],
        })
        return record
    except Exception as e:
        return _empty_dataset_record(path, f"Failed to count dataset rows: {e}")


def _first_existing_dataset_file(*names: str) -> Path:
    for name in names:
        path = _ml_dir() / name
        if path.exists():
            return path
    return _ml_dir() / names[0]


def _build_dataset_provenance() -> dict:
    datasets = {
        "server_role_training_dataset": _count_dataset_file(
            _first_existing_dataset_file(
                "server_role_training_dataset.parquet",
                "server_role_training_dataset.csv",
            ),
            default_source="synthetic",
        ),
        "workstation_role_training_dataset": _count_dataset_file(
            _first_existing_dataset_file(
                "workstation_role_training_dataset.parquet",
                "workstation_role_training_dataset.csv",
            ),
            default_source="synthetic",
        ),
        "user_behavior_training_dataset": _count_dataset_file(
            _first_existing_dataset_file("user_behavior_training_dataset.parquet"),
            default_source="synthetic",
        ),
    }

    summary = {
        "total_records_all_datasets": sum(int(item.get("total_records", 0) or 0) for item in datasets.values()),
        "synthetic_records_all_datasets": sum(int(item.get("synthetic_records", 0) or 0) for item in datasets.values()),
        "real_records_all_datasets": sum(int(item.get("real_records", 0) or 0) for item in datasets.values()),
        "unknown_records_all_datasets": sum(int(item.get("unknown_records", 0) or 0) for item in datasets.values()),
    }

    return {
        "summary": summary,
        "datasets": datasets,
        "computed_at": _now_local().isoformat(timespec="seconds"),
        "source": "current_dataset_files",
    }


def _build_kpis(year: int, inputs: dict, dashboard_data: dict) -> dict:
    kpis: dict[str, dict] = {}
    for group_config in KPI_GROUPS:
        group_key = str(group_config["json_key"])
        kpis[group_key] = {}
        for metric_key, _title, _accent in group_config["metrics"]:
            metric = resolve_kpi_value(
                year=year,
                inputs=inputs,
                dashboard_data=dashboard_data,
                group_key=group_key,
                metric_key=metric_key,
                telemetry_calculator=TELEMETRY_CALCULATORS.get(group_key, {}).get(metric_key),
                table_fallback_calculator=TABLE_FALLBACK_CALCULATORS.get(group_key, {}).get(metric_key),
            )
            kpis[group_key][metric_key] = _enhance_metric_for_modal(group_key, metric_key, metric)
    return kpis


def _snapshot_id(now: datetime) -> str:
    return f"kpi_{now.strftime('%Y-%m-%d_%H-%M-%S')}"


def _is_recent_api_snapshot(snapshot: dict, now: datetime) -> bool:
    if snapshot.get("creation_source") != "api_snapshot_on_open":
        return False
    generated_at = _parse_datetime(snapshot.get("generated_at"))
    if not generated_at:
        return False
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=now.tzinfo)
    return abs(now - generated_at) <= timedelta(seconds=10)


def _build_snapshot(year: int, inputs: dict, dashboard_data: dict, now: datetime) -> dict:
    previous = _latest_previous_snapshot(dashboard_data, year)
    inventory = _load_asset_inventory(year)
    asset_count = len(_all_assets(inventory))

    previous_scope = previous.get("scope", {}) if isinstance(previous.get("scope"), dict) else {}
    scope = {
        "name": previous_scope.get("name", "AI/ML Dashboard"),
        "asset_count": asset_count or previous_scope.get("asset_count", 0),
    }

    return {
        "snapshot_id": _snapshot_id(now),
        "generated_at": now.isoformat(timespec="seconds"),
        "creation_source": "api_snapshot_on_open",
        "year": year,
        "scope": scope,
        "kpis": _build_kpis(year, inputs, dashboard_data),
        "dataset_provenance": _build_dataset_provenance(),
        "rag": previous.get("rag", {
            "vector_database": "ChromaDB",
            "text_embedding_model": "nomic-embed-text:latest",
        }),
        "llm": _llm_display_info(previous.get("llm")),
    }


def _build_kpi_groups(snapshot: dict) -> list[dict]:
    kpis = snapshot.get("kpis", {})
    if not isinstance(kpis, dict):
        kpis = {}

    groups = []
    for group_config in KPI_GROUPS:
        source_group = kpis.get(group_config["json_key"], {})
        if not isinstance(source_group, dict):
            source_group = {}

        metrics = []
        for json_key, title, accent in group_config["metrics"]:
            source_metric = source_group.get(json_key)
            if isinstance(source_metric, dict):
                source_metric = _enhance_metric_for_modal(
                    str(group_config["json_key"]),
                    json_key,
                    deepcopy(source_metric),
                )
            detail = _metric_detail(source_metric)
            metrics.append({
                "key": json_key,
                "title": title,
                "value": detail["value"],
                "accent": accent,
                "computed": detail["computed"],
                "source": detail["source"],
                "raw_value": detail["raw_value"],
                "calculation": detail["calculation"],
            })

        groups.append({
            "group": group_config["group"],
            "json_key": group_config["json_key"],
            "metrics": metrics,
        })

    return groups


def _normalize_dashboard_response(data: dict, snapshot: dict, path: Path) -> dict:
    return {
        "success": True,
        "source_file": str(path),
        "meta": data.get("meta", {}),
        "latest_snapshot_id": data.get("latest_snapshot_id", ""),
        "available_snapshots": [
            {
                "snapshot_id": item.get("snapshot_id", ""),
                "generated_at": item.get("generated_at", ""),
                "year": item.get("year"),
                "creation_source": item.get("creation_source", ""),
            }
            for item in data.get("snapshots", [])
            if isinstance(item, dict)
        ],
        "snapshot_id": snapshot.get("snapshot_id", ""),
        "generated_at": snapshot.get("generated_at", ""),
        "year": snapshot.get("year"),
        "scope": snapshot.get("scope", {}),
        "kpis": snapshot.get("kpis", {}),
        "kpi_groups": _build_kpi_groups(snapshot),
        "dataset_provenance": snapshot.get("dataset_provenance", {}),
        "rag": snapshot.get("rag", {}),
        "llm": _llm_display_info(snapshot.get("llm")),
        "snapshot": snapshot,
    }


@router.get("/raw")
def get_aiml_dashboard_raw(year: int = Query(2026)):
    path = _aiml_dashboard_file(int(year))
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"AIMLDashboard.json not found: {path}",
        )

    data = _load_dashboard_data(int(year))
    snapshot = _snapshot_for_year(data, int(year))
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"No AI/ML dashboard snapshot found for {year}.")

    return _normalize_dashboard_response(data, snapshot, path)


@router.post("/snapshot")
def create_aiml_dashboard_snapshot(year: int = Query(2026)):
    resolved_year = int(year)
    path = _aiml_dashboard_file(resolved_year)
    data = _load_dashboard_data(resolved_year)
    now = _now_local()

    latest = _snapshot_for_year(data, resolved_year)
    if latest and _is_recent_api_snapshot(latest, now):
        return _normalize_dashboard_response(data, latest, path)

    inputs = _load_or_create_inputs_data(resolved_year)
    snapshot = _build_snapshot(resolved_year, inputs, data, now)

    data.setdefault("snapshots", [])
    data["snapshots"].append(snapshot)
    data["latest_snapshot_id"] = snapshot["snapshot_id"]
    _atomic_write_json(path, data)

    return _normalize_dashboard_response(data, snapshot, path)
