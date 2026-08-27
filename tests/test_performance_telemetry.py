from __future__ import annotations

import json
import queue
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.api import performance_telemetry as telemetry
from app.api.aiml_kpi_telemetry import ollama_total_tokens


EXPECTED_IDS = [
    "rag.kb_rebuild",
    "rag.shared_chroma_query",
    "rag.api_query",
    "assets.role_chroma",
    "threats.cve_format",
    "threats.mitigation_generate",
    "risk_eval.monitoring_fields",
    "risk_eval.monitoring_justification",
    "annex.rank_control_query_embed",
    "annex.rank_cve_candidate_embed",
    "annex.infer_controls_embed",
    "annex.catalog_batch_embed",
    "annex.retrieve_controls",
    "annex.control_info",
    "annex.row_justification_primary",
    "annex.row_justification_json_retry",
    "annex.row_justification_repair",
    "annex.row_justification_simple",
    "annex.select_controls",
    "action_plan.retrieve_controls",
    "action_plan.treatment_primary",
    "action_plan.treatment_repair",
    "action_plan.evidence_recommendations",
    "action_plan.evidence_description",
    "action_plan.implementation_steps",
    "monitoring.user_behavior_action",
    "monitoring.real_steps",
    "monitoring.evidence_description",
    "monitoring.bulk_evidence_descriptions",
    "monitoring.justification",
    "monitoring.query_embedding",
    "monitoring.record_embedding",
    "monitoring.retrieve_controls",
    "monitoring.action_primary",
    "monitoring.action_repair",
    "monitoring.evidence_recommendations",
]

EXPECTED_SECTIONS = {
    "RAG Infrastructure",
    "Asset Inventory & CIA",
    "Threats & Vulnerabilities",
    "Risk Evaluation & Treatment",
    "Annex A & SoA",
    "Action Plan & Implementation",
    "Monitoring & Improvement",
}

EXPECTED_KINDS = {"LLM Reasoning", "RAG Retrieval", "Embedding", "Retry/Repair"}

PROJECT_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_QWEN_MODEL_DECLARATIONS = [
    ("app/api/routes_threat_vulnerabilities.py", 'LLM_MODEL = "qwen3.8:27b"'),
    ("app/api/routes_risk_evaluation_treatment.py", 'LLM_MODEL = "qwen3.8:27b"'),
    ("app/api/routes_annex_a_soa.py", 'LLM_MODEL = os.getenv("ANNEX_LLM_MODEL", "qwen3.8:27b")'),
    ("app/api/routes_action_plan_implementation.py", 'OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.8:27b")'),
    ("app/api/routes_monitoring_improvement.py", 'OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.8:27b")'),
]

EXPECTED_GENERATION_PARAMETER_INVENTORY = {
    "threats.cve_format": (0.2, 0.9, "300"),
    "threats.mitigation_generate": (0.1, 0.9, "200"),
    "risk_eval.monitoring_fields": (0.2, 0.9, "300"),
    "risk_eval.monitoring_justification": (0.15, 0.85, "220"),
    "annex.control_info": (0.2, 0.9, "400"),
    "annex.row_justification_primary": (0.25, 0.9, "600"),
    "annex.row_justification_json_retry": (0.3, 0.9, "600"),
    "annex.row_justification_repair": (0.25, 0.9, "600"),
    "annex.row_justification_simple": (0.2, 0.9, "600"),
    "action_plan.treatment_primary": (0.1, 0.9, "220"),
    "action_plan.treatment_repair": (0.05, 0.9, "220"),
    "action_plan.evidence_recommendations": (0.1, 0.9, "90"),
    "action_plan.implementation_steps": (0.1, 0.9, "900"),
    "monitoring.user_behavior_action": (0.1, 0.9, "90"),
    "monitoring.real_steps": (0.1, 0.9, "900"),
    "monitoring.evidence_description": (0.1, 0.9, "90"),
    "monitoring.bulk_evidence_descriptions": (0.1, 0.9, r"max\(220, len\(host_lines\) \* 80\)"),
    "monitoring.justification": (0.2, 0.9, "300"),
    "monitoring.action_primary": (0.25, 0.9, "600"),
    "monitoring.action_repair": (0.2, 0.9, "600"),
    "monitoring.evidence_recommendations": (0.2, 0.9, "300"),
}


class PerformanceTelemetryTests(unittest.TestCase):
    def test_catalog_represents_all_execution_points(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(telemetry, "DATA_WORK_DIR", Path(temp_dir)):
                ids = [point.id for point in telemetry.EXECUTION_POINTS]
                self.assertEqual(ids, EXPECTED_IDS)
                self.assertEqual(len(ids), 36)
                self.assertEqual(len(set(ids)), 36)
                self.assertEqual({point.section for point in telemetry.EXECUTION_POINTS}, EXPECTED_SECTIONS)
                self.assertEqual({point.kind for point in telemetry.EXECUTION_POINTS}, EXPECTED_KINDS)
                self.assertTrue(all(point.slow_threshold_ms > 0 for point in telemetry.EXECUTION_POINTS))

                dashboard = telemetry.get_performance_dashboard(2026)
                self.assertEqual(dashboard["catalogCoverage"], {"represented": 36, "total": 36})
                self.assertEqual(len(dashboard["records"]), 36)
                self.assertEqual(dashboard["modelSummaries"][0]["model"], "qwen3.8:27b")
                self.assertEqual(dashboard["modelSummaries"][0]["callCount"], 0)
                self.assertEqual({record["status"] for record in dashboard["records"]}, {"Not Run"})
                self.assertEqual(dashboard["summary"]["totalExecutionPoints"], 36)
                self.assertEqual(dashboard["summary"]["totalObservedDurationMs"], 0)
                self.assertEqual(len(dashboard["sectionSummaries"]), 7)

    def test_span_records_success_event_and_dashboard_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with telemetry.performance_span(year=2026, operation_id="threats.cve_format") as span:
                    span.set_total_tokens(824)

                telemetry.flush_performance_telemetry()

                path = data_dir / "2026" / "PerformanceTelemetry.json"
                self.assertTrue(path.exists())

                stored = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(stored["meta"]["name"], "Performance_Telemetry")
                self.assertEqual(stored["meta"]["year"], 2026)
                self.assertEqual(stored["meta"]["max_events"], telemetry.PERFORMANCE_TELEMETRY_MAX_EVENTS)
                self.assertEqual(len(stored["events"]), 1)

                event = stored["events"][0]
                self.assertEqual(event["operation_id"], "threats.cve_format")
                self.assertEqual(event["outcome"], "Success")
                self.assertIsNone(event["error_type"])
                self.assertEqual(event["total_tokens"], 824)
                self.assertGreaterEqual(event["duration_ms"], 0)
                self.assertTrue(event["started_at"].endswith("Z"))

                dashboard = telemetry.get_performance_dashboard(2026)
                record = next(item for item in dashboard["records"] if item["id"] == "threats.cve_format")
                self.assertEqual(record["callCount"], 1)
                self.assertEqual(record["successCount"], 1)
                self.assertEqual(record["failureCount"], 0)
                self.assertEqual(record["status"], "Healthy")
                self.assertEqual(record["totalDurationMs"], event["duration_ms"])

    def test_span_records_exception_class_and_reraises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with self.assertRaises(ValueError):
                    with telemetry.performance_span(year=2026, operation_id="annex.select_controls"):
                        raise ValueError("sensitive message must not be stored")

                telemetry.flush_performance_telemetry()
                stored = json.loads((data_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8"))
                event = stored["events"][0]
                self.assertEqual(event["outcome"], "Failed")
                self.assertEqual(event["error_type"], "ValueError")
                self.assertNotIn("sensitive message", json.dumps(event))
                record = next(
                    item
                    for item in telemetry.get_performance_dashboard(2026)["records"]
                    if item["id"] == "annex.select_controls"
                )
                self.assertEqual(record["status"], "Failed")
                self.assertEqual(record["failureCount"], 1)

    def test_malformed_file_is_backed_up_and_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            path = data_dir / "2026" / "PerformanceTelemetry.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{not valid json", encoding="utf-8")

            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with telemetry.performance_span(year=2026, operation_id="rag.api_query"):
                    pass
                telemetry.flush_performance_telemetry()

                self.assertTrue(path.exists())
                backups = list(path.parent.glob("PerformanceTelemetry.json.malformed.*.bak"))
                self.assertEqual(len(backups), 1)
                stored = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(len(stored["events"]), 1)

    def test_unknown_execution_point_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry.record_event_safe(
                    {
                        "event_id": "bad",
                        "operation_id": "unknown-execution-point",
                        "started_at": "2026-08-25T12:34:56.123Z",
                        "duration_ms": 999,
                        "outcome": "Failed",
                        "error_type": "RuntimeError",
                        "_year": 2026,
                    }
                )
                telemetry.flush_performance_telemetry()

                self.assertFalse((data_dir / "2026" / "PerformanceTelemetry.json").exists())

    def test_storage_failure_does_not_affect_wrapped_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(telemetry, "DATA_WORK_DIR", Path(temp_dir)):
                with patch.object(telemetry, "_atomic_write_json", side_effect=OSError("disk full")):
                    with telemetry.performance_span(year=2026, operation_id="rag.api_query"):
                        value = {"ok": True}
                    telemetry.flush_performance_telemetry()
                self.assertEqual(value, {"ok": True})

    def test_disabled_telemetry_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with patch.object(telemetry, "PERFORMANCE_TELEMETRY_ENABLED", False):
                    with telemetry.performance_span(year=2026, operation_id="rag.api_query"):
                        pass
                    telemetry.flush_performance_telemetry()
                self.assertFalse((data_dir / "2026" / "PerformanceTelemetry.json").exists())

    def test_queue_full_does_not_block_or_raise(self) -> None:
        full_queue: queue.Queue[dict] = queue.Queue(maxsize=1)
        full_queue.put_nowait({"already": "full"})
        event = {
            "event_id": "queued",
            "operation_id": "rag.api_query",
            "started_at": "2026-08-25T12:34:56.123Z",
            "duration_ms": 1,
            "outcome": "Success",
            "error_type": None,
            "_year": 2026,
        }
        with patch.object(telemetry, "_event_queue", full_queue):
            with patch.object(telemetry, "start_performance_writer", return_value=None):
                before = telemetry._dropped_event_count
                telemetry.record_event_safe(event)
                self.assertEqual(telemetry._dropped_event_count, before + 1)

    def test_stored_history_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            events = [
                {
                    "event_id": str(idx),
                    "operation_id": "rag.api_query",
                    "started_at": f"2026-08-25T12:34:5{idx}.123Z",
                    "duration_ms": idx,
                    "outcome": "Success",
                    "error_type": None,
                    "_year": 2026,
                }
                for idx in range(5)
            ]
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with patch.object(telemetry, "PERFORMANCE_TELEMETRY_MAX_EVENTS", 3):
                    telemetry._write_event_batch(events)
                stored = json.loads((data_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8"))
                self.assertEqual([event["event_id"] for event in stored["events"]], ["2", "3", "4"])

    def test_malformed_events_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry._write_event_batch([
                    {"operation_id": "rag.api_query", "duration_ms": -1},
                    {"operation_id": "unknown", "duration_ms": 2},
                ])
                self.assertFalse((data_dir / "2026" / "PerformanceTelemetry.json").exists())

    def test_aggregation_uses_nearest_rank_p95_and_latest_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            events = [
                {
                    "event_id": str(idx),
                    "operation_id": "rag.api_query",
                    "started_at": f"2026-08-25T12:34:5{idx}.123Z",
                    "duration_ms": duration,
                    "outcome": "Success",
                    "error_type": None,
                    "_year": 2026,
                }
                for idx, duration in enumerate([10, 20, 30, 40])
            ]
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry._write_event_batch(events)
                record = next(
                    item
                    for item in telemetry.get_performance_dashboard(2026)["records"]
                    if item["id"] == "rag.api_query"
                )
                self.assertEqual(record["callCount"], 4)
                self.assertEqual(record["averageDurationMs"], 25)
                self.assertEqual(record["p95DurationMs"], 40)
                self.assertEqual(record["totalDurationMs"], 100)
                self.assertEqual(record["lastDurationMs"], 40)
                self.assertEqual(record["lastRunAt"], "2026-08-25T12:34:53.123Z")

    def test_endpoint_contract_and_router_registration(self) -> None:
        from app.main import app

        dashboard = telemetry.get_performance_dashboard(2026)
        self.assertIn("catalogCoverage", dashboard)
        self.assertIn("summary", dashboard)
        self.assertIn("sectionSummaries", dashboard)
        self.assertIn("records", dashboard)
        self.assertEqual(dashboard["catalogCoverage"]["total"], 36)
        self.assertEqual(
            [route.path for route in app.routes if "performance-dashboard" in route.path],
            ["/api/performance-dashboard"],
        )

    def test_reset_performance_telemetry_clears_dashboard_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry._write_event_batch([
                    {
                        "event_id": "before-reset",
                        "operation_id": "threats.cve_format",
                        "started_at": "2026-08-25T12:34:50.123Z",
                        "duration_ms": 100,
                        "outcome": "Success",
                        "error_type": None,
                        "_year": 2026,
                    },
                ])
                before = next(
                    item
                    for item in telemetry.get_performance_dashboard(2026)["records"]
                    if item["id"] == "threats.cve_format"
                )
                self.assertEqual(before["callCount"], 1)

                reset_path = telemetry.reset_performance_telemetry(2026)
                stored = json.loads(reset_path.read_text(encoding="utf-8"))
                self.assertEqual(stored["events"], [])

                dashboard = telemetry.get_performance_dashboard(2026)
                self.assertEqual({record["status"] for record in dashboard["records"]}, {"Not Run"})
                self.assertEqual(dashboard["summary"]["totalObservedDurationMs"], 0)
                self.assertEqual(dashboard["modelSummaries"][0]["model"], "qwen3.8:27b")
                self.assertTrue(dashboard["modelSummaries"][0]["configured"])

    def test_start_new_audit_resets_performance_telemetry(self) -> None:
        from app.api import routes_dashboard

        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            data_work_dir = base_dir / "data" / "work"
            with (
                patch.object(routes_dashboard, "BASE_DIR", base_dir),
                patch.object(telemetry, "DATA_WORK_DIR", data_work_dir),
            ):
                telemetry._write_event_batch([
                    {
                        "event_id": "before-start-new-audit",
                        "operation_id": "action_plan.treatment_primary",
                        "started_at": "2026-08-25T12:34:50.123Z",
                        "duration_ms": 250,
                        "outcome": "Success",
                        "error_type": None,
                        "_year": 2026,
                    },
                ])

                routes_dashboard.reset_audit(routes_dashboard.ResetAuditRequest(year=2026))

                stored = json.loads(
                    (data_work_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8")
                )
                self.assertEqual(stored["events"], [])
                dashboard = telemetry.get_performance_dashboard(2026)
                self.assertEqual(dashboard["summary"]["totalObservedDurationMs"], 0)
                self.assertEqual({record["callCount"] for record in dashboard["records"]}, {0})

    def test_no_sensitive_content_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with self.assertRaises(RuntimeError):
                    with telemetry.performance_span(year=2026, operation_id="threats.cve_format"):
                        raise RuntimeError("hostname CVE-2026-0001 prompt response retrieved document")
                telemetry.flush_performance_telemetry()
                stored = (data_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8")
                self.assertNotIn("hostname", stored)
                self.assertNotIn("CVE-2026-0001", stored)
                self.assertNotIn("sensitive message", stored)
                self.assertNotIn("response", stored)
                self.assertNotIn("retrieved document", stored)

    def test_existing_aiml_token_counter_helper_still_works(self) -> None:
        self.assertEqual(ollama_total_tokens({"prompt_eval_count": 10, "eval_count": 20}), 30)

    def test_safe_llm_configuration_whitelists_parameters_only(self) -> None:
        config = telemetry.safe_llm_configuration(
            model="qwen3.8:27b",
            payload={
                "model": "qwen3.8:27b",
                "prompt": "do not persist",
                "stream": False,
                "format": "json",
                "keep_alive": "10m",
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 220,
                    "private": "do not persist",
                },
            },
        )

        self.assertEqual(config["provider"], "Ollama")
        self.assertEqual(config["model"], "qwen3.8:27b")
        self.assertEqual(config["model_family"], "Qwen3.8")
        self.assertEqual(config["model_tag"], "27b")
        self.assertEqual(config["parameter_size"], "27B")
        self.assertEqual(
            config["generation_parameters"],
            {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 220,
                "stream": False,
                "format": "json",
                "keep_alive": "10m",
            },
        )
        self.assertNotIn("prompt", json.dumps(config))
        self.assertNotIn("private", json.dumps(config))

    def test_ollama_response_metrics_are_stored_as_milliseconds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            payload = {
                "model": "qwen3.8:27b",
                "prompt": "do not persist",
                "stream": False,
                "options": {"temperature": 0.1},
            }
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with telemetry.performance_span(
                    year=2026,
                    operation_id="action_plan.treatment_primary",
                    llm_configuration=telemetry.safe_llm_configuration(
                        model="qwen3.8:27b",
                        payload=payload,
                    ),
                ) as span:
                    span.set_ollama_metrics({
                        "model": "qwen3.8:27b",
                        "prompt_eval_count": 10,
                        "eval_count": 20,
                        "total_duration": 123_000_000,
                        "load_duration": 4_000_000,
                        "prompt_eval_duration": 5_000_000,
                        "eval_duration": 6_000_000,
                        "done_reason": "stop",
                        "response": "do not persist",
                    })
                telemetry.flush_performance_telemetry()

                stored = json.loads((data_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8"))
                event = stored["events"][0]
                self.assertEqual(event["model"], "qwen3.8:27b")
                self.assertEqual(event["prompt_tokens"], 10)
                self.assertEqual(event["completion_tokens"], 20)
                self.assertEqual(event["total_tokens"], 30)
                self.assertEqual(event["ollama_total_duration_ms"], 123)
                self.assertEqual(event["ollama_load_duration_ms"], 4)
                self.assertEqual(event["ollama_prompt_eval_duration_ms"], 5)
                self.assertEqual(event["ollama_eval_duration_ms"], 6)
                self.assertEqual(event["done_reason"], "stop")
                self.assertNotIn("do not persist", json.dumps(event))

    def test_record_response_includes_latest_config_and_observed_configurations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            events = [
                {
                    "event_id": "first",
                    "operation_id": "action_plan.treatment_repair",
                    "started_at": "2026-08-25T12:34:50.123Z",
                    "duration_ms": 100,
                    "outcome": "Success",
                    "error_type": None,
                    "provider": "Ollama",
                    "model": "qwen3.8:27b",
                    "model_family": "Qwen3.8",
                    "model_tag": "27b",
                    "parameter_size": "27B",
                    "generation_parameters": {
                        "temperature": 0.05,
                        "top_p": 0.9,
                        "num_predict": 220,
                        "stream": False,
                    },
                    "prompt_tokens": 3,
                    "completion_tokens": 7,
                    "total_tokens": 10,
                    "_year": 2026,
                },
                {
                    "event_id": "latest",
                    "operation_id": "action_plan.treatment_repair",
                    "started_at": "2026-08-25T12:34:51.123Z",
                    "duration_ms": 200,
                    "outcome": "Success",
                    "error_type": None,
                    "provider": "Ollama",
                    "model": "qwen3.8:27b",
                    "model_family": "Qwen3.8",
                    "model_tag": "27b",
                    "parameter_size": "27B",
                    "generation_parameters": {
                        "temperature": 0.07,
                        "top_p": 0.9,
                        "num_predict": 240,
                        "stream": False,
                    },
                    "prompt_tokens": 4,
                    "completion_tokens": 8,
                    "total_tokens": 12,
                    "_year": 2026,
                },
            ]
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry._write_event_batch(events)
                record = next(
                    item
                    for item in telemetry.get_performance_dashboard(2026)["records"]
                    if item["id"] == "action_plan.treatment_repair"
                )

                self.assertEqual(record["model"], "qwen3.8:27b")
                self.assertEqual(record["modelFamily"], "Qwen3.8")
                self.assertEqual(record["modelTag"], "27b")
                self.assertEqual(record["parameterSize"], "27B")
                self.assertEqual(record["generationParameters"]["temperature"], 0.07)
                self.assertEqual(record["generationParameters"]["topP"], 0.9)
                self.assertEqual(record["generationParameters"]["numPredict"], 240)
                self.assertEqual(record["promptTokens"], 4)
                self.assertEqual(record["completionTokens"], 8)
                self.assertEqual(record["totalTokens"], 12)
                self.assertEqual(len(record["observedConfigurations"]), 2)
                self.assertEqual(sum(item["callCount"] for item in record["observedConfigurations"]), 2)

    def test_model_summaries_group_multiple_qwen_versions_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            events = [
                {
                    "event_id": "qwen27",
                    "operation_id": "action_plan.treatment_primary",
                    "started_at": "2026-08-25T12:34:50.123Z",
                    "duration_ms": 100,
                    "outcome": "Success",
                    "error_type": None,
                    "provider": "Ollama",
                    "model": "qwen3.8:27b",
                    "model_family": "Qwen3.8",
                    "model_tag": "27b",
                    "parameter_size": "27B",
                    "generation_parameters": {"temperature": 0.1},
                    "total_tokens": 10,
                    "_year": 2026,
                },
                {
                    "event_id": "qwen32",
                    "operation_id": "monitoring.action_primary",
                    "started_at": "2026-08-25T12:34:51.123Z",
                    "duration_ms": 200,
                    "outcome": "Success",
                    "error_type": None,
                    "provider": "Ollama",
                    "model": "qwen3:32b",
                    "model_family": "Qwen3",
                    "model_tag": "32b",
                    "parameter_size": "32B",
                    "generation_parameters": {"temperature": 0.25},
                    "total_tokens": 20,
                    "_year": 2026,
                },
            ]
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                telemetry._write_event_batch(events)
                summaries = telemetry.get_performance_dashboard(2026)["modelSummaries"]

                self.assertEqual({item["model"] for item in summaries}, {"qwen3.8:27b", "qwen3:32b"})
                qwen27 = next(item for item in summaries if item["model"] == "qwen3.8:27b")
                qwen32 = next(item for item in summaries if item["model"] == "qwen3:32b")
                self.assertEqual(qwen27["parameterSize"], "27B")
                self.assertEqual(qwen32["parameterSize"], "32B")
                self.assertEqual(qwen27["totalTokens"], 10)
                self.assertEqual(qwen32["operationIds"], ["monitoring.action_primary"])

    def test_dynamic_num_predict_records_resolved_value(self) -> None:
        resolved_num_predict = max(220, 4 * 80)
        config = telemetry.safe_llm_configuration(
            model="qwen3.8:27b",
            payload={
                "model": "qwen3.8:27b",
                "prompt": "do not persist",
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": resolved_num_predict,
                },
            },
        )
        self.assertEqual(config["generation_parameters"]["num_predict"], 320)

    def test_missing_options_remain_missing(self) -> None:
        config = telemetry.safe_llm_configuration(
            model="qwen3.8:27b",
            payload={
                "model": "qwen3.8:27b",
                "prompt": "do not persist",
                "stream": False,
                "format": "json",
                "keep_alive": "10m",
            },
        )
        self.assertEqual(
            config["generation_parameters"],
            {
                "stream": False,
                "format": "json",
                "keep_alive": "10m",
            },
        )
        self.assertNotIn("temperature", config["generation_parameters"])
        self.assertNotIn("top_p", config["generation_parameters"])
        self.assertNotIn("num_predict", config["generation_parameters"])

    def test_safe_helpers_do_not_make_additional_ollama_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(telemetry, "DATA_WORK_DIR", Path(temp_dir)):
                with patch("requests.post") as post:
                    config = telemetry.safe_llm_configuration(
                        model="qwen3.8:27b",
                        payload={
                            "model": "qwen3.8:27b",
                            "prompt": "do not persist",
                            "stream": False,
                            "options": {"temperature": 0.1},
                        },
                    )
                    with telemetry.performance_span(
                        year=2026,
                        operation_id="action_plan.treatment_primary",
                        llm_configuration=config,
                    ) as span:
                        span.set_ollama_metrics({"prompt_eval_count": 1, "eval_count": 2})
                    telemetry.flush_performance_telemetry()
                    post.assert_not_called()

    def test_no_prompt_response_embeddings_or_retrieved_content_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            payload = {
                "model": "qwen3.8:27b",
                "prompt": "secret prompt embedding vector retrieved content host asset CVE-2026-9999",
                "stream": False,
                "options": {"temperature": 0.1},
            }
            with patch.object(telemetry, "DATA_WORK_DIR", data_dir):
                with telemetry.performance_span(
                    year=2026,
                    operation_id="action_plan.treatment_primary",
                    llm_configuration=telemetry.safe_llm_configuration(
                        model="qwen3.8:27b",
                        payload=payload,
                    ),
                ) as span:
                    span.set_ollama_metrics({
                        "response": "secret response text",
                        "prompt_eval_count": 0,
                        "eval_count": 0,
                    })
                telemetry.flush_performance_telemetry()
                stored = (data_dir / "2026" / "PerformanceTelemetry.json").read_text(encoding="utf-8")

                for forbidden in (
                    "secret prompt",
                    "embedding vector",
                    "retrieved content",
                    "host asset",
                    "CVE-2026-9999",
                    "secret response text",
                ):
                    self.assertNotIn(forbidden, stored)

    def test_qwen_model_declarations_and_generation_parameters_are_unchanged(self) -> None:
        for relative_path, declaration in EXPECTED_QWEN_MODEL_DECLARATIONS:
            source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(declaration, source)

        all_sources = "\n".join(
            (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
            for relative_path, _ in EXPECTED_QWEN_MODEL_DECLARATIONS
        )
        for operation_id, (temperature, top_p, num_predict) in EXPECTED_GENERATION_PARAMETER_INVENTORY.items():
            operation_index = all_sources.find(f'operation_id="{operation_id}"')
            self.assertNotEqual(operation_index, -1, operation_id)
            payload_window = all_sources[max(0, operation_index - 1200):operation_index]
            self.assertIn(f'"temperature": {temperature}', payload_window, operation_id)
            self.assertIn(f'"top_p": {top_p}', payload_window, operation_id)
            self.assertRegex(payload_window, rf'"num_predict": {num_predict}', operation_id)

        for operation_id in (
            "action_plan.evidence_description",
            "annex.select_controls",
        ):
            operation_index = all_sources.find(f'operation_id="{operation_id}"')
            self.assertNotEqual(operation_index, -1, operation_id)
            payload_window = all_sources[max(0, operation_index - 650):operation_index]
            self.assertNotIn('"temperature"', payload_window, operation_id)
            self.assertNotIn('"top_p"', payload_window, operation_id)
            self.assertNotIn('"num_predict"', payload_window, operation_id)


if __name__ == "__main__":
    unittest.main()
