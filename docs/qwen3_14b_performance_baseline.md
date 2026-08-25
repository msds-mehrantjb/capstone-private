# Qwen3 14B Performance Baseline

Generated from the local Performance Dashboard telemetry for year 2026.

## Scope

This report summarizes the current `qwen3:14b` LLM reasoning and retry/repair telemetry captured by the application.

Important note: these events were captured before the newest token/model-summary fields were added to telemetry. The code configuration verifies that these LLM paths use `qwen3:14b`, but token counts are not available for this captured run.

## Overall Baseline

| Metric | Value |
|---|---:|
| Model | `qwen3:14b` |
| Provider | Ollama |
| Total LLM/retry calls | 71 |
| Successful calls | 71 |
| Failed calls | 0 |
| Success rate | 100% |
| Total elapsed time | 1,762.9s / 29.4 min |
| Average duration per call | 24.8s |
| P95 duration | 69.5s |
| Slowest single call | 101.4s |
| Total tokens | Not available for this captured run |

## Operation-Level Performance

| Rank | Operation | Type | Calls | Avg | P95 | Total Time | Share | Status |
|---:|---|---|---:|---:|---:|---:|---:|---|
| 1 | Action Plan evidence description | LLM Reasoning | 21 | 51.2s | 72.5s | 1,075.7s | 61.0% | Slow |
| 2 | Annex row JSON retry | Retry/Repair | 6 | 46.5s | 51.7s | 279.2s | 15.8% | Slow |
| 3 | Monitoring evidence description | LLM Reasoning | 11 | 11.4s | 11.6s | 124.9s | 7.1% | Healthy |
| 4 | Action Plan treatment primary | LLM Reasoning | 7 | 15.3s | 18.7s | 106.9s | 6.1% | Healthy |
| 5 | Risk Evaluation justification | LLM Reasoning | 6 | 12.1s | 20.1s | 72.6s | 4.1% | Healthy |
| 6 | Annex control selection | LLM Reasoning | 7 | 10.3s | 27.9s | 72.3s | 4.1% | Healthy |
| 7 | Risk Evaluation monitoring fields | LLM Reasoning | 6 | 2.9s | 14.5s | 17.1s | 1.0% | Healthy |
| 8 | Annex row primary justification | LLM Reasoning | 7 | 2.0s | 9.9s | 14.1s | 0.8% | Healthy |

## Section Summary

| Section | Calls | Avg | P95 | Total Time |
|---|---:|---:|---:|---:|
| Action Plan & Implementation | 28 | 42.2s | 72.5s | 1,182.6s |
| Annex A & SoA | 20 | 18.3s | 50.8s | 365.7s |
| Monitoring & Improvement | 11 | 11.4s | 11.6s | 124.9s |
| Risk Evaluation & Treatment | 12 | 7.5s | 20.1s | 89.7s |

## Comparison Guidance

For comparison against other Qwen models, use these metrics as the primary baseline:

- Average duration per call
- P95 duration
- Total elapsed time
- Success rate
- Slowest single call
- Operation-level bottleneck share

The biggest bottleneck in this baseline is Action Plan evidence description, which accounts for about 61.0% of observed Qwen LLM time. This operation is the most important comparison point when evaluating other Qwen model sizes.

## Configuration Verification

The current worktree verifies the primary LLM model as `qwen3:14b`.

Observed Qwen model declarations:

| Area | Declaration |
|---|---|
| Threats & Vulnerabilities | `LLM_MODEL = "qwen3:14b"` |
| Risk Evaluation & Treatment | `LLM_MODEL = "qwen3:14b"` |
| Annex A & SoA | `LLM_MODEL = "qwen3:14b"` |
| Action Plan & Implementation | `OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:14b")` |
| Monitoring & Improvement | `OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:14b")` |

