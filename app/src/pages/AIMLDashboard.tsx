import React, { useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  Plus,
  Brain,
  Activity,
  Database,
  Sparkles,
  Users,
  ShieldAlert,
} from "lucide-react";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type SystemStatusDTO = {
  meta: { name: string; version: string };
  sections: Record<string, { status: StepStatus; scope_file_name?: string }>;
};

type DashboardRawDTO = {
  environment?: string;
  scope?: {
    name?: string;
    asset_count?: number;
    status?: StepStatus;
  };
  kpis?: {
    readiness_score?: {
      value?: number;
      max?: number;
      label?: string;
      delta_7d?: number;
    };
    evidence_coverage?: {
      percent?: number;
      have?: number;
      total?: number;
    };
    open_high_critical?: {
      count?: number;
      unresolved?: number;
    };
    soa?: {
      status?: StepStatus;
      count?: number;
    };
  };
  scope_context_section2?: {
    title?: string;
    bullets?: string[];
    body?: string;
  };
  scope_file_name?: string;
};

type Accent = "amber" | "emerald" | "rose" | "slate" | "sky";

type KpiCalculationDTO = {
  method?: string;
  formula?: string;
  source_files?: string[];
  inputs?: Record<string, unknown>;
  notes?: string[];
  fallback_reason?: string;
  previous_snapshot_id?: string;
  previous_generated_at?: string;
  previous_source?: string;
  what_this_means?: string;
  readable_formula?: string;
  actual_calculation?: string;
  data_used?: { label?: string; value?: unknown }[];
  [key: string]: unknown;
};

type AimlMetricDTO = {
  key?: string;
  title: string;
  value: React.ReactNode;
  accent: Accent;
  computed?: boolean | null;
  source?: string;
  raw_value?: unknown;
  calculation?: KpiCalculationDTO;
};

type AimlGroupDTO = {
  group: string;
  json_key?: string;
  metrics: AimlMetricDTO[];
};

type DatasetRecordDTO = {
  total_records?: number;
  synthetic_records?: number;
  real_records?: number;
};

type AimlDashboardDTO = {
  success?: boolean;
  source_file?: string;
  snapshot_id?: string;
  generated_at?: string;
  year?: number;
  kpi_groups?: AimlGroupDTO[];
  dataset_provenance?: {
    summary?: {
      total_records_all_datasets?: number;
      synthetic_records_all_datasets?: number;
      real_records_all_datasets?: number;
    };
    datasets?: Record<string, DatasetRecordDTO>;
  };
  rag?: {
    vector_database?: string;
    text_embedding_model?: string;
  };
  llm?: {
    model?: string;
    version?: string;
    parameters?: string;
    deployment_style?: string;
  };
};

const LEFT_MENU_STEPS = [
  { step: 1, name: "Scope & Context", href: "#/scope" },
  { step: 2, name: "Asset Inventory & CIA", href: "#/assets" },
  { step: 3, name: "Threats & Vulnerabilities", href: "#/threats" },
  { step: 4, name: "Existing Controls & Posture", href: "#/controls" },
  { step: 5, name: "Risk Analysis", href: "#/risk-analysis" },
  { step: 6, name: "Risk Evaluation/Treatment", href: "#/risk-evaluation-treatment" },
  { step: 7, name: "Annex A & SoA", href: "#/annex-a-soa" },
  { step: 8, name: "Action Plan / Implementation", href: "#/action-plan-implementation" },
  { step: 9, name: "Monitoring & Improvement", href: "#/monitoring-improvement" },
  { step: 10, name: "Final Deliverables", href: "#/final-deliverables" },
] as const;

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const fallbackKpiData: AimlGroupDTO[] = [
  {
    group: "Core ML",
    metrics: [
      { title: "Role Prediction Accuracy (%)", value: 92, accent: "emerald" },
      { title: "CIA Prediction Accuracy (%)", value: 89, accent: "emerald" },
      { title: "F1 Score (Role Model)", value: 0.91, accent: "emerald" },
      { title: "Model Accuracy (%)", value: 87, accent: "emerald" },
    ],
  },
  {
    group: "ML-based UABV",
    metrics: [
      { title: "Behavior Model Accuracy (%)", value: 87, accent: "amber" },
      { title: "High-Risk User Percentage (%)", value: 12, accent: "amber" },
      { title: "Score Difference (ML vs Rule)", value: 1.5, accent: "amber" },
      { title: "Top Contributing Feature Distribution (%)", value: 45, accent: "amber" },
    ],
  },
  {
    group: "RAG Performance",
    metrics: [
      { title: "RAG Query Count", value: 1250, accent: "rose" },
      { title: "Retrieval Success Rate (%)", value: 94, accent: "rose" },
    ],
  },
  {
    group: "LLM Performance",
    metrics: [
      { title: "Reasoning Calls", value: 340, accent: "sky" },
      { title: "Total Tokens", value: 58000, accent: "sky" },
    ],
  },
  {
    group: "Human-in-the-Loop",
    metrics: [
      { title: "Manual Role Corrections", value: 7, accent: "amber" },
      { title: "Manual Risk Corrections", value: 5, accent: "amber" },
    ],
  },
  {
    group: "Trust & Reliability",
    metrics: [
      { title: "Override Rate (%)", value: 3, accent: "rose" },
      { title: "Low Confidence Predictions (%)", value: 4, accent: "rose" },
    ],
  },
];

async function apiGetJSON<T>(path: string): Promise<T> {
  const sep = path.includes("?") ? "&" : "?";
  const url = `${API_BASE}${path}${sep}_ts=${Date.now()}`;

  const res = await fetch(url, {
    cache: "no-store",
    headers: {
      "Cache-Control": "no-cache, no-store, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    },
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function apiPostJSON<T>(path: string): Promise<T> {
  const sep = path.includes("?") ? "&" : "?";
  const url = `${API_BASE}${path}${sep}_ts=${Date.now()}`;

  const res = await fetch(url, {
    method: "POST",
    cache: "no-store",
    headers: {
      "Cache-Control": "no-cache, no-store, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    },
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/raw?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetSystemStatus(year: number): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>(
    `/api/system/status?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetAimlDashboard(year: number): Promise<AimlDashboardDTO> {
  return apiGetJSON<AimlDashboardDTO>(
    `/api/aiml-dashboard/raw?year=${encodeURIComponent(String(year))}`
  );
}

async function apiCreateAimlSnapshot(year: number): Promise<AimlDashboardDTO> {
  return apiPostJSON<AimlDashboardDTO>(
    `/api/aiml-dashboard/snapshot?year=${encodeURIComponent(String(year))}`
  );
}

function ShellCard({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={[
        "rounded-2xl border border-white/10 bg-white/5 shadow-xl ring-1 ring-white/10",
        className,
      ].join(" ")}
    >
      {children}
    </div>
  );
}

function KpiCard({
  title,
  value,
  icon,
  accent,
  onClick,
}: {
  title: string;
  value: React.ReactNode;
  icon: React.ReactNode;
  accent: Accent;
  onClick?: () => void;
}) {
  const badge =
    accent === "amber"
      ? "bg-amber-500/15 ring-1 ring-amber-500/25 text-amber-200"
      : accent === "emerald"
      ? "bg-emerald-500/15 ring-1 ring-emerald-500/25 text-emerald-200"
      : accent === "rose"
      ? "bg-rose-500/15 ring-1 ring-rose-500/25 text-rose-200"
      : accent === "sky"
      ? "bg-sky-500/15 ring-1 ring-sky-500/25 text-sky-200"
      : "bg-white/5 ring-1 ring-white/10 text-slate-200";

  const card = (
    <ShellCard className={`h-full p-4 ${onClick ? "transition hover:bg-white/10" : ""}`}>
      <div className="flex h-full items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm text-slate-300">{title}</div>
          <div className="mt-2 text-3xl font-semibold leading-none text-white sm:text-4xl">
            {value}
          </div>
        </div>

        <div className={`grid h-12 w-12 shrink-0 place-items-center rounded-2xl ${badge}`}>
          {icon}
        </div>
      </div>
    </ShellCard>
  );

  if (!onClick) return card;

  return (
    <button
      type="button"
      onClick={onClick}
      className="h-full w-full rounded-2xl text-left focus:outline-none focus:ring-2 focus:ring-sky-400/70"
    >
      {card}
    </button>
  );
}

function getGroup(groups: AimlGroupDTO[], groupName: string) {
  return groups.find((g) => g.group === groupName);
}

function getGroupIcon(groupName: string) {
  if (groupName === "Core ML") return <Brain className="h-6 w-6" />;
  if (groupName === "ML-based UABV") return <Activity className="h-6 w-6" />;
  if (groupName === "RAG Performance") return <Database className="h-6 w-6" />;
  if (groupName === "LLM Performance") return <Sparkles className="h-6 w-6" />;
  if (groupName === "Human-in-the-Loop") return <Users className="h-6 w-6" />;
  if (groupName === "Trust & Reliability") return <ShieldAlert className="h-6 w-6" />;
  return <Plus className="h-6 w-6" />;
}

function renderGroup(
  groups: AimlGroupDTO[],
  groupName: string,
  colsClass: string,
  onMetricClick?: (metric: AimlMetricDTO) => void
) {
  const group = getGroup(groups, groupName);
  if (!group) return null;
  const cardsAreClickable = Boolean(onMetricClick);

  return (
    <div className="h-full">
      <h2 className="mb-3 text-xl font-bold text-slate-100 md:text-xl">  {group.group} </h2>
      <div className={colsClass}>
        {group.metrics.map((metric, idx) => (
          <KpiCard
            key={`${group.group}-${idx}`}
            title={metric.title}
            value={metric.value}
            icon={getGroupIcon(group.group)}
            accent={metric.accent}
            onClick={cardsAreClickable ? () => onMetricClick?.(metric) : undefined}
          />
        ))}
      </div>
    </div>
  );
}

function stringifyValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "NA";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function readableInputLabel(key: string) {
  const labels: Record<string, string> = {
    correct_predictions: "Correct predictions",
    total_predictions: "Total evaluated predictions",
    matching_predictions: "ML predictions matching final value",
    evaluated_assets: "Assets evaluated",
    assets_with_cia_rating: "Assets with CIA rating",
    total_assets: "Total assets",
    evaluated_predictions: "Evaluated predictions",
    macro_f1: "Macro F1 score",
    run_id: "Training run",
    accuracy_pct: "Model accuracy",
    accuracy_source: "Accuracy source",
    server_accuracy_pct: "Server model accuracy",
    workstation_accuracy_pct: "Workstation model accuracy",
    total_behavior_predictions: "Total behavior predictions",
    total_user_behavior_records: "Total user behavior records",
    high_risk_users: "High-risk user behavior records",
    compared_behavior_predictions: "Behavior predictions compared",
    compared_user_behavior_records: "User behavior records compared",
    feature_count: "Features included",
    top_feature: "Top contributing feature",
    top_feature_contribution_pct: "Top feature contribution (%)",
    total_feature_importance_pct: "Total normalized feature importance (%)",
    rag_query_count: "Total RAG retrieval requests",
    rag_success_count: "Successful RAG retrievals",
    rag_failure_count: "Failed RAG retrievals",
    successful_retrievals: "Successful RAG retrievals",
    evaluated_rag_queries: "Evaluated RAG retrieval requests",
    llm_reasoning_calls: "Successful LLM reasoning calls",
    llm_total_tokens: "Total LLM tokens",
    manual_role_corrections: "Manual asset role corrections",
    manual_risk_corrections: "Manual risk corrections",
    overridden_role_predictions: "Role predictions changed by user",
    evaluated_role_predictions: "Total evaluated role predictions",
    low_confidence_predictions: "Low-confidence role predictions",
    predictions_with_confidence: "Role predictions with confidence score",
    override_records: "Risk records manually overridden",
    total_risk_records: "Total risk records",
    previous_value: "Latest available KPI value",
    previous_generated_at: "Latest available snapshot date",
    latest_available_kpi_value: "Latest available KPI value",
    latest_available_snapshot_date: "Latest available snapshot date",
    latest_available_source: "Latest available data source",
  };
  if (labels[key]) return labels[key];

  const normalized = String(key || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");

  if (normalized) {
    for (const [rawKey, label] of Object.entries(labels)) {
      const rawNormalized = rawKey.toLowerCase().replace(/[^a-z0-9]/g, "");
      const labelNormalized = label.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (normalized === rawNormalized || normalized === labelNormalized) {
        return label;
      }
    }
  }

  const withSpaces = String(key || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .trim();
  return withSpaces.replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function readableSourceValue(value: unknown) {
  const text = String(value ?? "").trim();
  if (!text) return value;

  const mapping: Record<string, string> = {
    telemetry: "Current telemetry",
    previous_snapshot: "Previous snapshot history",
    table_fallback: "Current table fallback",
    not_available: "Not available",
    reset_audit: "Reset audit snapshot",
    role_prediction_events_proxy: "Current role prediction events proxy",
    current_role_prediction_events_proxy: "Current role prediction events proxy",
  };

  return (
    mapping[text.toLowerCase()] ??
    text.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
  );
}

function dataUsedItems(calculation: KpiCalculationDTO) {
  if (Array.isArray(calculation.data_used) && calculation.data_used.length > 0) {
    return calculation.data_used.map((item) => ({
      label: (() => {
        const normalizedLabel =
          item.label === "Previous KPI value"
            ? "latest_available_kpi_value"
            : item.label === "Previous snapshot date"
            ? "latest_available_snapshot_date"
            : item.label || "Value";
        return readableInputLabel(normalizedLabel);
      })(),
      value:
        readableInputLabel(item.label || "") === "Latest Available Data Source" ||
        String(item.label || "").toLowerCase() === "latest available data source" ||
        readableInputLabel(item.label || "") === "Accuracy Source"
          ? readableSourceValue(item.value)
          : item.value,
    }));
  }

  const inputs = calculation.inputs ?? {};
  return Object.entries(inputs)
    .filter(([key]) => !["previous_source", "previous_method"].includes(key))
    .map(([key, value]) => ({
      label: readableInputLabel(key),
      value: key === "latest_available_source" ? readableSourceValue(value) : value,
    }));
}

type DataUsedItem = ReturnType<typeof dataUsedItems>[number];

const metricKeyByTitle: Record<string, string> = {
  "Role Prediction Accuracy (%)": "role_prediction_accuracy_pct",
  "Model Accuracy (%)": "model_accuracy_pct",
  "CIA Prediction Accuracy (%)": "cia_prediction_accuracy_pct",
  "F1 Score (Role Model)": "f1_score_role_model",
  "Behavior Model Accuracy (%)": "behavior_model_accuracy_pct",
  "High-Risk User Percentage (%)": "high_risk_user_percentage_pct",
  "Score Difference (ML vs Rule)": "score_difference_ml_vs_rule",
  "Top Contributing Feature Distribution (%)": "top_contributing_feature_distribution_pct",
  "RAG Query Count": "rag_query_count",
  "Retrieval Success Rate (%)": "retrieval_success_rate_pct",
  "Reasoning Calls": "reasoning_calls",
  "Total Tokens": "total_tokens",
  "Manual Role Corrections": "manual_role_corrections",
  "Manual Risk Corrections": "manual_risk_corrections",
  "Override Rate (%)": "override_rate_pct",
  "Low Confidence Predictions (%)": "low_confidence_predictions_pct",
};

function metricKey(metric: AimlMetricDTO) {
  return metric.key || metricKeyByTitle[metric.title] || "";
}

function numberFromUnknown(value: unknown) {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") {
    const parsed = Number(value.replace("%", "").replace(/,/g, "").trim());
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function metricNumber(metric: AimlMetricDTO) {
  const rawNumber = numberFromUnknown(metric.raw_value);
  if (rawNumber !== null) return rawNumber;
  return numberFromUnknown(metric.value);
}

function qualityText(value: number | null, highIsGood = true) {
  if (value === null) {
    return "The dashboard does not have enough current data to judge this KPI yet.";
  }

  if (highIsGood) {
    if (value >= 90) {
      return "This is a strong result and suggests the related model or workflow is performing well.";
    }
    if (value >= 75) {
      return "This is a usable result, but there is still room to improve consistency.";
    }
    if (value >= 50) {
      return "This is a moderate result and should be reviewed for model tuning, better labels, or more representative input data.";
    }
    return "This is a weak result and suggests the related model or workflow needs attention before it should be trusted for important decisions.";
  }

  if (value <= 5) return "This is a low rate, which is generally a good sign for this KPI.";
  if (value <= 20) return "This is a moderate rate and should be watched over time.";
  return "This is a high rate and should be reviewed because it may indicate trust, confidence, or data-quality issues.";
}

function dataValue(dataUsed: DataUsedItem[], label: string) {
  return dataUsed.find((item) => item.label === label)?.value;
}

function dataActivityText(dataUsed: DataUsedItem[], numeratorLabel: string, denominatorLabel: string) {
  const numerator = dataValue(dataUsed, numeratorLabel);
  const denominator = dataValue(dataUsed, denominatorLabel);
  if (numerator === undefined || denominator === undefined) return "";

  const numeratorNumber = numberFromUnknown(numerator);
  const denominatorNumber = numberFromUnknown(denominator);
  let sentence = `In the current data, ${numeratorLabel} is ${stringifyValue(numerator)} and ${denominatorLabel} is ${stringifyValue(denominator)}.`;

  if (numeratorNumber !== null && denominatorNumber !== null) {
    const misses = Math.max(denominatorNumber - numeratorNumber, 0);
    sentence += ` That leaves ${stringifyValue(misses)} records that did not meet this KPI condition.`;
  }

  return sentence;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function formulaWithDataLabels(formula: unknown, inputs: Record<string, unknown> | undefined) {
  if (typeof formula !== "string" || !formula.trim()) return "";
  let output = formula;
  Object.keys(inputs ?? {})
    .sort((a, b) => b.length - a.length)
    .forEach((key) => {
      output = output.replace(new RegExp(`\\b${escapeRegExp(key)}\\b`, "g"), readableInputLabel(key));
    });
  return output;
}

function carriedForwardPrefix(metric: AimlMetricDTO) {
  if (metric.source !== "previous_snapshot") return "";
  return "Current telemetry was missing, so Displayed value was set from Latest available KPI value in Latest available snapshot date. ";
}

function inferredHowComputed(metric: AimlMetricDTO) {
  const prefix = carriedForwardPrefix(metric);

  switch (metricKey(metric)) {
    case "role_prediction_accuracy_pct":
      return `${prefix}Correct predictions / Total evaluated predictions * 100. Correct predictions counts records where the ML-predicted role matched the final selected role. Total evaluated predictions counts records where both the model prediction and final selected role were available.`;
    case "model_accuracy_pct":
      if (metric.calculation?.inputs?.run_id && metric.calculation?.inputs?.accuracy_pct !== undefined) {
        return `${prefix}The dashboard reads the latest role model training run from AIMLKPIInputs.json and uses its stored Model accuracy value. When available, this is the direct role-model accuracy metric captured for that run.`;
      }
      return `${prefix}Stored role model training accuracy was not available, so the dashboard used Correct predictions / Total evaluated predictions * 100 from current role prediction telemetry as the role-model accuracy indicator.`;
    case "cia_prediction_accuracy_pct":
      return `${prefix}Correct CIA predictions / Total CIA predictions * 100. If direct CIA prediction telemetry is not available, Assets with CIA rating / Total assets * 100 is used as a fallback coverage estimate.`;
    case "f1_score_role_model":
      return `${prefix}Macro F1 score is calculated from role-class precision and recall. For each role class, the system compares ML-predicted role with final selected role, then builds true positives, false positives, and false negatives. Precision = true positives / predicted positives. Recall = true positives / actual positives. Per-role F1 = 2 * precision * recall / (precision + recall). The displayed Macro F1 score is the average of the per-role F1 values, so smaller role classes still affect the result.`;
    case "behavior_model_accuracy_pct":
      return `${prefix}Model accuracy is calculated on the held-out Test split. The behavior training pipeline median-imputes numeric behavior features, encodes the risk label, trains the Model algorithm, then predicts the held-out test rows. Model accuracy = correctly predicted test rows / total test rows * 100.`;
    case "high_risk_user_percentage_pct":
      return `${prefix}High-risk user behavior records / Total user behavior records * 100. High-risk user behavior records counts behavior rows assigned to the highest risk band.`;
    case "score_difference_ml_vs_rule":
      return `${prefix}For every record in Behavior predictions compared, the dashboard calculates the absolute difference between the ML risk score and the rule-based risk score, then averages those differences.`;
    case "top_contributing_feature_distribution_pct":
      return `${prefix}Top feature contribution (%) / Total normalized feature importance (%) * 100. Top feature contribution (%) is the largest normalized feature-importance value from the latest behavior model training run. Total normalized feature importance (%) is 100 because all included feature shares are normalized to a full distribution.`;
    case "rag_query_count":
      return `${prefix}The dashboard uses Total RAG retrieval requests as the displayed count.`;
    case "retrieval_success_rate_pct":
      return `${prefix}Successful RAG retrievals / Total RAG retrieval requests * 100. Successful RAG retrievals counts requests that returned usable context for assistant actions.`;
    case "reasoning_calls":
      return `${prefix}The dashboard uses Successful LLM reasoning calls as the displayed count.`;
    case "total_tokens":
      return `${prefix}The dashboard uses Total LLM tokens as the displayed count.`;
    case "manual_role_corrections":
      return `${prefix}The dashboard uses Manual asset role corrections as the displayed count.`;
    case "manual_risk_corrections":
      return `${prefix}The dashboard uses Manual risk corrections as the displayed count.`;
    case "override_rate_pct":
      return `${prefix}Role predictions changed by user / Total evaluated role predictions * 100. Role predictions changed by user counts cases where the final role decision differed from the ML prediction.`;
    case "low_confidence_predictions_pct":
      return `${prefix}Low-confidence role predictions / Role predictions with confidence score * 100. Low-confidence role predictions counts role predictions below the 0.60 confidence threshold.`;
    default:
      return prefix + formulaWithDataLabels(metric.calculation?.formula, metric.calculation?.inputs);
  }
}

function inferredMeaning(metric: AimlMetricDTO, dataUsed: DataUsedItem[]) {
  const key = metricKey(metric);
  const value = metricNumber(metric);
  const displayed = stringifyValue(metric.value);

  if (metric.source === "not_available") {
    return "No usable data is available for this KPI yet. The system has not captured enough telemetry, previous snapshot history, or fallback table data to measure this part of AI/ML performance.";
  }

  const latestContext =
    metric.source === "previous_snapshot"
      ? "This uses the latest available KPI data because current telemetry was missing. "
      : "";

  switch (key) {
    case "role_prediction_accuracy_pct":
      return `${latestContext}${displayed}% role prediction accuracy means the role model matched the final selected asset role at that rate. ${dataActivityText(dataUsed, "Correct predictions", "Total evaluated predictions")} The goal is to make asset role assignment reliable enough to support CIA rating, risk analysis, and downstream ISO workflow decisions with less manual correction. ${qualityText(value)}`;
    case "model_accuracy_pct":
      if (dataValue(dataUsed, "Training run") !== undefined && dataValue(dataUsed, "Model accuracy") !== undefined) {
        return `${latestContext}${displayed}% model accuracy means the latest role-model evaluation ran at that accuracy level for asset role classification. The goal is to show whether the trained role model itself is learning role classes well enough before we trust it in live assignment workflows. ${qualityText(value)}`;
      }
      return `${latestContext}${displayed}% model accuracy is currently being estimated from evaluated role prediction outcomes because stored role-training accuracy was not available. ${dataActivityText(dataUsed, "Correct predictions", "Total evaluated predictions")} The goal is to keep a usable model-quality signal available for the role model even when dedicated training telemetry is missing. ${qualityText(value)}`;
    case "cia_prediction_accuracy_pct":
      return `${latestContext}${displayed}% CIA prediction accuracy means CIA outcomes were matched or covered at that rate. ${dataActivityText(dataUsed, "Assets with CIA rating", "Total assets") || dataActivityText(dataUsed, "Correct predictions", "Total evaluated predictions")} The goal is to keep confidentiality, integrity, and availability classification consistent before risk scoring depends on it. ${qualityText(value)}`;
    case "f1_score_role_model":
      return `${latestContext}An F1 score of ${displayed} is a class-balanced role model quality signal. It penalizes both false role assignments and missed role assignments, so it is more useful than accuracy when role classes are uneven. The goal is for every asset role class, not only the most common ones, to be predicted reliably. ${qualityText(value === null ? null : value * 100)}`;
    case "behavior_model_accuracy_pct":
      return `${latestContext}${displayed}% behavior model accuracy means the user-behavior model predicted held-out behavior-risk labels correctly at that rate. This reflects how well the model generalizes from training behavior records to unseen behavior records, which matters for UABV risk detection. ${qualityText(value)}`;
    case "high_risk_user_percentage_pct":
      return `${latestContext}${displayed}% of user behavior records are currently high risk. ${dataActivityText(dataUsed, "High-risk user behavior records", "Total user behavior records")} The goal is to show how much monitored activity is being pushed into the highest risk band. ${qualityText(value, false)}`;
    case "score_difference_ml_vs_rule":
      return `${latestContext}The ML-vs-rule score difference is ${displayed}. Lower values mean the ML scoring and rule-based scoring are aligned; higher values mean model behavior is drifting away from the transparent rule baseline.`;
    case "top_contributing_feature_distribution_pct":
      return `${latestContext}${displayed}% top contributing feature distribution means ${stringifyValue(dataValue(dataUsed, "Top contributing feature") || "the strongest behavior feature")} is the strongest behavior signal in the model. This percentage is its share of the normalized feature-importance distribution. A high value means one behavior feature is driving much of the model's decision pattern, which should be reviewed for bias or over-dependence.`;
    case "rag_query_count":
      return `${latestContext}The dashboard recorded ${displayed} RAG retrieval requests. This measures retrieval workload across assistant actions that need knowledge-base context.`;
    case "retrieval_success_rate_pct":
      return `${latestContext}${displayed}% retrieval success means RAG returned usable context at that rate. ${dataActivityText(dataUsed, "Successful RAG retrievals", "Total RAG retrieval requests")} The goal is for knowledge retrieval to consistently provide supporting controls, risks, or guidance for assistant responses. ${qualityText(value)}`;
    case "reasoning_calls":
      return `${latestContext}The app recorded ${displayed} successful LLM reasoning calls. This reflects reasoning workload and feature usage volume, not direct answer quality.`;
    case "total_tokens":
      return `${latestContext}The app recorded ${displayed} LLM tokens. This reflects approximate LLM workload and can explain latency, memory pressure, and model-serving cost.`;
    case "manual_role_corrections":
      return value === 0
        ? `${latestContext}No manual role corrections are recorded in the available KPI data. That means users have not needed to change model-assisted asset role decisions in that measurement window, which is a good trust signal if role prediction activity exists.`
        : `${latestContext}${displayed} manual role corrections are recorded. This means users changed asset role decisions after model-assisted assignment, so these corrections are useful feedback for improving role prediction quality.`;
    case "manual_risk_corrections":
      return value === 0
        ? `${latestContext}No manual risk corrections are recorded in the available KPI data. That means users have not needed to change risk values in that measurement window, which is a good reliability signal if risk analysis activity exists.`
        : `${latestContext}${displayed} manual risk corrections are recorded. This means users changed risk decisions after analysis, so the risk model or rule output should be reviewed against those human decisions.`;
    case "override_rate_pct":
      return `${latestContext}${displayed}% override rate means final role decisions differed from the ML-predicted role at that rate. ${dataActivityText(dataUsed, "Role predictions changed by user", "Total evaluated role predictions")} The goal is to measure user trust in model output: lower override rates usually mean model suggestions are fitting the workflow better. ${qualityText(value, false)}`;
    case "low_confidence_predictions_pct":
      return `${latestContext}${displayed}% low-confidence predictions means that share of ML role predictions fell below the 0.60 confidence threshold. ${dataActivityText(dataUsed, "Low-confidence role predictions", "Role predictions with confidence score")} The goal is to identify where the model is uncertain and where human review or more training data is most valuable. ${qualityText(value, false)}`;
    default:
      return "This KPI summarizes the related AI/ML dashboard signal using the data shown above.";
  }
}

function KpiDetailModal({
  metric,
  onClose,
}: {
  metric: AimlMetricDTO | null;
  onClose: () => void;
}) {
  if (!metric) return null;

  const calculation = metric.calculation ?? {};
  const dataUsed = dataUsedItems(calculation);
  const backendMeaning =
    typeof calculation.what_this_means === "string" &&
    !calculation.what_this_means.includes("summarizes the related AI/ML dashboard signal") &&
    !calculation.what_this_means.includes("{'")
      ? calculation.what_this_means
      : "";
  const whatThisMeans = backendMeaning || inferredMeaning(metric, dataUsed);
  const fallbackFormula = formulaWithDataLabels(calculation.formula, calculation.inputs);
  const rawBackendFormula = formulaWithDataLabels(calculation.readable_formula, calculation.inputs);
  const backendFormula =
    rawBackendFormula.includes("No new calculation was run") ||
    rawBackendFormula.includes("carried forward the previous KPI value")
      ? ""
      : rawBackendFormula;
  const readableFormula =
    backendFormula || inferredHowComputed(metric) || fallbackFormula || "NA";

  return (
    <div
      className="fixed inset-0 z-[100] grid place-items-center bg-black/65 px-4"
      role="dialog"
      aria-modal="true"
    >
      <div className="max-h-[88vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-white/10 bg-[#0B1020] p-5 text-slate-100 shadow-2xl ring-1 ring-white/10">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-sky-200">
              KPI Details
            </div>
            <h2 className="mt-1 text-2xl font-bold">{metric.title}</h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-white/10 px-3 py-1 text-sm text-slate-200 hover:bg-white/10"
          >
            Close
          </button>
        </div>

        <div className="grid gap-3">
          <div className="rounded-lg bg-white/5 p-3 ring-1 ring-white/10">
            <div className="text-xs uppercase text-slate-400">Displayed value</div>
            <div className="mt-1 text-2xl font-semibold text-white">
              {stringifyValue(metric.value)}
            </div>
          </div>

          <div className="rounded-lg bg-white/5 p-3 ring-1 ring-white/10">
            <div className="text-xs uppercase text-slate-400">Data used</div>
            <div className="mt-2 grid gap-2">
              {dataUsed.length > 0 ? (
                dataUsed.map((item, idx) => (
                  <div
                    key={`${item.label}-${idx}`}
                    className="flex flex-col gap-1 rounded-lg bg-black/15 px-3 py-2 text-sm text-slate-100 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <span className="text-slate-300">{item.label}</span>
                    <span className="font-semibold text-white">{stringifyValue(item.value)}</span>
                  </div>
                ))
              ) : (
                <div className="rounded-lg bg-black/15 px-3 py-2 text-sm text-slate-100">
                  No usable data was available for this KPI.
                </div>
              )}
            </div>
          </div>
        </div>

        {metric.source === "previous_snapshot" ? (
          <div className="mt-3 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-100 ring-1 ring-amber-500/20">
            Current telemetry was missing, so this card uses the latest available KPI data from snapshot history.
          </div>
        ) : null}

        {metric.source === "table_fallback" ? (
          <div className="mt-3 rounded-lg bg-sky-500/10 p-3 text-sm text-sky-100 ring-1 ring-sky-500/20">
            No telemetry or previous KPI value was available, so this value was estimated from the current application table data.
          </div>
        ) : null}

        <div className="mt-4 grid gap-3">
          <div className="rounded-lg bg-white/5 p-3 ring-1 ring-white/10">
            <div className="text-xs uppercase text-slate-400">What this means</div>
            <div className="mt-1 text-sm text-slate-100">
              {whatThisMeans}
            </div>
          </div>

          <div className="rounded-lg bg-white/5 p-3 ring-1 ring-white/10">
            <div className="text-xs uppercase text-slate-400">How it was computed</div>
            <div className="mt-1 text-sm text-slate-100">
              {stringifyValue(readableFormula)}
            </div>
          </div>

          {calculation.fallback_reason && metric.source !== "previous_snapshot" ? (
            <div className="rounded-lg bg-white/5 p-3 ring-1 ring-white/10">
              <div className="text-xs uppercase text-slate-400">Fallback reason</div>
              <div className="mt-1 text-sm text-slate-100">
                {stringifyValue(calculation.fallback_reason)}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

const fallbackDatasetProvenance: NonNullable<AimlDashboardDTO["dataset_provenance"]> = {
  summary: {},
  datasets: {},
};

function MiniInfoCard({
  title,
  lines,
}: {
  title: string;
  lines: Array<{ label: string; value: React.ReactNode }>;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
      <h3 className="mb-3 shrink-0 text-xl font-bold text-slate-100">{title}</h3>

      <div className="grid min-h-0 flex-1 gap-3">
        {lines.map((item, idx) => (
          <div
            key={`${title}-${idx}`}
            className="flex min-h-0 items-center justify-between gap-3 rounded-xl bg-black/10 px-3 py-2"
          >
            <span className="text-sm text-slate-300">{item.label}</span>
            <span className="text-lg font-semibold text-white">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SpecCard({
  title,
  subtitle,
  icon,
  lines,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  lines: string[];
}) {
  return (
    <div className="flex h-full min-h-0 flex-col rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
      <div className="mb-3 flex shrink-0 items-start justify-between gap-3">
        <div>
          <h3 className="text-xl font-bold text-slate-100">{title}</h3>
          <p className="mt-1 text-sm text-slate-300">{subtitle}</p>
        </div>

        <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25">
          {icon}
        </div>
      </div>

      <div className="grid min-h-0 flex-1 gap-2">
        {lines.map((line, idx) => (
          <div
            key={`${title}-${idx}`}
            className="rounded-xl bg-black/10 px-3 py-2 text-sm leading-6 text-slate-200"
          >
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}

function valueOrNA(value: React.ReactNode | undefined) {
  return value ?? "NA";
}

function datasetRecord(
  datasetProvenance: NonNullable<AimlDashboardDTO["dataset_provenance"]>,
  key: string
) {
  return datasetProvenance.datasets?.[key] ?? {};
}

function DashboardSections({ aimlData }: { aimlData: AimlDashboardDTO | null }) {
  const [selectedMetric, setSelectedMetric] = useState<AimlMetricDTO | null>(null);

  const groups =
    aimlData?.kpi_groups && aimlData.kpi_groups.length > 0
      ? aimlData.kpi_groups
      : fallbackKpiData;

  const datasetProvenance =
    aimlData?.dataset_provenance ?? fallbackDatasetProvenance;

  const summary = datasetProvenance.summary ?? {};
  const serverDataset = datasetRecord(datasetProvenance, "server_role_training_dataset");
  const workstationDataset = datasetRecord(datasetProvenance, "workstation_role_training_dataset");
  const userBehaviorDataset = datasetRecord(datasetProvenance, "user_behavior_training_dataset");

  const rag = aimlData?.rag ?? {};
  const llm = aimlData?.llm ?? {};

  return (
    <>
    <ShellCard className="flex min-h-[460px] h-full flex-col p-4 gap-4">
      {/* Section 1 */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
        {renderGroup(groups, "Core ML", "grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4", setSelectedMetric)}
      </div>

      {/* Section 2 */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
        {renderGroup(groups, "ML-based UABV", "grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4", setSelectedMetric)}
      </div>

      {/* Section 3 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup(groups, "RAG Performance", "grid grid-cols-1 gap-4 sm:grid-cols-2", setSelectedMetric)}
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup(groups, "LLM Performance", "grid grid-cols-1 gap-4 sm:grid-cols-2", setSelectedMetric)}
        </div>
      </div>

      {/* Section 4 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup(groups, "Human-in-the-Loop", "grid grid-cols-1 gap-4 sm:grid-cols-2", setSelectedMetric)}
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup(groups, "Trust & Reliability", "grid grid-cols-1 gap-4 sm:grid-cols-2", setSelectedMetric)}
        </div>
      </div>

      {/* New bottom shell card */}
        <ShellCard className="h-[28vh] p-4">
          <div className="flex h-full flex-col">
            <div className="mb-3 shrink-0">
              <h2 className="text-2xl font-bold text-slate-100 md:text-3xl">
                Datasets / RAG / LLM 
              </h2>
            </div>
        
            <div className="grid min-h-0 flex-1 grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="All Datasets"
                  lines={[
                    { label: "Total", value: valueOrNA(summary.total_records_all_datasets) },
                    { label: "Synthetic", value: valueOrNA(summary.synthetic_records_all_datasets) },
                    { label: "Real", value: valueOrNA(summary.real_records_all_datasets) },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="Server Dataset"
                  lines={[
                    { label: "Total", value: valueOrNA(serverDataset.total_records) },
                    { label: "Synthetic", value: valueOrNA(serverDataset.synthetic_records) },
                    { label: "Real", value: valueOrNA(serverDataset.real_records) },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="Workstation Dataset"
                  lines={[
                    { label: "Total", value: valueOrNA(workstationDataset.total_records) },
                    { label: "Synthetic", value: valueOrNA(workstationDataset.synthetic_records) },
                    { label: "Real", value: valueOrNA(workstationDataset.real_records) },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="User Behavior Dataset"
                  lines={[
                    { label: "Total", value: valueOrNA(userBehaviorDataset.total_records) },
                    { label: "Synthetic", value: valueOrNA(userBehaviorDataset.synthetic_records) },
                    { label: "Real", value: valueOrNA(userBehaviorDataset.real_records) },
                  ]}
                />
              </div>
        
                <div className="min-h-0 h-full">
                  <SpecCard
                    title="RAG"
                    subtitle=""
                    icon={<Database className="h-5 w-5" />}
                    lines={[
                      `Vector Database: ${rag.vector_database ?? "ChromaDB"}`,
                      `Text Embedding Model: ${rag.text_embedding_model ?? "nomic-embed-text:latest"}`,  
                    ]}
                  />
                </div>
                
                <div className="min-h-0 h-full">
                  <SpecCard
                    title="LLM"
                    subtitle=""
                    icon={<Sparkles className="h-5 w-5" />}
                    lines={[
                      `Deployment Style: ${llm.deployment_style ?? "Local LLM - Llama"}`,
                      `Model: ${llm.model ?? "Qwen 33"}`,
                      `Parameters: ${llm.parameters ?? "14B"}`,
                      
                    ]}
                  />
                </div>
            </div>
          </div>
        </ShellCard>
    </ShellCard>
    <KpiDetailModal metric={selectedMetric} onClose={() => setSelectedMetric(null)} />
    </>
  );
}


export default function AIML() {
  const YEAR = 2026;

  const initialSnapshotRequestedRef = useRef(false);
  const [, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [aimlData, setAimlData] = useState<AimlDashboardDTO | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(0);

  const refreshAll = async (createSnapshot = false) => {
    try {
      setErr(null);

      const [raw, sys, aiml] = await Promise.all([
        apiGetDashboardRaw(YEAR),
        apiGetSystemStatus(YEAR),
        createSnapshot ? apiCreateAimlSnapshot(YEAR) : apiGetAimlDashboard(YEAR),
      ]);

      setDashboardRaw(raw);
      setSystemStatus(sys);
      setAimlData(aiml);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    const syncSelectedStep = () => {
      const h = (window.location.hash || "").toLowerCase();

      if (h.startsWith("#/scope")) setSelectedStep(1);
      else if (h.startsWith("#/assets")) setSelectedStep(2);
      else if (h.startsWith("#/threats")) setSelectedStep(3);
      else if (h.startsWith("#/controls")) setSelectedStep(4);
      else if (h.startsWith("#/risk-analysis")) setSelectedStep(5);
      else if (h.startsWith("#/risk-evaluation-treatment")) setSelectedStep(6);
      else if (h.startsWith("#/annex-a-soa")) setSelectedStep(7);
      else if (h.startsWith("#/action-plan-implementation")) setSelectedStep(8);
      else if (h.startsWith("#/monitoring-improvement")) setSelectedStep(9);
      else if (h.startsWith("#/final-deliverables")) setSelectedStep(10);
      else setSelectedStep(0);
    };

    syncSelectedStep();
    if (!initialSnapshotRequestedRef.current) {
      initialSnapshotRequestedRef.current = true;
      void refreshAll(true);
    } else {
      void refreshAll(false);
    }

    const onHashChange = () => {
      syncSelectedStep();
    };

    const onFocus = () => {
      void refreshAll(false);
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void refreshAll(false);
      }
    };

    window.addEventListener("hashchange", onHashChange);
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.removeEventListener("hashchange", onHashChange);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#070A12] text-slate-50">
      {/* Mobile / small screens */}
      <div className="xl:hidden">
        <aside className="border-b border-white/10 bg-[#060815]">
          <div className="px-5 py-5">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-xl bg-sky-500/15 ring-1 ring-sky-500/25">
                <ShieldCheck className="h-5 w-5 text-sky-200" />
              </div>
              <div>
                <div className="text-lg font-semibold tracking-tight">ISO 27001</div>
                <div className="text-sm text-slate-400">Audit Lifecycle</div>
              </div>
            </div>
          </div>

          <nav className="grid grid-cols-1 gap-1 px-3 pb-3 sm:grid-cols-2">
            {LEFT_MENU_STEPS.map((item) => {
              const active = selectedStep === item.step;
              return (
                <button
                  type="button"
                  key={item.step}
                  onClick={() => {
                    window.location.hash = item.href;
                  }}
                  className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm ${
                    active ? "bg-white/5 ring-1 ring-white/10" : "hover:bg-white/5"
                  }`}
                >
                  <span
                    className={`grid h-7 w-7 place-items-center rounded-lg text-xs ${
                      active
                        ? "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25"
                        : "bg-white/5 text-slate-300 ring-1 ring-white/10"
                    }`}
                  >
                    {item.step}
                  </span>
                  <span className={`${active ? "text-slate-50" : "text-slate-200"}`}>
                    {item.name}
                  </span>
                </button>
              );
            })}
          </nav>

          <div className="px-4 pb-4 space-y-2">
            <button
              onClick={() => (window.location.hash = "#/ai-ml")}
              className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
            >
              AI/ML Dashboard
            </button>
            <button
              onClick={() => (window.location.hash = "#/dashboard")}
              className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
            >
              Dashboard
            </button>
          </div>
        </aside>

        <main className="px-4 py-4">
          <header className="mb-4">
            <div className="rounded-2xl border border-white/10 bg-[#070A12] py-4 text-center ring-1 ring-white/10">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                ISO 27001 Audit Readiness Dashboard
              </h1>
            </div>
          </header>

          <DashboardSections aimlData={aimlData} />

          {err ? (
            <div className="mt-4 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
              Error: {err}
            </div>
          ) : null}
        </main>
      </div>

      {/* Desktop / large screens */}
      <div className="hidden h-screen overflow-hidden xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1fr)] xl:grid-rows-[auto_auto_auto_auto_minmax(420px,1fr)]">
        {/* Section 1 */}
        <aside className="col-[1] row-[1/6] border-r border-white/10 bg-[#060815]">
          <div className="flex h-full min-h-0 flex-col">
            <div className="px-6 py-6">
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-xl bg-sky-500/15 ring-1 ring-sky-500/25">
                  <ShieldCheck className="h-5 w-5 text-sky-200" />
                </div>
                <div>
                  <div className="text-lg font-semibold tracking-tight">ISO 27001</div>
                  <div className="text-sm text-slate-400">Audit Lifecycle</div>
                </div>
              </div>
            </div>

            <nav className="min-h-0 flex-1 overflow-y-auto px-3">
              {LEFT_MENU_STEPS.map((item) => {
                const active = selectedStep === item.step;
                return (
                  <button
                    type="button"
                    key={item.step}
                    onClick={() => {
                      window.location.hash = item.href;
                    }}
                    className={`mb-1 flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm ${
                      active ? "bg-white/5 ring-1 ring-white/10" : "hover:bg-white/5"
                    }`}
                  >
                    <span
                      className={`grid h-7 w-7 place-items-center rounded-lg text-xs ${
                        active
                          ? "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25"
                          : "bg-white/5 text-slate-300 ring-1 ring-white/10"
                      }`}
                    >
                      {item.step}
                    </span>
                    <span className={`${active ? "text-slate-50" : "text-slate-200"}`}>
                      {item.name}
                    </span>
                  </button>
                );
              })}
            </nav>

            <div className="p-4 space-y-2">
              <button
                onClick={() => (window.location.hash = "#/ai-ml")}
                className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              >
                AI/ML Dashboard
              </button>
              <button
                onClick={() => (window.location.hash = "#/dashboard")}
                className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              >
                Dashboard
              </button>
            </div>
          </div>
        </aside>

        {/* Section 2 */}
        <div className="col-[2] row-[1/6] border-r border-white/10 bg-[#070A12]" />

        {/* Section 3 */}
        <header className="col-[3] row-[1] border-b border-white/10 bg-[#070A12]">
          <div className="flex h-[89px] items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              AI/ML Performance Dashboard
            </h1>
          </div>
        </header>

        {/* Section 4 */}
        <div className="col-[3] row-[2] p-3" />

        {/* Section 5 */}
        <div className="col-[3] row-[3] p-3 pt-0" />

        {/* Section 6 */}
        <div className="col-[3] row-[4]" />

        {/* Section 7 */}
        <div className="col-[3] row-[5] p-3 pt-0">
          <DashboardSections aimlData={aimlData} />
        </div>
      </div>
    </div>
  );
}
