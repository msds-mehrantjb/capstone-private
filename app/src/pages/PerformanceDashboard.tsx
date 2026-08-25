import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  BarChart3,
  Brain,
  Clock3,
  Cpu,
  Database,
  HardDrive,
  Layers3,
  MemoryStick,
  Monitor,
  ShieldCheck,
} from "lucide-react";
import {
  PERFORMANCE_EXECUTION_POINT_TOTAL,
  type PerformanceModelSummary,
  type PerformanceTelemetryRecord,
} from "../data/performanceTelemetry";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8003";
const YEAR = 2026;

type PerformanceDashboardResponse = {
  success: boolean;
  year: number;
  generatedAt: string;
  sourceFile: string;
  telemetryEnabled: boolean;
  droppedEventCount: number;
  catalogCoverage: {
    represented: number;
    total: number;
  };
  summary: {
    totalExecutionPoints: number;
    totalObservedDurationMs: number;
    averageLlmDurationMs: number | null;
    averageRagDurationMs: number | null;
    p95DurationMs: number | null;
    slowestOperationId: string | null;
  };
  modelSummaries: PerformanceModelSummary[];
  records: PerformanceTelemetryRecord[];
  sectionSummaries: Array<{
    section: string;
    executionPointCount: number;
    callCount: number;
    successCount: number;
    failureCount: number;
    totalDurationMs: number;
  }>;
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

const SECTION_ORDER = [
  "RAG Infrastructure",
  "Asset Inventory & CIA",
  "Threats & Vulnerabilities",
  "Risk Evaluation & Treatment",
  "Annex A & SoA",
  "Action Plan & Implementation",
  "Monitoring & Improvement",
] as const;

function selectedStepFromHash() {
  const h = (window.location.hash || "").toLowerCase();
  const item = LEFT_MENU_STEPS.find((step) => h.startsWith(step.href));
  return item?.step ?? 0;
}

function formatDuration(value: number | null) {
  if (value === null) return "NA";
  if (value >= 1000) return `${Number((value / 1000).toFixed(1))}s`;
  return `${Math.round(value)}ms`;
}

function averageDuration(records: PerformanceTelemetryRecord[]) {
  const values = records
    .map((record) => record.averageDurationMs)
    .filter((value): value is number => value !== null);
  if (values.length === 0) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function numericDuration(value: number | null) {
  return value ?? -1;
}

function ShellCard({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-2xl border border-white/10 bg-white/[0.035] ring-1 ring-white/10 ${className}`}
    >
      {children}
    </section>
  );
}

function KpiCard({
  title,
  value,
  detail,
  icon,
  tone,
}: {
  title: string;
  value: React.ReactNode;
  detail: React.ReactNode;
  icon: React.ReactNode;
  tone: "indigo" | "sky" | "emerald" | "amber" | "rose";
}) {
  const toneClass =
    tone === "indigo"
      ? "bg-indigo-500/15 text-indigo-100 ring-indigo-400/25"
      : tone === "sky"
        ? "bg-sky-500/15 text-sky-100 ring-sky-400/25"
        : tone === "emerald"
          ? "bg-emerald-500/15 text-emerald-100 ring-emerald-400/25"
          : tone === "rose"
            ? "bg-rose-500/15 text-rose-100 ring-rose-400/25"
            : "bg-amber-500/15 text-amber-100 ring-amber-400/25";

  return (
    <ShellCard className="min-w-0 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm text-slate-400">{title}</div>
          <div className="mt-2 truncate text-2xl font-bold tracking-tight text-slate-50">
            {value}
          </div>
          <div className="mt-1 truncate text-xs text-slate-500">{detail}</div>
        </div>
        <div className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ring-1 ${toneClass}`}>
          {icon}
        </div>
      </div>
    </ShellCard>
  );
}

function Sidebar({ selectedStep }: { selectedStep: number }) {
  return (
    <aside className="border-white/10 bg-[#060815] xl:col-[1] xl:row-[1/6] xl:border-r">
      <div className="flex h-full min-h-0 flex-col">
        <div className="px-5 py-5 xl:px-6 xl:py-6">
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

        <nav className="grid grid-cols-1 gap-1 px-3 pb-3 sm:grid-cols-2 xl:block xl:min-h-0 xl:flex-1 xl:overflow-y-auto xl:pb-0">
          {LEFT_MENU_STEPS.map((item) => {
            const active = selectedStep === item.step;
            return (
              <button
                type="button"
                key={item.step}
                onClick={() => {
                  window.location.hash = item.href;
                }}
                className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm xl:mb-1 ${
                  active ? "bg-indigo-600/15 ring-1 ring-indigo-400/45" : "hover:bg-white/5"
                }`}
              >
                <span
                  className={`grid h-7 w-7 place-items-center rounded-lg text-xs ${
                    active
                      ? "bg-indigo-600 text-white ring-1 ring-indigo-400/50"
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

        <div className="space-y-2 px-4 pb-4 xl:p-4">
          <button
            type="button"
            onClick={() => (window.location.hash = "#/performance")}
            className="w-full rounded-xl bg-indigo-600 px-4 py-2 text-sm font-semibold text-white ring-1 ring-indigo-300/60 transition hover:bg-indigo-500"
            aria-current="page"
          >
            Performance Dashboard
          </button>
          <button
            type="button"
            onClick={() => (window.location.hash = "#/ai-ml")}
            className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
          >
            AI/ML Dashboard
          </button>
          <button
            type="button"
            onClick={() => (window.location.hash = "#/dashboard")}
            className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
          >
            Dashboard
          </button>
        </div>
      </div>
    </aside>
  );
}

export default function PerformanceDashboard() {
  const [selectedStep, setSelectedStep] = useState<number>(() => selectedStepFromHash());
  const [records, setRecords] = useState<PerformanceTelemetryRecord[]>([]);
  const [expectedExecutionPoints, setExpectedExecutionPoints] = useState(PERFORMANCE_EXECUTION_POINT_TOTAL);
  const [modelSummaries, setModelSummaries] = useState<PerformanceModelSummary[]>([]);

  useEffect(() => {
    const onHashChange = () => setSelectedStep(selectedStepFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const loadTelemetry = useCallback(async () => {
    try {
      const response = await fetch(
        `${API_BASE}/api/performance-dashboard?year=${YEAR}&_ts=${Date.now()}`
      );
      if (!response.ok) {
        throw new Error(`Performance telemetry request failed (${response.status})`);
      }
      const data = (await response.json()) as PerformanceDashboardResponse;
      setRecords(Array.isArray(data.records) ? data.records : []);
      setModelSummaries(Array.isArray(data.modelSummaries) ? data.modelSummaries : []);
      setExpectedExecutionPoints(data.catalogCoverage?.total ?? PERFORMANCE_EXECUTION_POINT_TOTAL);
    } catch (error) {
      setRecords([]);
      setModelSummaries([]);
      console.error(error);
    }
  }, []);

  useEffect(() => {
    void loadTelemetry();
  }, [loadTelemetry]);

  const kpis = useMemo(() => {
    const totalElapsed = records.reduce(
      (sum, record) => sum + record.totalDurationMs,
      0
    );
    const llmAverage = averageDuration(
      records.filter((record) => record.kind === "LLM Reasoning")
    );
    const ragAverage = averageDuration(
      records.filter((record) => record.kind === "RAG Retrieval")
    );
    const maxP95 = records.reduce(
      (max, record) => Math.max(max, record.p95DurationMs ?? 0),
      0
    );
    const slowest = [...records].sort(
      (a, b) => numericDuration(b.averageDurationMs) - numericDuration(a.averageDurationMs)
    )[0] ?? null;

    return {
      totalExecutionPoints: records.length,
      totalElapsed,
      llmAverage,
      ragAverage,
      maxP95,
      slowest,
    };
  }, [records]);

  const sectionSummaries = useMemo(() => {
    const maxTotal = Math.max(
      ...SECTION_ORDER.map((name) =>
        records
          .filter((record) => record.section === name)
          .reduce((sum, record) => sum + record.totalDurationMs, 0)
      ),
      1
    );

    return SECTION_ORDER.map((name) => {
      const sectionRecords = records.filter((record) => record.section === name);
      const totalDurationMs = sectionRecords.reduce((sum, record) => sum + record.totalDurationMs, 0);
      return {
        name,
        count: sectionRecords.length,
        totalDurationMs,
        pct: Math.max(4, (totalDurationMs / maxTotal) * 100),
      };
    });
  }, [records]);

  const qwenSummaries = useMemo(() => {
    const configuredSummaries = modelSummaries.filter((summary) => summary.configured);
    if (configuredSummaries.length > 0) return configuredSummaries;
    return modelSummaries.filter((summary) =>
      (summary.modelFamily ?? "").toLowerCase().startsWith("qwen")
    );
  }, [modelSummaries]);

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#070A12] text-slate-50">
      <div className="xl:hidden">
        <Sidebar selectedStep={selectedStep} />
        <main className="max-w-full px-3 py-4 sm:px-4">
          <DashboardContent
            expectedExecutionPoints={expectedExecutionPoints}
            kpis={kpis}
            modelSummaries={qwenSummaries}
            sectionSummaries={sectionSummaries}
          />
        </main>
      </div>

      <div className="hidden xl:grid xl:h-screen xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1fr)] xl:grid-rows-[auto_minmax(0,1fr)] xl:overflow-hidden">
        <Sidebar selectedStep={selectedStep} />
        <div className="col-[2] row-[1/3] border-r border-white/10 bg-[#070A12]" />
        <header className="col-[3] row-[1] border-b border-white/10 bg-[#070A12]">
          <div className="flex h-[89px] items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              LLM & RAG Performance Dashboard
            </h1>
          </div>
        </header>
        <main className="col-[3] row-[2] min-h-0 max-w-full overflow-y-auto overflow-x-hidden px-6 py-5">
          <DashboardContent
            expectedExecutionPoints={expectedExecutionPoints}
            kpis={kpis}
            modelSummaries={qwenSummaries}
            sectionSummaries={sectionSummaries}
          />
        </main>
      </div>
    </div>
  );
}

type KpiValues = {
  totalExecutionPoints: number;
  totalElapsed: number;
  llmAverage: number | null;
  ragAverage: number | null;
  maxP95: number;
  slowest: PerformanceTelemetryRecord | null;
};

type SectionSummary = {
  name: string;
  count: number;
  totalDurationMs: number;
  pct: number;
};

function HardwareMetric({
  detail,
  icon,
  label,
  value,
}: {
  detail?: string;
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="min-w-0 rounded-xl bg-[#060815] p-3 ring-1 ring-white/10">
      <div className="flex items-start gap-3">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-sky-500/10 text-sky-100 ring-1 ring-sky-400/20">
          {icon}
        </div>
        <div className="min-w-0">
          <div className="text-xs font-semibold uppercase text-slate-500">{label}</div>
          <div className="mt-1 truncate text-sm font-semibold text-slate-100" title={value}>
            {value}
          </div>
          {detail ? <div className="mt-1 truncate text-xs text-slate-500" title={detail}>{detail}</div> : null}
        </div>
      </div>
    </div>
  );
}

function DashboardContent({
  expectedExecutionPoints,
  kpis,
  modelSummaries,
  sectionSummaries,
}: {
  expectedExecutionPoints: number;
  kpis: KpiValues;
  modelSummaries: PerformanceModelSummary[];
  sectionSummaries: SectionSummary[];
}) {
  return (
    <div className="space-y-4">
      <header className="xl:hidden">
        <div className="rounded-2xl border border-white/10 bg-[#070A12] px-3 py-4 text-center ring-1 ring-white/10">
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            LLM & RAG Performance Dashboard
          </h1>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <ShellCard className="p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Brain className="h-4 w-4 text-indigo-200" />
            Qwen Configuration
          </div>
          {modelSummaries.length > 0 ? (
            <div className="grid grid-cols-1 gap-3">
              {modelSummaries.map((summary) => (
                <div key={`${summary.provider ?? "provider"}:${summary.model}`} className="rounded-xl bg-[#060815] p-3 ring-1 ring-indigo-400/20">
                  <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <div className="truncate font-mono text-sm font-semibold text-slate-100" title={summary.model}>
                        {summary.model}
                      </div>
                      <div className="mt-1 text-xs text-slate-400">
                        Provider: {summary.provider ?? "NA"} / Family: {summary.modelFamily ?? "NA"} / Parameter size: {summary.parameterSize ?? "NA"}
                      </div>
                    </div>
                    <span className="mt-2 inline-flex w-max rounded-full bg-indigo-500/10 px-2.5 py-1 text-xs font-semibold text-indigo-100 ring-1 ring-indigo-400/25 sm:mt-0">
                      {summary.configured
                        ? "Configured model"
                        : summary.callCount > 0
                        ? `${summary.callCount} reasoning calls`
                        : "Configured model"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl bg-[#060815] px-4 py-5 text-sm text-slate-400 ring-1 ring-white/10">
              No Qwen model executions have been captured yet. Run a Qwen-backed generation to populate this summary.
            </div>
          )}
        </ShellCard>

        <ShellCard className="p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Cpu className="h-4 w-4 text-sky-200" />
            Hardware Configuration
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <HardwareMetric
              label="CPU"
              value="13th Gen Intel(R) Core(TM) i9-13900K"
              detail="24 cores / 32 logical processors"
              icon={<Cpu className="h-4 w-4" />}
            />
            <HardwareMetric
              label="GPU"
              value="NVIDIA GeForce RTX 4070 Ti"
              detail="16 GB VRAM"
              icon={<Monitor className="h-4 w-4" />}
            />
            <HardwareMetric
              label="RAM"
              value="32 GB"
              detail="DDR5"
              icon={<MemoryStick className="h-4 w-4" />}
            />
            <HardwareMetric
              label="HDD"
              value="Samsung SSD 980 PRO 1TB"
              detail="Disk 1 / Online / Healthy"
              icon={<HardDrive className="h-4 w-4" />}
            />
          </div>
        </ShellCard>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 2xl:grid-cols-6">
        <KpiCard
          title="Total Execution Points"
          value={kpis.totalExecutionPoints}
          detail={`${expectedExecutionPoints} expected`}
          icon={<Layers3 className="h-5 w-5" />}
          tone="indigo"
        />
        <KpiCard
          title="Total Elapsed Time"
          value={formatDuration(kpis.totalElapsed)}
          detail="Sum of captured totals"
          icon={<Clock3 className="h-5 w-5" />}
          tone="sky"
        />
        <KpiCard
          title="Avg LLM Reasoning Time"
          value={formatDuration(kpis.llmAverage)}
          detail="Mean of captured averages"
          icon={<Brain className="h-5 w-5" />}
          tone="indigo"
        />
        <KpiCard
          title="Avg RAG/Retrieval Time"
          value={formatDuration(kpis.ragAverage)}
          detail="Mean of retrieval averages"
          icon={<Database className="h-5 w-5" />}
          tone="emerald"
        />
        <KpiCard
          title="P95 Duration"
          value={formatDuration(kpis.maxP95)}
          detail="Highest captured p95"
          icon={<BarChart3 className="h-5 w-5" />}
          tone="amber"
        />
        <KpiCard
          title="Slowest Operation"
          value={formatDuration(kpis.slowest?.averageDurationMs ?? null)}
          detail={kpis.slowest?.operation ?? "No runs captured yet"}
          icon={<Activity className="h-5 w-5" />}
          tone="rose"
        />
      </div>

      <ShellCard className="p-4">
        <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-sm font-semibold text-slate-100">Section Summary</div>
          <div className="text-xs text-slate-500">Aggregated captured total time</div>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {sectionSummaries.map((summary) => (
            <div key={summary.name} className="rounded-xl bg-[#060815] p-3 ring-1 ring-white/10">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0 truncate text-sm font-semibold text-slate-100">
                  {summary.name}
                </div>
                <div className="shrink-0 text-xs text-slate-400">
                  {summary.count} rows / {formatDuration(summary.totalDurationMs)}
                </div>
              </div>
              <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-indigo-400/80"
                  style={{ width: `${summary.pct}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </ShellCard>
    </div>
  );
}
