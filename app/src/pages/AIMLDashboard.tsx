import React, { useEffect, useState } from "react";
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

const kpiData = [
  {
    group: "Core ML",
    metrics: [
      { title: "Role Prediction Accuracy (%)", value: 92, accent: "emerald" },
      { title: "CIA Prediction Accuracy (%)", value: 89, accent: "emerald" },
      { title: "F1 Score (Role Model)", value: 0.91, accent: "emerald" },
      { title: "Behavior Model Accuracy (%)", value: 87, accent: "emerald" },
    ],
  },
  {
    group: "ML-based UABV",
    metrics: [
      { title: "Average Behavior Risk Score", value: 3.7, accent: "amber" },
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
] as const;

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
}: {
  title: string;
  value: React.ReactNode;
  icon: React.ReactNode;
  accent: "amber" | "emerald" | "rose" | "slate" | "sky";
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

  return (
    <ShellCard className="h-full p-4">
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
}

function getGroup(groupName: string) {
  return kpiData.find((g) => g.group === groupName);
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

function renderGroup(groupName: string, colsClass: string) {
  const group = getGroup(groupName);
  if (!group) return null;

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
          />
        ))}
      </div>
    </div>
  );
}

const datasetInfo = {
  dataset_provenance: {
    total_records_all_datasets: 2060,
    synthetic_records_all_datasets: 1800,
    real_records_all_datasets: 260,
  },
  datasets: {
    server_role_training_dataset: {
      total_records: 940,
      synthetic_records: 800,
      real_records: 140,
    },
    workstation_role_training_dataset: {
      total_records: 820,
      synthetic_records: 700,
      real_records: 120,
    },
    user_behavior_training_dataset: {
      total_records: 300,
      synthetic_records: 300,
      real_records: 0,
    },
  },
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

function DashboardSections() {
  return (
    <ShellCard className="flex min-h-[460px] h-full flex-col p-4 gap-4">
      {/* Section 1 */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
        {renderGroup("Core ML", "grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4")}
      </div>

      {/* Section 2 */}
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
        {renderGroup("ML-based UABV", "grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4")}
      </div>

      {/* Section 3 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup("RAG Performance", "grid grid-cols-1 gap-4 sm:grid-cols-2")}
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup("LLM Performance", "grid grid-cols-1 gap-4 sm:grid-cols-2")}
        </div>
      </div>

      {/* Section 4 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup("Human-in-the-Loop", "grid grid-cols-1 gap-4 sm:grid-cols-2")}
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-xl ring-1 ring-white/10">
          {renderGroup("Trust & Reliability", "grid grid-cols-1 gap-4 sm:grid-cols-2")}
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
                    { label: "Total", value: 2060 },
                    { label: "Synthetic", value: 1800 },
                    { label: "Real", value: 260 },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="Server Dataset"
                  lines={[
                    { label: "Total", value: 940 },
                    { label: "Synthetic", value: 800 },
                    { label: "Real", value: 140 },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="Workstation Dataset"
                  lines={[
                    { label: "Total", value: 820 },
                    { label: "Synthetic", value: 700 },
                    { label: "Real", value: 120 },
                  ]}
                />
              </div>
        
              <div className="min-h-0 h-full">
                <MiniInfoCard
                  title="User Behavior Dataset"
                  lines={[
                    { label: "Total", value: 300 },
                    { label: "Synthetic", value: 300 },
                    { label: "Real", value: 0 },
                  ]}
                />
              </div>
        
                <div className="min-h-0 h-full">
                  <SpecCard
                    title="RAG"
                    subtitle=""
                    icon={<Database className="h-5 w-5" />}
                    lines={[
                      "Vector Database: ChromaDB",
                    ]}
                  />
                </div>
                
                <div className="min-h-0 h-full">
                  <SpecCard
                    title="LLM"
                    subtitle=""
                    icon={<Sparkles className="h-5 w-5" />}
                    lines={[
                      "Model: Llama 3",
                      "Version: Llama 3.1",
                      "Parameters: 8B",
                      "Deployment Style: Local LLM",
                    ]}
                  />
                </div>
            </div>
          </div>
        </ShellCard>
    </ShellCard>
  );
}


export default function AIML() {
  const YEAR = 2026;

  const [, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(0);

  const refreshAll = async () => {
    try {
      setErr(null);

      const [raw, sys] = await Promise.all([
        apiGetDashboardRaw(YEAR),
        apiGetSystemStatus(YEAR),
      ]);

      setDashboardRaw(raw);
      setSystemStatus(sys);
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
    void refreshAll();

    const onHashChange = () => {
      syncSelectedStep();
    };

    const onFocus = () => {
      void refreshAll();
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void refreshAll();
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

          <DashboardSections />

          {err ? (
            <div className="mt-4 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
              Error: {err}
            </div>
          ) : null}
        </main>
      </div>

      {/* Desktop / large screens */}
      <div className="hidden xl:grid xl:min-h-screen xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1fr)] xl:grid-rows-[auto_auto_auto_auto_minmax(420px,1fr)]">
        {/* Section 1 */}
        <aside className="col-[1] row-[1/6] border-r border-white/10 bg-[#060815]">
          <div className="flex h-full flex-col">
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

            <nav className="flex-1 px-3">
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
          <DashboardSections />
        </div>
      </div>
    </div>
  );
}