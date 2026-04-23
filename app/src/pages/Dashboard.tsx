import React, { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Plus,
  CheckCircle2,
  BadgeCheck,
  AlertTriangle,
  FileText,
} from "lucide-react";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";
type Tone = "emerald" | "sky" | "amber" | "rose" | "slate";

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
      label?: string;
      pending_approvals?: number;
    };
    high_risk_critical_impact?: {
      high_risk_count?: number;
      critical_impact_count?: number;
    };
  };
  scope_context_section2?: {
    title?: string;
    bullets?: string[];
    body?: string;
  };
  scope_file_name?: string;
};

const NAV_STEPS = [
  { step: 1, name: "Scope & Context", href: "#/scope" },
  { step: 2, name: "Asset Inventory & CIA", href: "#/assets" },
  { step: 3, name: "Threats & Vulnerabilities", href: "#/threats" },
  { step: 4, name: "Existing Controls & Posture", href: "#/controls" },
  { step: 5, name: "Risk Analysis", href: "#/risk-analysis" },
  { step: 6, name: "Risk Evaluation/Treatment", href: "#/risk-evaluation-treatment" },
  { step: 7, name: "Annex A & SoA", href: "#/annex-a-soa" },
  { step: 8, name: "Action Plan / Implementation", href: "#/action-plan-implementation" },
  { step: 9, name: "Monitoring & Improvement", href: "#/monitoring-improvement" },
] as const;

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

const STEP_TO_SECTION_KEY: Record<number, string> = {
  1: "scope_context",
  2: "assets_cia",
  3: "threats_vulns",
  4: "existing_controls_postures",
  5: "risk_analysis",
  6: "risk_evaluation_treatment",
  7: "annex_a_soa",
  8: "action_plan_implementation",
  9: "monitoring_improvement",
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

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

async function apiResetAudit(year: number): Promise<DashboardRawDTO> {
  const res = await fetch(`${API_BASE}/api/dashboard/reset-audit?_ts=${Date.now()}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    },
    body: JSON.stringify({ year }),
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as DashboardRawDTO;
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

function Pill({
  tone,
  children,
}: {
  tone: Tone;
  children: React.ReactNode;
}) {
  const map: Record<typeof tone, string> = {
    emerald: "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25",
    sky: "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/25",
    amber: "bg-orange-500/15 text-orange-200 ring-1 ring-orange-500/25",
    rose: "bg-rose-500/15 text-rose-200 ring-1 ring-rose-500/25",
    slate: "bg-white/5 text-slate-200 ring-1 ring-white/10",
  };

  return (
    <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs ${map[tone]}`}>
      {children}
    </span>
  );
}

function KpiCard({
  title,
  value,
  subtitle,
  icon,
  accent,
  progressTone,
  progressPct,
  showProgress = true,
}: {
  title: string;
  value: React.ReactNode;
  subtitle: React.ReactNode;
  icon: React.ReactNode;
  accent: Tone;
  progressTone?: Tone;
  progressPct?: number;
  showProgress?: boolean;
}) {
  const badge =
    accent === "amber"
      ? "bg-amber-500/15 ring-1 ring-amber-500/25 text-amber-200"
    : accent === "emerald"
      ? "bg-emerald-500/15 ring-1 ring-emerald-500/25 text-emerald-200"
    : accent === "rose"
      ? "bg-rose-500/15 ring-1 ring-rose-500/25 text-rose-200"
      : "bg-white/5 ring-1 ring-white/10 text-slate-200";

  const fill =
    progressTone === "amber"
      ? "bg-amber-400"
      : progressTone === "emerald"
      ? "bg-emerald-400"
      : progressTone === "rose"
      ? "bg-rose-400"
      : "bg-slate-200";

  return (
    <ShellCard className="h-full p-4">
      <div className="flex h-full items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm text-slate-300">{title}</div>
          <div className="mt-2 text-3xl font-semibold leading-none text-white sm:text-4xl">
            {value}
          </div>
          <div className="mt-2 text-sm text-slate-300">{subtitle}</div>

            {showProgress && typeof progressPct === "number" && (
              <div className="mt-3 h-2 w-full rounded-full bg-white/10">
                <div
                  className={`h-2 rounded-full ${fill}`}
                  style={{ width: `${Math.max(0, Math.min(100, progressPct))}%` }}
                />
              </div>
            )}
        </div>

        <div className={`grid h-12 w-12 shrink-0 place-items-center rounded-2xl ${badge}`}>
          {icon}
        </div>
      </div>
    </ShellCard>
  );
}

const labelTone = (s: StepStatus): Tone => {
  if (s === "Completed") return "emerald";
  if (s === "In Progress") return "amber";
  if (s === "Not Started") return "sky";
  return "rose";
};

function getReadinessTone(pct: number): "emerald" | "amber" | "sky" {
  if (Math.round(pct) === 100) return "emerald";
  if (pct >= 50) return "amber";
  return "sky";
}

export default function Dashboard() {
  const YEAR = 2026;

  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(0);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [confirmErr, setConfirmErr] = useState<string | null>(null);

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

  const lifecycle = useMemo(() => {
    return NAV_STEPS.map((s) => {
      const key = STEP_TO_SECTION_KEY[s.step];
      const status = systemStatus?.sections?.[key]?.status;

      return {
        ...s,
        status,
      };
    });
  }, [systemStatus]);

  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const displayAssetCount = dashboardRaw?.scope?.asset_count ?? 0;

  const section2Title =
    dashboardRaw?.scope_context_section2?.title ||
    "Scope & Context — Section 2 (Organizational Boundaries)";

  const section2Items = useMemo(() => {
    const bullets = dashboardRaw?.scope_context_section2?.bullets ?? [];
    return bullets
      .map((b) => (typeof b === "string" ? b.trim() : ""))
      .filter(Boolean);
  }, [dashboardRaw]);

  const section2Body = dashboardRaw?.scope_context_section2?.body?.trim() ?? "";

  const onStartNewAudit = () => {
    setConfirmErr(null);
    setConfirmOpen(true);
  };

  const onConfirmNo = () => {
    setConfirmOpen(false);
    setConfirmErr(null);
  };

  const onConfirmYes = async () => {
    try {
      setConfirmBusy(true);
      setConfirmErr(null);

      const updatedDashboard = await apiResetAudit(YEAR);
      setDashboardRaw(updatedDashboard);

      await refreshAll();

      setConfirmOpen(false);
      window.location.hash = "#/scope";
    } catch (e) {
      setConfirmErr(e instanceof Error ? e.message : String(e));
    } finally {
      setConfirmBusy(false);
    }
  };

  const readinessPct =
    ((dashboardRaw?.kpis?.readiness_score?.value ?? 0) /
      Math.max(1, dashboardRaw?.kpis?.readiness_score?.max ?? 100)) *
    100;
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

          <div className="space-y-4">
            <ShellCard className="p-4">
              <div className="flex flex-col gap-4">
                <div className="flex flex-col gap-3">
                  <div className="text-lg text-slate-300">Audit Scope:</div>

                  <div className="flex flex-col gap-3">
                    <div className="relative">
                      <select
                        value={displayScopeName}
                        disabled
                        aria-label="Audit Scope"
                        className="w-full cursor-not-allowed appearance-none rounded-xl border border-white/10 bg-white/5 px-4 py-2 pr-10 text-sm text-slate-100 opacity-90 ring-1 ring-white/10"
                      >
                        <option value={displayScopeName}>{displayScopeName}</option>
                      </select>
                      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                    </div>

                    <span className="text-sm text-slate-300">({displayAssetCount} assets)</span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={onStartNewAudit}
              >
                <Plus className="h-14 w-4" />
                Start New Audit
              </button>
            </div>

            <ShellCard className="p-4">
              <div className="text-sm font-semibold text-slate-100">{section2Title}</div>

              <div className="mt-2 text-sm leading-6 text-slate-300">
                {section2Items.length > 0 ? (
                  <ul className="list-disc space-y-1 pl-5">
                    {section2Items.map((x, idx) => (
                      <li key={idx}>{x}</li>
                    ))}
                  </ul>
                ) : section2Body ? (
                  <div>{section2Body}</div>
                ) : (
                  <span>NA</span>
                )}
              </div>
            </ShellCard>

            {dashboardRaw?.kpis ? (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <KpiCard
                  title="Audit Readiness Score"
                  value={
                    <>
                      {dashboardRaw.kpis.readiness_score?.value ?? 0}
                      <span className="text-slate-400">
                        /{dashboardRaw.kpis.readiness_score?.max ?? 100}
                      </span>
                    </>
                  }
                  subtitle={
                    <>
                      {dashboardRaw.kpis.readiness_score?.label ?? "NA"}
                    </>
                  }
                  icon={<BadgeCheck className="h-6 w-6" />}
                  accent={getReadinessTone(readinessPct) === "sky" ? "amber" : getReadinessTone(readinessPct)}
                  progressTone={getReadinessTone(readinessPct) === "sky" ? "amber" : getReadinessTone(readinessPct)}
                  progressPct={readinessPct}
                />
                <KpiCard
                  title="Evidence Coverage"
                  value={`${(dashboardRaw.kpis.evidence_coverage?.percent ?? 0).toFixed(1)}%`}
                  subtitle={
                    <>
                      {dashboardRaw.kpis.evidence_coverage?.have ?? 0}/
                      {dashboardRaw.kpis.evidence_coverage?.total ?? 0} hosts have evidence
                    </>
                  }
                  icon={<CheckCircle2 className="h-6 w-6" />}
                  accent="emerald"
                  progressTone="emerald"
                  progressPct={dashboardRaw.kpis.evidence_coverage?.percent ?? 0}
                />

                <KpiCard
                  title="Open High/Critical Risks"
                  value={dashboardRaw.kpis.open_high_critical?.count ?? 0}
                  subtitle={
                    <span className="text-rose-200">
                      {dashboardRaw.kpis.open_high_critical?.unresolved ?? 0} unresolved risks
                    </span>
                  }
                  icon={<AlertTriangle className="h-6 w-6" />}
                  accent="rose"
                  progressTone="rose"
                  progressPct={Math.min(
                    100,
                    (dashboardRaw.kpis.open_high_critical?.count ?? 0) * 5
                  )}
                />

                <KpiCard
                  title="SoA Status"
                  value={dashboardRaw.kpis.soa?.status ?? "NA"}
                  subtitle={
                    <>
                      {dashboardRaw.kpis.soa?.label ?? "NA"} •{" "}
                      {dashboardRaw.kpis.soa?.pending_approvals ?? 0} pending approvals
                    </>
                  }
                  icon={<FileText className="h-6 w-6" />}
                  accent="amber"
                  progressTone="amber"
                  progressPct={Math.min(
                    100,
                    (dashboardRaw.kpis.soa?.pending_approvals ?? 0) * 7
                  )}
                />
              </div>
            ) : null}

            <ShellCard className="p-6">
              <div className="flex items-center justify-between">
                <div className="text-lg font-semibold">ISO 27001 Audit Lifecycle</div>
              </div>

              <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
                {lifecycle.map((s) => (
                  <div
                    key={s.step}
                    className="flex min-w-0 items-center justify-between gap-3 rounded-xl bg-white/5 px-4 py-3 ring-1 ring-white/10"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-white/10 text-xs ring-1 ring-white/10">
                        {s.step}
                      </div>
                      <div className="truncate text-sm text-slate-100">{s.name}</div>
                    </div>

                    {s.status ? (
                      <Pill tone={labelTone(s.status)}>{s.status}</Pill>
                    ) : (
                      <Pill tone="slate">NA</Pill>
                    )}
                  </div>
                ))}
              </div>
            </ShellCard>

            {err ? (
              <div className="rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Error: {err}
              </div>
            ) : null}
          </div>
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
              ISO 27001 Audit Readiness Dashboard
            </h1>
          </div>
        </header>

        {/* Section 4 */}
        <div className="col-[3] row-[2] p-3">
          <div className="flex min-h-[71px] flex-wrap items-center justify-between gap-4">
            <ShellCard className="flex min-h-[71px] min-w-0 flex-1 items-center px-4">
              <div className="flex w-full flex-wrap items-center gap-4">
                <div className="flex min-w-0 flex-wrap items-center gap-3">
                  <div className="text-xl text-slate-300">Audit Scope:</div>

                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <div className="relative min-w-[280px] max-w-[480px] flex-1">
                      <select
                        value={displayScopeName}
                        disabled
                        aria-label="Audit Scope"
                        className="w-full cursor-not-allowed appearance-none rounded-xl border border-white/10 bg-white/5 px-4 py-2 pr-10 text-sm text-slate-100 opacity-90 ring-1 ring-white/10"
                      >
                        <option value={displayScopeName}>{displayScopeName}</option>
                      </select>
                      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                    </div>

                    <span className="text-sm text-slate-300">({displayAssetCount} assets)</span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex min-h-[71px] items-center justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={onStartNewAudit}
              >
                <Plus className="h-14 w-4" />
                Start New Audit
              </button>
            </div>
          </div>
        </div>

        {/* Section 5 */}
        <div className="col-[3] row-[3] p-3 pt-0">
          <ShellCard className="min-h-[161px] p-4">
            <div className="text-sm font-semibold text-slate-100">{section2Title}</div>

            <div className="mt-2 text-sm leading-6 text-slate-300">
              {section2Items.length > 0 ? (
                <ul className="list-disc space-y-1 pl-5">
                  {section2Items.map((x, idx) => (
                    <li key={idx}>{x}</li>
                  ))}
                </ul>
              ) : section2Body ? (
                <div>{section2Body}</div>
              ) : (
                <span>NA</span>
              )}
            </div>
          </ShellCard>
        </div>

        {/* Section 6 */}
        {dashboardRaw?.kpis ? (
          <div className="col-[3] row-[4] p-3 pt-0">
            <div className="grid min-h-[132px] grid-cols-1 gap-4 sm:grid-cols-2 2xl:grid-cols-4">
              <KpiCard
                title="Audit Readiness Score"
                value={
                  <>
                    {dashboardRaw.kpis.readiness_score?.value ?? 0}
                    <span className="text-slate-400">
                      /{dashboardRaw.kpis.readiness_score?.max ?? 100}
                    </span>
                  </>
                }
                subtitle={
                  <>
                    {dashboardRaw.kpis.readiness_score?.label ?? "NA"}
                  </>
                }
                icon={<BadgeCheck className="h-6 w-6" />}
                accent={getReadinessTone(readinessPct) === "sky" ? "amber" : getReadinessTone(readinessPct)}
                progressTone={getReadinessTone(readinessPct) === "sky" ? "amber" : getReadinessTone(readinessPct)}
                progressPct={readinessPct}
              />

              <KpiCard
                title="Evidence Coverage"
                value={`${(dashboardRaw.kpis.evidence_coverage?.percent ?? 0).toFixed(1)}%`}
                subtitle={
                  <>
                    {dashboardRaw.kpis.evidence_coverage?.have ?? 0}/
                    {dashboardRaw.kpis.evidence_coverage?.total ?? 0} hosts have evidence
                  </>
                }
                icon={<CheckCircle2 className="h-6 w-6" />}
                accent="emerald"
                progressTone="emerald"
                progressPct={dashboardRaw.kpis.evidence_coverage?.percent ?? 0}
              />

              <KpiCard
                title="High Risk / Critical (or High) Impact"
                value={
                  <>
                    {dashboardRaw?.kpis?.high_risk_critical_impact?.high_risk_count ?? 0}
                    <span className="text-slate-400">
                      /{dashboardRaw?.kpis?.high_risk_critical_impact?.critical_impact_count ?? 0}
                    </span>
                  </>
                }
                subtitle=""
                icon={<AlertTriangle className="h-6 w-6" />}
                accent="emerald"
                progressTone="rose"
                progressPct={Math.min(
                  100,
                  (dashboardRaw?.kpis?.high_risk_critical_impact?.high_risk_count ?? 0) * 5
                )}
                showProgress={false}
              />
              <KpiCard
                title="SoA Status"
                value={dashboardRaw?.kpis?.soa?.status ?? "Not Started"}
                subtitle={`${dashboardRaw?.kpis?.soa?.count ?? 0} controls`}
                icon={<FileText className="h-6 w-6" />}
                accent={
                  (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "Completed"
                    ? "emerald"
                    : (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "In Progress"
                    ? "amber"
                    : "sky"
                }
                progressTone={
                  (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "Completed"
                    ? "emerald"
                    : (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "In Progress"
                    ? "amber"
                    : "rose"
                }
                progressPct={
                  (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "Completed"
                    ? 100
                    : (dashboardRaw?.kpis?.soa?.status ?? "Not Started") === "In Progress"
                    ? 60
                    : 15
                }
              />
            </div>
          </div>
        ) : (
          <div className="col-[3] row-[4]" />
        )}

        {/* Section 7 */}
        <div className="col-[3] row-[5] p-3 pt-0">
          <ShellCard className="flex h-full min-h-[460px] flex-col p-6">
            <div className="flex items-center justify-between">
              <div className="text-lg font-semibold">ISO 27001 Audit Lifecycle</div>
            </div>

            <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2">
              {lifecycle.map((s) => (
                <div
                  key={s.step}
                  className="flex min-w-0 items-center justify-between gap-3 rounded-xl bg-white/5 px-4 py-3 ring-1 ring-white/10"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-white/10 text-xs ring-1 ring-white/10">
                      {s.step}
                    </div>
                    <div className="truncate text-sm text-slate-100">{s.name}</div>
                  </div>

                  {s.status ? (
                    <Pill tone={labelTone(s.status)}>{s.status}</Pill>
                  ) : (
                    <Pill tone="slate">NA</Pill>
                  )}
                </div>
              ))}
            </div>

            {err ? (
              <div className="mt-5 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Error: {err}
              </div>
            ) : null}
          </ShellCard>
        </div>
      </div>

      {confirmOpen ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0b1020] p-5 shadow-2xl ring-1 ring-white/10">
            <div className="text-lg font-semibold text-slate-100">Start a new audit?</div>
            <div className="mt-2 text-sm text-slate-300">
              Another audit is in progress. If you start a new audit, you will lose the current
              audit process. Continue?
            </div>

            {confirmErr ? (
              <div className="mt-3 rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Error: {confirmErr}
              </div>
            ) : null}

            <div className="mt-5 flex items-center justify-end gap-2">
              <button
                onClick={onConfirmNo}
                disabled={confirmBusy}
                className="rounded-xl px-4 py-2 text-sm font-semibold text-slate-200 transition hover:bg-white/5 disabled:opacity-60"
              >
                No
              </button>
              <button
                onClick={onConfirmYes}
                disabled={confirmBusy}
                className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600 disabled:opacity-60"
              >
                {confirmBusy ? "Resetting..." : "Yes"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
