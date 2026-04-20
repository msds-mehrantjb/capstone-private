import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Plus,
  Database,
  CircleCheck,
  Send,
  AlertTriangle,
  Activity,
} from "lucide-react";

type SeverityValue = "Critical" | "High" | "Medium" | "Low" | "Unscanned";
type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type ChatMessage = { role: "user" | "assistant"; content: string };

type Kpi = {
  title: string;
  value: string;
  icon: React.ReactNode;
  accent: "amber" | "emerald" | "rose" | "slate";
};

type TrainResponse = {
  success?: boolean;
  message?: string;
  dataset_path?: string;
  model_path?: string;
  label_encoder_path?: string;
  accuracy?: number;
};

type RiskFinding = {
  cve: string;
  vulnerability: string;
  cvssScore: string | number;
  ciaRating: SeverityValue;
  likelihood: SeverityValue;
  risk: SeverityValue;
  riskScore?: number;

  exploitAvailable?: string;
  patchStatus?: string;
  exposure?: string;
  mlProbability?: number | string;
  likelihoodScore?: number | string;

  cvssNormalized?: number | string;
  exploitNormalized?: number | string;
  patchNormalized?: number | string;
  exposureNormalized?: number | string;
  roleNormalized?: number | string;
  ciaNormalized?: number | string;

  userBehavior?: {
    failedLoginAttempts?: number;
    accessFrequency?: number;
    loginConsistency?: number;
    passwordResets?: number;
    sessionDuration?: number;
    behaviorRiskScore?: number;
    rule_score?: number;
    ml_score?: number;
    likelihood?: string;
  };
};

type RiskHostRow = {
  hostname: string;
  role: string;
  location: string;
  impact: SeverityValue;
  likelihood: SeverityValue;
  risk: SeverityValue;
  ipAddress?: string;
  openPorts?: Array<number | string>;
  runningServices?: string[];
  installedSoftware?: string[];
  department?: string;

  ciaWeight?: number | string;
  mlProbability?: number | string;
  likelihoodScore?: number | string;
  roleWeight?: number | string;

  findings: RiskFinding[];
};

type SelectedFinding = {
  hostname: string;
  index: number;
};

type SystemStatusDTO = {
  meta: { name: string; version: string };
  sections: Record<string, { status: StepStatus; scope_file_name?: string }>;
};

type DashboardRawDTO = {
  scope?: {
    name?: string;
    asset_count?: number;
  };
  scope_context_section2?: {
    title?: string;
    bullets?: string[];
    body?: string;
  };
};

type AnalysisResponse = {
  success?: boolean;
  message?: string;
  inventory?: any;
  processed_hosts?: number;
};

type SetRiskResponse = {
  success?: boolean;
  message?: string;
  inventory?: any;
  hostname?: string;
  cve?: string;
  risk?: SeverityValue;
};

type DeleteResponse = {
  success?: boolean;
  message?: string;
  inventory?: any;
  hostname?: string;
  cve?: string;
};

type SubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: any;
  requires_confirmation?: boolean;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function apiTrainBehaviorModel(year: number): Promise<TrainResponse> {
  return apiPostJSONBody<TrainResponse>("/api/risk-analysis/train", {
    year,
    dataset_path: "data/ml/user_behavior_training_dataset.parquet",
    model_dir: "data/ml/models",
  });
}

async function apiGetJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function apiPostJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: "POST" });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}${txt ? ` - ${txt}` : ""}`);
  }
  return (await res.json()) as T;
}

async function apiPostJSONBody<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const text = await res.text();

  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }

  if (!res.ok) {
    throw new Error(data?.message || `HTTP ${res.status}`);
  }

  return data as T;
}

async function apiUnblockRiskAnalysis(year: number) {
  return apiPostJSON(`/api/risk-analysis/unblock?year=${year}`);
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>("/api/system/status");
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/summary?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetRiskInventory(year: number): Promise<any> {
  return apiGetJSON<any>(
    `/api/risk-analysis/inventory?year=${encodeURIComponent(String(year))}`
  );
}

async function apiCreateBlankRiskInventory(
  year: number,
  force?: boolean
): Promise<any> {
  const qs = new URLSearchParams({ year: String(year) });
  if (force) qs.set("force", "true");
  return apiPostJSON<any>(`/api/risk-analysis/inventory/new?${qs.toString()}`);
}

function getRiskLabelFromScore(score: number): SeverityValue {
  if (score >= 15) return "Critical";
  if (score >= 12) return "High";
  if (score >= 6) return "Medium";
  return "Low";
}

function normalizeSeverity(value?: string): SeverityValue {
  if (!value) return "Unscanned";
  const v = String(value).trim().toLowerCase();

  if (v === "critical") return "Critical";
  if (v === "high") return "High";
  if (v === "medium") return "Medium";
  if (v === "low") return "Low";
  return "Unscanned";
}

function toText(value: any, fallback = "NA"): string {
  if (value === null || value === undefined) return fallback;
  const s = String(value).trim();
  return s ? s : fallback;
}

function firstDefined(...values: any[]) {
  for (const v of values) {
    if (v !== undefined && v !== null && String(v).trim() !== "") return v;
  }
  return undefined;
}

function flattenInventoryToRows(doc: any): RiskHostRow[] {
  const rawHosts = Array.isArray(doc?.hosts) ? doc.hosts : [];
  const grouped = new Map<string, RiskHostRow>();

  rawHosts.forEach((h: any) => {
    const hostname = toText(h?.hostname, "").trim();
    if (!hostname) return;

    const role = toText(h?.role, "-");
    const location = toText(h?.location ?? h?.ip_address, "-");
    const key = hostname.toLowerCase();

    if (!grouped.has(key)) {
      grouped.set(key, {
        hostname,
        role,
        location,
        impact: normalizeSeverity(h?.impact ?? h?.["CIA rating"]),
        likelihood: normalizeSeverity(h?.likelihood),
        risk: normalizeSeverity(h?.risk),
        ipAddress: toText(h?.ip_address, ""),
        openPorts: Array.isArray(h?.open_ports) ? h.open_ports : [],
        runningServices: Array.isArray(h?.running_services) ? h.running_services : [],
        installedSoftware: Array.isArray(h?.installed_software) ? h.installed_software : [],
        department: toText(h?.department, ""),
        ciaWeight: firstDefined(h?.cia_weight, h?.CIA_weight, h?.ciaWeight, "NA"),
        mlProbability: firstDefined(h?.ml_probability, h?.ML_probability, h?.mlProbability, "NA"),
        likelihoodScore: firstDefined(
          h?.likelihood_score,
          h?.Likelihood_score,
          h?.likelihoodScore,
          "NA"
        ),
        roleWeight: firstDefined(h?.role_weight, h?.roleWeight, "NA"),
        findings: [],
      });
    }

    const row = grouped.get(key)!;

    row.impact =
      row.impact !== "Unscanned"
        ? row.impact
        : normalizeSeverity(h?.impact ?? h?.["CIA rating"]);

    row.likelihood =
      row.likelihood !== "Unscanned"
        ? row.likelihood
        : normalizeSeverity(h?.likelihood);

    row.risk =
      row.risk !== "Unscanned"
        ? row.risk
        : normalizeSeverity(h?.risk);

    if ((!row.ipAddress || row.ipAddress === "NA") && h?.ip_address) {
      row.ipAddress = toText(h?.ip_address, "");
    }

    if ((!row.department || row.department === "NA") && h?.department) {
      row.department = toText(h?.department, "");
    }

    if ((!row.openPorts || row.openPorts.length === 0) && Array.isArray(h?.open_ports)) {
      row.openPorts = h.open_ports;
    }

    if (
      (!row.runningServices || row.runningServices.length === 0) &&
      Array.isArray(h?.running_services)
    ) {
      row.runningServices = h.running_services;
    }

    if (
      (!row.installedSoftware || row.installedSoftware.length === 0) &&
      Array.isArray(h?.installed_software)
    ) {
      row.installedSoftware = h.installed_software;
    }

    if ((row.ciaWeight === "NA" || row.ciaWeight === undefined) && h?.cia_weight !== undefined) {
      row.ciaWeight = h.cia_weight;
    }

    if (
      (row.mlProbability === "NA" || row.mlProbability === undefined) &&
      h?.ml_probability !== undefined
    ) {
      row.mlProbability = h.ml_probability;
    }

    if (
      (row.likelihoodScore === "NA" || row.likelihoodScore === undefined) &&
      h?.likelihood_score !== undefined
    ) {
      row.likelihoodScore = h.likelihood_score;
    }

    if ((row.roleWeight === "NA" || row.roleWeight === undefined) && h?.role_weight !== undefined) {
      row.roleWeight = h.role_weight;
    }

    const hasFindingData =
      h?.cve !== undefined ||
      h?.vulnerability_name !== undefined ||
      h?.vulnerability !== undefined ||
      h?.cvss_score !== undefined ||
      h?.cvss !== undefined;

    if (hasFindingData) {
      const rawRiskScore =
        typeof h?.risk_score === "number"
          ? h.risk_score
          : Number(h?.risk_score ?? h?.riskScore ?? 0);

      row.findings.push({
        cve: toText(h?.cve ?? h?.CVE, "-"),
        vulnerability: toText(
          h?.vulnerability_name ?? h?.vulnerability ?? h?.title ?? h?.name,
          "-"
        ),
        cvssScore: firstDefined(h?.cvss_score, h?.cvss, h?.["CVSS Score"], "-") ?? "-",
        ciaRating: normalizeSeverity(h?.["CIA rating"] ?? h?.cia_rating ?? h?.impact),
        likelihood: normalizeSeverity(h?.likelihood ?? h?.likelihood_rating),
        risk:
          normalizeSeverity(h?.risk ?? h?.risk_rating) !== "Unscanned"
            ? normalizeSeverity(h?.risk ?? h?.risk_rating)
            : getRiskLabelFromScore(Number.isFinite(rawRiskScore) ? rawRiskScore : 0),
        riskScore: Number.isFinite(rawRiskScore) ? rawRiskScore : 0,

        exploitAvailable: toText(
          firstDefined(h?.exploit_available, h?.exploitability, h?.known_exploited),
          "NA"
        ),
        patchStatus: toText(firstDefined(h?.patch_status, h?.patching_status), "NA"),
        exposure: toText(firstDefined(h?.exposure, h?.network_exposure), "NA"),
        mlProbability: firstDefined(h?.ml_probability, h?.ML_probability, h?.mlProbability, "NA"),
        likelihoodScore: firstDefined(
          h?.likelihood_score,
          h?.Likelihood_score,
          h?.likelihoodScore,
          "NA"
        ),

        cvssNormalized: firstDefined(h?.cvss_normalized, h?.CVSS_n, h?.cvss_n, "NA"),
        exploitNormalized: firstDefined(
          h?.exploit_normalized,
          h?.Exploit_n,
          h?.exploit_n,
          "NA"
        ),
        patchNormalized: firstDefined(h?.patch_normalized, h?.Patch_n, h?.patch_n, "NA"),
        exposureNormalized: firstDefined(
          h?.exposure_normalized,
          h?.Exposure_n,
          h?.exposure_n,
          "NA"
        ),
        roleNormalized: firstDefined(h?.role_normalized, h?.Role_n, h?.role_n, "NA"),
        ciaNormalized: firstDefined(h?.cia_normalized, h?.CIA_n, h?.cia_n, "NA"),

        userBehavior: h?.user_behavior ?? {},
      });
    }
  });

  return Array.from(grouped.values());
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

function KpiCard({ kpi }: { kpi: Kpi }) {
  const badge =
    kpi.accent === "amber"
      ? "bg-amber-500/15 ring-1 ring-amber-500/25 text-amber-200"
      : kpi.accent === "emerald"
      ? "bg-emerald-500/15 ring-1 ring-emerald-500/25 text-emerald-200"
      : kpi.accent === "rose"
      ? "bg-rose-500/15 ring-1 ring-rose-500/25 text-rose-200"
      : "bg-white/5 ring-1 ring-white/10 text-slate-200";

  return (
    <ShellCard className="h-full p-4">
      <div className="flex h-full items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm text-slate-300">{kpi.title}</div>
          <div className="mt-2 text-3xl font-semibold leading-none text-white">{kpi.value}</div>
        </div>
        <div className={`grid h-12 w-12 shrink-0 place-items-center rounded-2xl ${badge}`}>
          {kpi.icon}
        </div>
      </div>
    </ShellCard>
  );
}

function SeverityPill({ value }: { value: SeverityValue }) {
  if (value === "Unscanned") return <span className="text-slate-400">-</span>;

  const map: Record<Exclude<SeverityValue, "Unscanned">, string> = {
    Critical: "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25",
    High: "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/25",
    Medium: "bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/25",
    Low: "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25",
  };

  return (
    <span className={`inline-flex items-center rounded-lg px-3 py-1 text-xs ${map[value]}`}>
      {value}
    </span>
  );
}

function Modal({
  open,
  title,
  text,
  onClose,
}: {
  open: boolean;
  title: string;
  text: string;
  onClose: () => void;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0b1020] p-6 shadow-2xl ring-1 ring-white/10">
        <div className="mb-3 text-lg font-semibold text-white">{title}</div>
        <div className="whitespace-pre-wrap text-sm text-slate-300">{text}</div>
        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
          >
            OK
          </button>
        </div>
      </div>
    </div>
  );
}

function RiskFindingsCard({
  row,
  selectedFindingIndex,
  onSelectFinding,
}: {
  row: RiskHostRow;
  selectedFindingIndex: number | null;
  onSelectFinding: (index: number) => void;
}) {
  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-[#0a0f1d] ring-1 ring-white/10">
      <div className="flex flex-wrap items-center gap-x-8 gap-y-2 border-b border-white/10 bg-[#0d1426] px-4 py-4">
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-sm font-semibold text-slate-400">Host:</span>
          <span className="break-words text-sm font-semibold text-white">
            {row.hostname || "-"}
          </span>
        </div>

        <div className="flex min-w-0 items-center gap-2">
          <span className="text-sm font-semibold text-slate-400">Role:</span>
          <span className="break-words text-sm text-slate-200">{row.role || "-"}</span>
        </div>

        <div className="flex min-w-0 items-center gap-2">
          <span className="text-sm font-semibold text-slate-400">Location:</span>
          <span className="break-words text-sm text-slate-200">{row.location || "-"}</span>
        </div>
      </div>

      <div className="bg-[#11192d]">
        {row.findings.length === 0 ? (
          <div className="px-4 py-6 text-sm text-slate-400">
            No records available for this host.
          </div>
        ) : (
          <>
            <div className="hidden overflow-x-hidden lg:block">
              <div className="grid grid-cols-[1.1fr_2.4fr_0.9fr_1fr_1fr_1fr] border-b border-white/10 bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">
                <div className="px-3 py-3">CVE</div>
                <div className="px-3 py-3">Vulnerability</div>
                <div className="px-3 py-3">CVSS Score</div>
                <div className="px-3 py-3">CIA rating</div>
                <div className="px-3 py-3">Likelihood</div>
                <div className="px-3 py-3">Risk</div>
              </div>

              {row.findings.map((f, index) => {
                const findingSelected = selectedFindingIndex === index;

                return (
                  <div
                    key={`${row.hostname}-${f.cve}-${index}`}
                    onClick={() => onSelectFinding(index)}
                    className={`grid cursor-pointer grid-cols-[1.1fr_2.4fr_0.9fr_1fr_1fr_1fr] items-center transition ${
                      findingSelected
                        ? "bg-indigo-500/15 ring-1 ring-inset ring-indigo-400/40"
                        : "bg-[#11192d] hover:bg-white/5"
                    } ${
                      index !== row.findings.length - 1 ? "border-b border-white/10" : ""
                    }`}
                  >
                    <div className="break-words px-3 py-3 text-sm text-slate-100">{f.cve}</div>
                    <div className="break-words px-3 py-3 text-sm text-slate-200">
                      {f.vulnerability}
                    </div>
                    <div className="break-words px-3 py-3 text-sm text-slate-200">
                      {String(f.cvssScore)}
                    </div>
                    <div className="px-3 py-3">
                      <SeverityPill value={f.ciaRating} />
                    </div>
                    <div className="px-3 py-3">
                      <SeverityPill value={f.likelihood} />
                    </div>
                    <div className="px-3 py-3">
                      <SeverityPill value={f.risk} />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="divide-y divide-white/10 lg:hidden">
              {row.findings.map((f, index) => {
                const findingSelected = selectedFindingIndex === index;

                return (
                  <div
                    key={`${row.hostname}-${f.cve}-${index}`}
                    onClick={() => onSelectFinding(index)}
                    className={`cursor-pointer px-4 py-3 transition ${
                      findingSelected
                        ? "bg-indigo-500/15 ring-1 ring-inset ring-indigo-400/40"
                        : "hover:bg-white/5"
                    }`}
                  >
                    <div className="grid gap-3">
                      <div className="grid gap-1">
                        <div className="text-[11px] uppercase tracking-wide text-slate-400">CVE</div>
                        <div className="break-words text-sm text-slate-100">{f.cve}</div>
                      </div>

                      <div className="grid gap-1">
                        <div className="text-[11px] uppercase tracking-wide text-slate-400">
                          Vulnerability
                        </div>
                        <div className="break-words text-sm text-slate-200">
                          {f.vulnerability}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            CVSS Score
                          </div>
                          <div className="text-sm text-slate-200">{String(f.cvssScore)}</div>
                        </div>

                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            CIA rating
                          </div>
                          <div>
                            <SeverityPill value={f.ciaRating} />
                          </div>
                        </div>

                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            Likelihood
                          </div>
                          <div>
                            <SeverityPill value={f.likelihood} />
                          </div>
                        </div>

                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            Risk
                          </div>
                          <div>
                            <SeverityPill value={f.risk} />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function RiskAnalysis() {
  const YEAR = 2026;
  const [selectedStep, setSelectedStep] = useState<number>(5);

  const [pendingCommand, setPendingCommand] = useState<
    | null
    | "confirm-reset"
    | "confirm-submit"
    | "confirm-analysis"
    | "setrisk-value"
    | "confirm-delete"
  >(null);

  const [pendingHostname, setPendingHostname] = useState<string | null>(null);
  const [pendingCve, setPendingCve] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<SelectedFinding | null>(null);

  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [rows, setRows] = useState<RiskHostRow[]>([]);

  const [popupOpen, setPopupOpen] = useState(false);
  const [popupText, setPopupText] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Risk Analysis — Command Mode\n\n" +
        "Available commands:\n" +
        "/analysis   → Run risk analysis\n" +
        "/train      → Train user behavior ML model\n" +
        "/setrisk    → Set risk for the highlighted subtable row\n" +
        "/details    → Show detailed risk information for the highlighted subtable row.\n" +
        "/delete     → Remove highlighted row from the table\n" +
        "/submit     → Finalize risk analysis results\n" +
        "/reset      → Clear the table\n" +
        "/exit       → Exit the current command mode\n" +
        "/commands   → Show all available commands\n" +
        "/help       → Explain this section",
    },
  ]);
    
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement | null>(null);

  const LEFT_MENU_ITEMS = useMemo(
    () => [
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
    ],
    []
  );

  const backendRiskStatus = systemStatus?.sections?.risk_analysis?.status;

  const riskAnalysisStatus: StepStatus = useMemo(() => {
    if (backendRiskStatus === "Completed") return "Completed";
    if (backendRiskStatus === "Blocked") return "Blocked";
    if (backendRiskStatus === "In Progress") return "In Progress";
    if (rows.length > 0) return "In Progress";
    return "Not Started";
  }, [backendRiskStatus, rows.length]);

  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const rowCount = rows.length;

  const selectedFindingContext = useMemo(() => {
    if (!selectedFinding) return null;

    const host =
      rows.find(
        (r) =>
          (r.hostname || "").trim().toLowerCase() ===
          selectedFinding.hostname.trim().toLowerCase()
      ) ?? null;

    if (!host) return null;

    const finding = host.findings[selectedFinding.index];
    if (!finding) return null;

    return { host, finding };
  }, [rows, selectedFinding]);

  const criticalImpactCount = useMemo(
    () =>
      rows.reduce((count, host) => {
        const hostCritical = host.findings?.filter((f) => f.ciaRating === "Critical").length ?? 0;
        return count + hostCritical;
      }, 0),
    [rows]
  );

  const criticalRiskCount = useMemo(
    () =>
      rows.reduce((count, host) => {
        const hostCriticalCount = host.findings?.filter((f) => f.risk === "Critical").length ?? 0;
        return count + hostCriticalCount;
      }, 0),
    [rows]
  );

  const highRiskCount = useMemo(
    () =>
      rows.reduce((count, host) => {
        const hostHighCount = host.findings?.filter((f) => f.risk === "High").length ?? 0;
        return count + hostHighCount;
      }, 0),
    [rows]
  );

  const mediumRiskCount = useMemo(
    () =>
      rows.reduce((count, host) => {
        const hostMediumCount = host.findings?.filter((f) => f.risk === "Medium").length ?? 0;
        return count + hostMediumCount;
      }, 0),
    [rows]
  );

  const orgBoundaryItems = useMemo(() => {
    return dashboardRaw?.scope_context_section2?.bullets ?? [];
  }, [dashboardRaw]);

  const kpis: Kpi[] = useMemo(
    () => [
      {
        title: "Analyzed Assets",
        value: String(rowCount),
        icon: <Database className="h-6 w-6" />,
        accent: "amber",
      },
      {
        title: "Critical Impact",
        value: String(criticalImpactCount),
        icon: <AlertTriangle className="h-6 w-6" />,
        accent: "emerald",
      },
      {
        title: "Critical / High Risk",
        value: `${criticalRiskCount} / ${highRiskCount}`,
        icon: <Activity className="h-6 w-6" />,
        accent: "slate",
      },
      {
        title: "Medium Risk",
        value: String(mediumRiskCount),
        icon: <CircleCheck className="h-6 w-6" />,
        accent: "rose",
      },
    ],
    [rowCount, criticalImpactCount, highRiskCount, mediumRiskCount]
  );

  const showPopup = (text: string) => {
    setPopupText(text);
    setPopupOpen(true);
  };

  const closePopup = () => setPopupOpen(false);

  const openConfirm = (text: string) => {
    setConfirmText(text);
    setConfirmOpen(true);
  };

  const closeConfirm = () => {
    setConfirmOpen(false);
  };

  const scrollChatToBottom = (behavior: ScrollBehavior = "smooth") => {
    requestAnimationFrame(() => {
      chatBottomRef.current?.scrollIntoView({ behavior, block: "end" });
    });
  };

  const formatList = (items?: Array<string | number>) => {
    if (!items || items.length === 0) return "NA";
    return items.map((x) => String(x)).join(", ");
  };

  const formatValue = (value: unknown) => {
    if (value === undefined || value === null) return "NA";
    const s = String(value).trim();
    return s ? s : "NA";
  };

  const formatSelectedFindingDetails = (
    row: RiskHostRow,
    f: RiskFinding
  ) => {
    const ub = f.userBehavior ?? {};

    if (String(f.vulnerability).trim().toLowerCase() === "user activity behavior") {
      return (
        `Risk Details for:\n\n` +
        `Host: ${row.hostname}\n` +
        `Vulnerability: User Activity Behavior\n` +
        `------------------------\n` +
        `CIA Rating: ${formatValue(f.ciaRating)}\n` +
        `Failed Login Attempts: ${formatValue(ub.failedLoginAttempts)}\n` +
        `Access Frequency: ${formatValue(ub.accessFrequency)}\n` +
        `Login Consistency: ${formatValue(ub.loginConsistency)}\n` +
        `Password Resets: ${formatValue(ub.passwordResets)}\n` +
        `Session Duration: ${formatValue(ub.sessionDuration)}\n` +
        `Rule Score: ${formatValue(ub.rule_score)}\n` +
        `ML Score: ${formatValue(ub.ml_score)}\n` +
        `Behavior Risk Score: ${formatValue(ub.behaviorRiskScore)}\n` +
        `------------------------\n` +
        `Likelihood: ${formatValue(ub.likelihood ?? f.likelihood)}\n` +
        `Risk Score: ${formatValue(f.riskScore)}\n` +
        `Risk: ${formatValue(f.risk)}`
      );
    }

    return (
      `Risk Details for:\n\n` +
      `Host: ${row.hostname}\n` +
      `CVE: ${formatValue(f.cve)}\n` +
      `------------------------\n` +
      `Vulnerability: ${formatValue(f.vulnerability)}\n` +
      `CVSS: ${formatValue(f.cvssScore)}\n` +
      `CIA Rating: ${formatValue(f.ciaRating)}\n` +
      `Exploit Available: ${formatValue(f.exploitAvailable)}\n` +
      `Patch Status: ${formatValue(f.patchStatus)}\n` +
      `Exposure: ${formatValue(f.exposure)}\n` +
      `Open Ports: ${formatList(row.openPorts)}\n` +
      `------------------------\n` +
      `Likelihood: ${formatValue(f.likelihood)}\n` +
      `Risk Score: ${formatValue(f.riskScore)}\n` +
      `Risk: ${formatValue(f.risk)}`
    );
  };
    
  const refreshInventoryRows = async () => {
    const doc = await apiGetRiskInventory(YEAR);
    const nextRows = flattenInventoryToRows(doc);
    setRows(nextRows);

    if (selectedFinding) {
      const host = nextRows.find(
        (r) =>
          r.hostname.trim().toLowerCase() === selectedFinding.hostname.trim().toLowerCase()
      );
      if (!host || !host.findings[selectedFinding.index]) {
        setSelectedFinding(null);
      }
    }
  };

  const refreshDashboardRaw = async () => {
    try {
      const raw = await apiGetDashboardRaw(YEAR);
      setDashboardRaw(raw);
    } catch {
      setDashboardRaw(null);
    }
  };

  const handleCreateNewRiskAnalysis = async () => {
    try {
      await apiCreateBlankRiskInventory(YEAR, true);

      const doc = await apiGetRiskInventory(YEAR);
      const nextRows = flattenInventoryToRows(doc);
      setRows(nextRows);
      setSelectedFinding(null);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "A new risk analysis is started.",
        },
      ]);
    } catch (e) {
      showPopup(e instanceof Error ? e.message : String(e));
    } finally {
      closeConfirm();
      scrollChatToBottom();
    }
  };

  const handleNewRiskAnalysisClick = async () => {
    try {
      if (riskAnalysisStatus === "Blocked") {
        await apiUnblockRiskAnalysis(YEAR);

        const sys = await apiGetSystemStatus();
        setSystemStatus(sys);
      }

      const doc = await apiGetRiskInventory(YEAR);
      const existingRows = flattenInventoryToRows(doc);
      setRows(existingRows);

      if (existingRows.length > 0) {
        openConfirm(
          "You are in middle of risk analysis.\n\nDo you want to start a new one?"
        );
        return;
      }

      const created = await apiCreateBlankRiskInventory(YEAR, true);

      if ((created as any)?.inventory) {
        const nextRows = flattenInventoryToRows((created as any).inventory);
        setRows(nextRows);
      } else {
        const freshDoc = await apiGetRiskInventory(YEAR);
        const nextRows = flattenInventoryToRows(freshDoc);
        setRows(nextRows);
      }

      setSelectedFinding(null);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "A new risk analysis is started.",
        },
      ]);

      scrollChatToBottom();
    } catch (e) {
      showPopup(e instanceof Error ? e.message : String(e));
    }
  };

  const runTraining = async () => {
    setSending(true);

    try {
      const data = await apiTrainBehaviorModel(YEAR);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            [
              "User behavior training completed successfully.",
              data.dataset_path ? `Dataset: ${data.dataset_path}` : null,
              data.model_path ? `Model: ${data.model_path}` : null,
              data.label_encoder_path ? `Label encoder: ${data.label_encoder_path}` : null,
              data.accuracy !== undefined ? `Accuracy: ${Number(data.accuracy).toFixed(4)}` : null,
            ]
              .filter(Boolean)
              .join("\n"),
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : String(e),
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };
    
  const runAnalysis = async () => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<AnalysisResponse>("/api/risk-analysis/analysis", {
        year: YEAR,
      });

      if (!data.success) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: data.message || "Risk analysis failed.",
          },
        ]);
        return;
      }

      if (data.inventory) {
        const nextRows = flattenInventoryToRows(data.inventory);
        setRows(nextRows);
      } else {
        await refreshInventoryRows();
      }

      setSelectedFinding(null);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Risk analysis completed successfully.",
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : String(e),
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleSetRisk = async (
    hostname: string,
    cve: string,
    risk: "High" | "Medium" | "Low"
  ) => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<SetRiskResponse>("/api/risk-analysis/setrisk", {
        year: YEAR,
        hostname,
        cve,
        risk,
      });

      if (data.inventory) {
        const nextRows = flattenInventoryToRows(data.inventory);
        setRows(nextRows);
      } else {
        await refreshInventoryRows();
      }

      setPendingCommand(null);
      setPendingHostname(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || `${hostname} / ${cve} risk updated to ${risk}.`,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while updating the risk." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleDeleteYes = async () => {
    if (!pendingHostname || !pendingCve) return;

    setSending(true);

    try {
      const data = await apiPostJSONBody<DeleteResponse>("/api/risk-analysis/delete", {
        year: YEAR,
        hostname: pendingHostname,
        cve: pendingCve,
      });

      if (data.inventory) {
        const nextRows = flattenInventoryToRows(data.inventory);
        setRows(nextRows);
      } else {
        await refreshInventoryRows();
      }

      if (
        selectedFinding &&
        selectedFinding.hostname.trim().toLowerCase() === pendingHostname.trim().toLowerCase()
      ) {
        setSelectedFinding(null);
      }

      const deletedHost = pendingHostname;
      const deletedCve = pendingCve;

      setPendingHostname(null);
      setPendingCve(null);
      setPendingCommand(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message || `Deleted highlighted row:\n\nHost: ${deletedHost}\nCVE: ${deletedCve}`,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while deleting the selected row." },
     ]);
    } finally {
      setSending(false);
     scrollChatToBottom();
    }
  };

  const handleDeleteNo = () => {
    setPendingHostname(null);
    setPendingCve(null);
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Delete cancelled." }]);
    scrollChatToBottom();
  };

  const handleResetConfirmYes = async () => {
    setSending(true);

    try {
      await apiCreateBlankRiskInventory(YEAR, true);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      const doc = await apiGetRiskInventory(YEAR);
      const nextRows = flattenInventoryToRows(doc);
      setRows(nextRows);
      setSelectedFinding(null);

      setPendingCommand(null);
      setPendingHostname(null);

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Risk analysis table has been cleared." },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while resetting the risk analysis table." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleResetConfirmNo = () => {
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Reset cancelled." }]);
    scrollChatToBottom();
  };

  const handleSubmitConfirmYes = async () => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<SubmitResponse>("/api/risk-analysis/submit", {
        year: YEAR,
        confirm: true,
      });

      if (data.inventory) {
        const nextRows = flattenInventoryToRows(data.inventory);
        setRows(nextRows);
      } else {
        await refreshInventoryRows();
      }

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setPendingCommand(null);
      setPendingHostname(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Risk analysis submitted successfully.",
        },
      ]);
    } catch {
      setPendingCommand(null);
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while submitting the risk analysis." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleAnalysisConfirmYes = async () => {
    setPendingCommand(null);
    await runAnalysis();
  };

  const handleAnalysisConfirmNo = () => {
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Analysis cancelled." }]);
    scrollChatToBottom();
  };

  const handleSubmitConfirmNo = () => {
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Submit cancelled." }]);
    scrollChatToBottom();
  };

  const onSend = async () => {
    const text = input.trim();
    if (!text || sending) return;

    setMessages((prev) => [...prev, { role: "user", content: text }]);
    setInput("");
    setSending(true);

    try {
      if (text.toLowerCase() === "/exit") {
        setPendingCommand(null);
        setPendingHostname(null);
        setMessages((prev) => [...prev, { role: "assistant", content: "Exited command mode." }]);
        return;
      }

      if (text.toLowerCase() === "/train") {
        await runTraining();
        return;
      }
        
      if (text.toLowerCase() === "/analysis") {
        try {
          const doc = await apiGetRiskInventory(YEAR);
          const hostCount = Array.isArray((doc as any)?.hosts) ? (doc as any).hosts.length : 0;

          if (hostCount > 0) {
            setPendingCommand("confirm-analysis");
            setMessages((prev) => [
              ...prev,
              {
                role: "assistant",
                content:
                  "RiskAnalysis.json already contains records.\n\nDo you want to run a new analysis?",
              },
            ]);
            return;
          }

          await runAnalysis();
          return;
        } catch (e) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: e instanceof Error ? e.message : String(e),
            },
          ]);
          return;
        }
      }

      if (text.toLowerCase() === "/submit") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "The risk analysis table is empty. Please run /analysis first.",
            },
          ]);
          return;
        }
    
        setPendingCommand("confirm-submit");
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "The risk analysis results will be finalized, are you sure?",
          },
        ]);
        return;
      }
        
      if (text === "/help") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "This page analyzes vulnerabilities across your assets and computes their risk level to support ISO 27001 risk management and prioritization. Risk is calculated using the formula Risk = CIA_weight × Likelihood × (1 + ML_probability), where CIA weights reflect asset importance (Critical=9, High=8, Medium=6, Low=3). Based on the final score, risks are classified as Low (0–<6), Medium (6–<10), High (10–<15), or Critical (15–18).\n\n" +
              "Likelihood represents how likely a vulnerability is to be exploited and is computed from multiple factors including CVSS severity, exploit availability, patch status, network exposure, asset role, and CIA impact. These factors are combined into a weighted score and then adjusted using ML_probability to reflect real-world conditions.\n\n" +
              "ML_probability introduces behavioral intelligence into the model by estimating the likelihood of attack based on observed system activity. It is predicted using an XGBoost machine learning model supported by agent-based data collection, using signals such as failed login attempts, access frequency, login consistency, and incident reports. This allows the system to move beyond static scoring and prioritize risks based on actual attacker behavior.",
          },
        ]);
        return;
      }

      if (text === "/commands") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "Available commands:\n\n" +
              "/analysis   → Run risk analysis\n" +
              "/train      → Train user behavior ML model\n" +
              "/setrisk    → Set risk for the highlighted subtable row\n" +
              "/details    → Show detailed risk information for the highlighted subtable row.\n" +
              "/delete     → Remove highlighted row from the table\n" +
              "/submit     → finalize risk analysis results\n" +
              "/reset      → Clear the table\n" +
              "/exit       → Exit the current command mode\n" +
              "/commands   → Show all available commands\n" +
              "/help       → Explain this section",
          },
        ]);
        return;
      }
        
      if (text.toLowerCase() === "/setrisk") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The table is empty. Please run /analysis first." },
          ]);
          return;
        }

        if (!selectedFindingContext) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content:
                "Please highlight a row in one of the subtables first, then run /setrisk.",
            },
          ]);
          return;
        }

        const { host, finding } = selectedFindingContext;

        setPendingCommand("setrisk-value");
        setPendingHostname(host.hostname);

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              `Risk Details for:\n\n` +
              `Host: ${host.hostname}\n` +
              `CVE: ${formatValue(finding.cve)}\n` +
              `Vulnerability: ${formatValue(finding.vulnerability)}\n\n` +
              `Change risk level to:`,
          },
        ]);
        return;
      }

      if (text.toLowerCase() === "/details") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The table is empty. Please run /analysis first." },
          ]);
          return;
        }

        if (!selectedFindingContext) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content:
                "Please highlight a row in one of the subtables first, then run /details.",
            },
          ]);
          return;
        }

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: formatSelectedFindingDetails(
              selectedFindingContext.host,
              selectedFindingContext.finding
            ),
          },
        ]);
        return;
      }

      if (text.toLowerCase() === "/delete") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The table is empty. There is nothing to delete." },
          ]);
          return;
        }
    
        if (!selectedFindingContext) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "Please highlight a row in one of the subtables first, then run /delete.",
            },
          ]);
          return;
        }
    
        const { host, finding } = selectedFindingContext;
    
        setPendingHostname(host.hostname);
        setPendingCve(finding.cve);
        setPendingCommand("confirm-delete");
    
        setMessages((prev) => [
          ...prev,
          { 
            role: "assistant",
            content:
              `Remove highlighted row from the table.\n\n` +
              `Host: ${host.hostname}\n` +
              `CVE: ${formatValue(finding.cve)}\n` +
              `Vulnerability: ${formatValue(finding.vulnerability)}\n\n` +
              `Are you sure?`,
          },
        ]);
        return;
      }
        
      if (text.toLowerCase() === "/reset") {
        try {
          const doc = await apiGetRiskInventory(YEAR);
          const hostCount = Array.isArray((doc as any)?.hosts) ? (doc as any).hosts.length : 0;

          if (hostCount > 0) {
            setPendingCommand("confirm-reset");
            setMessages((prev) => [
              ...prev,
              {
                role: "assistant",
                content:
                  "You are in middle of risk analysis.\n\nDo you want to start a new one?",
              },
            ]);
            return;
          }

          await handleResetConfirmYes();
          return;
        } catch (e) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: e instanceof Error ? e.message : String(e),
            },
          ]);
          return;
        }
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Unknown command. Type /commands to see the available operations.",
        },
      ]);
    } catch {
      setPendingCommand(null);
      setPendingHostname(null);
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while processing the command." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  useEffect(() => {
    (async () => {
      try {
        setScopeErr(null);
        const sys = await apiGetSystemStatus();
        setSystemStatus(sys);
      } catch (e) {
        setScopeErr(e instanceof Error ? e.message : String(e));
        setSystemStatus(null);
      }
    })();
  }, []);

  useEffect(() => {
    void refreshDashboardRaw();
  }, []);

  useEffect(() => {
    const refreshHeaderData = async () => {
      try {
        const sys = await apiGetSystemStatus();
        setSystemStatus(sys);
      } catch {
        // keep previous state
      }

      await refreshDashboardRaw();
    };

    window.addEventListener("focus", refreshHeaderData);
    window.addEventListener("hashchange", refreshHeaderData);

    return () => {
      window.removeEventListener("focus", refreshHeaderData);
      window.removeEventListener("hashchange", refreshHeaderData);
    };
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const doc = await apiGetRiskInventory(YEAR);
        const nextRows = flattenInventoryToRows(doc);
        setRows(nextRows);
      } catch {
        setRows([]);
      }
    })();
  }, []);

  useEffect(() => {
    if (!selectedFinding) return;
    const host = rows.find(
      (r) =>
        r.hostname.trim().toLowerCase() === selectedFinding.hostname.trim().toLowerCase()
    );
    if (!host || !host.findings[selectedFinding.index]) {
      setSelectedFinding(null);
    }
  }, [rows, selectedFinding]);

  useEffect(() => {
    scrollChatToBottom("smooth");
  }, [messages, sending, pendingCommand, pendingHostname]);

  const riskTableContent = (
    <div className="mt-4 min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
      {rows.length === 0 ? (
        <div className="rounded-xl border border-dashed border-white/10 bg-white/5 px-4 py-10 text-center text-sm text-slate-400">
          No risk analysis records available.
        </div>
      ) : (
        <div className="space-y-4">
          {rows.map((row, idx) => (
            <RiskFindingsCard
              key={`${row.hostname || "row"}-${idx}`}
              row={row}
              selectedFindingIndex={
                selectedFinding?.hostname === row.hostname ? selectedFinding.index : null
              }
              onSelectFinding={(findingIndex) => {
                setSelectedFinding({ hostname: row.hostname, index: findingIndex });
              }}
            />
          ))}
        </div>
      )}
    </div>
  );

  const assistantPanel = (
    <ShellCard className="flex h-full min-h-0 flex-col overflow-hidden">
      <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-5 py-4">
        <div className="text-lg font-semibold">Assistant</div>
        <div className="text-sm text-slate-400">Command mode</div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col px-5 py-4">
        <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-[#060815] p-4 ring-1 ring-white/10">
          <div className="space-y-3">
            {messages.map((m, idx) => {
              const isUser = m.role === "user";
              return (
                <div key={idx} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`max-w-[90%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm ring-1 ${
                      isUser
                        ? "bg-indigo-600/30 text-slate-50 ring-indigo-500/30"
                        : "bg-white/5 text-slate-200 ring-white/10"
                    }`}
                  >
                    {m.content}
                  </div>
                </div>
              );
            })}

            {pendingCommand === "setrisk-value" && selectedFindingContext ? (
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  onClick={() =>
                    void handleSetRisk(
                      selectedFindingContext.host.hostname,
                      selectedFindingContext.finding.cve,
                      "High"
                    )
                  }
                  className="rounded-xl bg-yellow-600/20 px-3 py-2 text-sm text-yellow-100 ring-1 ring-yellow-500/30 hover:bg-yellow-600/30"
                >
                  High
                </button>

                <button
                  onClick={() =>
                    void handleSetRisk(
                      selectedFindingContext.host.hostname,
                      selectedFindingContext.finding.cve,
                      "Medium"
                    )
                  }
                  className="rounded-xl bg-amber-600/20 px-3 py-2 text-sm text-amber-100 ring-1 ring-amber-500/30 hover:bg-amber-600/30"
                >
                  Medium
                </button>

                <button
                  onClick={() =>
                    void handleSetRisk(
                      selectedFindingContext.host.hostname,
                      selectedFindingContext.finding.cve,
                      "Low"
                    )
                  }
                  className="rounded-xl bg-sky-600/20 px-3 py-2 text-sm text-sky-100 ring-1 ring-sky-500/30 hover:bg-sky-600/30"
                >
                  Low
                </button>

                <button
                  onClick={() => {
                    setPendingHostname(null);
                    setPendingCommand(null);
                    setMessages((prev) => [
                      ...prev,
                      { role: "assistant", content: "Set risk cancelled." },
                    ]);
                    scrollChatToBottom();
                  }}
                  className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                >
                  Cancel
                </button>
              </div>
            ) : null}

            {pendingCommand === "confirm-delete" && pendingHostname ? (
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  onClick={() => void handleDeleteYes()}
                  className="rounded-xl bg-rose-600/20 px-3 py-2 text-sm text-rose-100 ring-1 ring-rose-500/30 hover:bg-rose-600/30"
                >
                  Yes
                </button>

                <button
                  onClick={handleDeleteNo}
                  className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                >
                  No
                </button>
              </div>
            ) : null}

            {pendingCommand === "confirm-reset" ? (
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  onClick={() => void handleResetConfirmYes()}
                  className="rounded-xl bg-rose-600/20 px-3 py-2 text-sm text-rose-100 ring-1 ring-rose-500/30 hover:bg-rose-600/30"
                >
                  Yes
                </button>

                <button
                  onClick={handleResetConfirmNo}
                  className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                >
                  No
                </button>
              </div>
            ) : null}

            {pendingCommand === "confirm-submit" ? (
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  onClick={() => void handleSubmitConfirmYes()}
                  className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                >
                  Yes
                </button>

                <button
                  onClick={handleSubmitConfirmNo}
                  className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                >
                  No
                </button>
              </div>
            ) : null}

            {pendingCommand === "confirm-analysis" ? (
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  onClick={() => void handleAnalysisConfirmYes()}
                  className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                >
                  Yes
                </button>

                <button
                  onClick={handleAnalysisConfirmNo}
                  className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                >
                  No
                </button>
              </div>
            ) : null}

            {sending ? (
              <div className="flex justify-start">
                <div className="max-w-[90%] rounded-2xl bg-white/5 px-4 py-3 text-sm text-slate-200 ring-1 ring-white/10">
                  …
                </div>
              </div>
            ) : null}

            <div ref={chatBottomRef} />
          </div>
        </div>

        <div className="mt-4 flex shrink-0 items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void onSend();
            }}
            placeholder="Type a command (e.g., /help)..."
            className="flex-1 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 ring-1 ring-white/10"
          />
          <button
            onClick={() => void onSend()}
            className="inline-flex items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-3 text-sm font-semibold text-white hover:bg-indigo-600 disabled:opacity-60"
            disabled={sending}
          >
            <Send className="h-4 w-4" />
            Send
          </button>
        </div>

        <div className="mt-3 shrink-0 text-xs text-slate-500">
            Command mode: /analysis /train /setrisk /details /delete /submit /reset /exit /commands /help
        </div>
      </div>
    </ShellCard>
  );

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      <Modal open={popupOpen} title="Message" text={popupText} onClose={closePopup} />

      {confirmOpen ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4">
          <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0b1020] p-6 shadow-2xl ring-1 ring-white/10">
            <div className="mb-3 text-lg font-semibold text-white">Confirmation</div>
            <div className="whitespace-pre-wrap text-sm text-slate-300">{confirmText}</div>
            <div className="mt-5 flex justify-end gap-3">
              <button
                onClick={closeConfirm}
                className="rounded-xl bg-white/10 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/15"
              >
                No
              </button>
              <button
                onClick={() => void handleCreateNewRiskAnalysis()}
                className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
              >
                Yes
              </button>
            </div>
          </div>
        </div>
      ) : null}

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
            {LEFT_MENU_ITEMS.map((item) => {
              const active = selectedStep === item.step;
              return (
                <button
                  key={item.step}
                  onClick={() => {
                    setSelectedStep(item.step);
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

          <div className="px-4 pb-4">
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
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Risk Analysis</h1>
            </div>
          </header>

          <div className="space-y-4">
            <ShellCard className="p-4">
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

                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-slate-300">({rowCount} assets)</span>
                    <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                      <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                      {riskAnalysisStatus}
                    </span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={() => void handleNewRiskAnalysisClick()}
              >
                <Plus className="h-14 w-4" />
                New Risk Analysis
              </button>
            </div>

            <ShellCard className="p-4">
              <div className="text-sm font-semibold text-slate-100">
                Scope & Context — Section 2 (Organizational Boundaries)
              </div>

              <div className="mt-2 text-sm text-slate-300">
                {orgBoundaryItems.length === 0 ? (
                  <span>NA</span>
                ) : (
                  <ul className="list-disc space-y-1 pl-5">
                    {orgBoundaryItems.map((x, idx) => (
                      <li key={idx}>{x}</li>
                    ))}
                  </ul>
                )}
              </div>

              {scopeErr ? (
                <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                  Error loading system status: {scopeErr}
                </div>
              ) : null}
            </ShellCard>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {kpis.map((k) => (
                <KpiCard key={k.title} kpi={k} />
              ))}
            </div>

            <ShellCard className="flex min-h-[420px] flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">Risk Analysis Table</div>
              {riskTableContent}
            </ShellCard>

            <div className="min-h-[700px]">{assistantPanel}</div>
          </div>
        </main>
      </div>

      <div className="hidden h-full xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1.7fr)_minmax(380px,0.95fr)] xl:grid-rows-[auto_auto_auto_auto_minmax(0,1fr)]">
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
              {LEFT_MENU_ITEMS.map((item) => {
                const active = selectedStep === item.step;
                return (
                  <button
                    key={item.step}
                    onClick={() => {
                      setSelectedStep(item.step);
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

        <div className="col-[2] row-[1/6] border-r border-white/10 bg-[#070A12]" />

        <header className="col-[3/5] row-[1] border-b border-white/10 bg-[#070A12]">
          <div className="flex h-[89px] items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              Risk Analysis
            </h1>
          </div>
        </header>

        <div className="col-[3] row-[2] p-3 pr-2">
          <ShellCard className="flex min-h-[71px] items-center px-4">
            <div className="flex w-full flex-wrap items-center justify-between gap-4">
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

                  <span className="text-sm text-slate-300">- ({rowCount} assets)</span>

                  <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                    {riskAnalysisStatus}
                  </span>
                </div>
              </div>
            </div>
          </ShellCard>
        </div>

        <div className="col-[4] row-[2] p-3 pl-2">
          <div className="flex min-h-[71px] items-center justify-end">
            <button
              className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              onClick={() => void handleNewRiskAnalysisClick()}
            >
              <Plus className="h-14 w-4" />
              New Risk Analysis
            </button>
          </div>
        </div>

        <div className="col-[3] row-[3] p-3 pr-2 pt-0">
          <ShellCard className="p-4">
            <div className="text-sm font-semibold text-slate-100">
              Scope & Context — Section 2 (Organizational Boundaries)
            </div>

            <div className="mt-2 text-sm text-slate-300">
              {orgBoundaryItems.length === 0 ? (
                <span>NA</span>
              ) : (
                <ul className="list-disc space-y-1 pl-5">
                  {orgBoundaryItems.map((x, idx) => (
                    <li key={idx}>{x}</li>
                  ))}
                </ul>
              )}
            </div>

            {scopeErr ? (
              <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Error loading system status: {scopeErr}
              </div>
            ) : null}
          </ShellCard>
        </div>

        <div className="col-[3] row-[4] p-3 pr-2 pt-0">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            {kpis.map((k) => (
              <KpiCard key={k.title} kpi={k} />
            ))}
          </div>
        </div>

        <div className="col-[3] row-[5] min-h-0 p-3 pr-2 pt-0">
          <ShellCard className="flex h-full min-h-0 flex-col p-5">
            <div className="shrink-0 text-lg font-semibold">Risk Analysis Table</div>
            {riskTableContent}
          </ShellCard>
        </div>

        <div className="col-[4] row-[3/6] min-h-0 p-3 pl-2 pt-0">{assistantPanel}</div>
      </div>
    </div>
  );
}
