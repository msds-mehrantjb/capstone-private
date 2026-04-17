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

type PendingCommand =
  | null
  | "confirm-submit"
  | "setrisk-value"
  | "confirm-delete"
  | "confirm-reset"
  | "confirm-analysis";

type EvaluationValue = "Accept" | "Monitor" | "Treat" | "";
type TreatmentValue = "Mitigate" | "Transfer" | "Avoid" | "Accept" | "" | "-";

type RiskFinding = {
  cve: string;
  vulnerability: string;
  risk: SeverityValue;
  riskScore?: number;

  evaluation?: EvaluationValue;
  treatment?: TreatmentValue;

  exploitAvailable?: string;
  patchStatus?: string;
  exposure?: string;
  mlProbability?: number | string;
  likelihoodScore?: number | string;

  cvssScore?: string | number;
  ciaRating?: SeverityValue;
  likelihood?: SeverityValue;

  cvssNormalized?: number | string;
  exploitNormalized?: number | string;
  patchNormalized?: number | string;
  exposureNormalized?: number | string;
  roleNormalized?: number | string;
  ciaNormalized?: number | string;
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

type SubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: any;
  requires_confirmation?: boolean;
};

type FindingEditState = {
  evaluation: EvaluationValue;
  treatment: TreatmentValue;
};

type FindingEditMap = Record<string, FindingEditState>;

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const FINALIZE_RISK_ANALYSIS_FIRST = "Finalize risk analysis first";

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

async function apiSetEvaluation(body: {
  year: number;
  hostname: string;
  cve: string;
  evaluation: EvaluationValue;
}): Promise<{ success?: boolean; message?: string; inventory?: any }> {
  return apiPostJSONBody(
    "/api/risk-evaluation-treatment/set-evaluation",
    body
  );
}


async function persistDefaultEvaluationsOnLoad(doc: any, year: number) {
  const hosts = Array.isArray(doc?.hosts) ? doc.hosts : [];

  for (const h of hosts) {
    const currentEvaluation = String(h?.evaluation ?? "").trim();
    const risk = normalizeSeverity(h?.risk ?? h?.risk_rating);
    const defaultEvaluation = getDefaultEvaluation({
      cve: String(h?.cve ?? ""),
      vulnerability: String(h?.vulnerability_name ?? ""),
      risk: normalizeSeverity(h?.risk ?? h?.risk_rating),
    });    

    if (!currentEvaluation && defaultEvaluation && h?.hostname && h?.cve) {
      const result = await apiSetEvaluation({
        year,
        hostname: String(h.hostname),
        cve: String(h.cve),
        evaluation: defaultEvaluation,
      });

      if (result?.success === false) {
        throw new Error(result.message || "Failed to update evaluation.");
      }
    }
  }
}


async function apiReinitializeTreatment(year: number) {
  return apiPostJSONBody<any>("/api/risk-evaluation-treatment/reinitialize", {
    year,
    confirm: true,
  });
}

async function apiGetTreatmentExists(year: number): Promise<{ exists: boolean }> {
  return apiGetJSON<{ exists: boolean }>(
    `/api/risk-evaluation-treatment/exists?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>("/api/system/status");
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/summary?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetTreatmentInventory(year: number): Promise<any> {
  return apiGetJSON<any>(
    `/api/risk-evaluation-treatment/inventory?year=${encodeURIComponent(String(year))}`
  );
}


async function loadTreatmentDataSafe(year: number) {
  const existsRes = await apiGetTreatmentExists(year);

  if (!existsRes.exists) {
    throw new Error(FINALIZE_RISK_ANALYSIS_FIRST);
  }

  return await apiGetTreatmentInventory(year);
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

function getEvaluationFromRisk(risk: SeverityValue): EvaluationValue {
  if (risk === "Low") return "Accept";
  if (risk === "Medium") return "Monitor";
  if (risk === "High" || risk === "Critical") return "Treat";
  return "";
}

function applyDefaultEvaluationsToDoc(doc: any) {
  const hosts = Array.isArray(doc?.hosts) ? doc.hosts : [];

  const nextHosts = hosts.map((h: any) => {
    const risk = normalizeSeverity(h?.risk ?? h?.risk_rating);
    const evaluation = getEvaluationFromRisk(risk);

    return {
      ...h,
      evaluation,
      treatment: evaluation === "Treat" ? h?.treatment ?? "" : "",
    };
  });

  return {
    ...doc,
    hosts: nextHosts,
  };
}

function flattenInventoryToRows(doc: any): RiskHostRow[] {
  const rawHosts = Array.isArray(doc?.hosts) ? doc.hosts : [];
  const grouped = new Map<string, RiskHostRow>();

  rawHosts.forEach((h: any) => {
    const hostname = String(h?.hostname ?? "").trim();
    if (!hostname) return;

    const key = hostname.toLowerCase();
    const role = String(h?.role ?? "-").trim() || "-";
    const location = String(h?.ip_address ?? "-").trim() || "-";

    if (!grouped.has(key)) {
      grouped.set(key, {
        hostname,
        role,
        location,
        impact: normalizeSeverity(h?.["CIA rating"]),
        likelihood: "Unscanned",
        risk: normalizeSeverity(h?.risk),
        ipAddress: String(h?.ip_address ?? "").trim(),
        findings: [],
      });
    }

    const row = grouped.get(key)!;

    if (row.impact === "Unscanned") {
      row.impact = normalizeSeverity(h?.["CIA rating"]);
    }

    if (row.risk === "Unscanned") {
      row.risk = normalizeSeverity(h?.risk);
    }

    row.findings.push({
      cve: String(h?.cve ?? "-").trim() || "-",
      vulnerability: String(h?.vulnerability_name ?? "-").trim() || "-",
      risk: normalizeSeverity(h?.risk),
      evaluation: String(h?.evaluation ?? "").trim() as EvaluationValue,
      treatment: getDisplayTreatmentValue(h?.treatment),
      ciaRating: normalizeSeverity(h?.["CIA rating"]),
    });
  });

  return Array.from(grouped.values());
}

function getFindingKey(hostname: string, finding: RiskFinding, index: number): string {
  return `${hostname}__${finding.cve}__${index}`;
}

function buildInitialFindingEdits(rows: RiskHostRow[]): FindingEditMap {
  const map: FindingEditMap = {};

  for (const row of rows) {
    row.findings.forEach((f, index) => {
      const key = getFindingKey(row.hostname, f, index);
      const evaluation =
        f.evaluation && f.evaluation !== "" ? f.evaluation : getDefaultEvaluation(f);

      const savedTreatment = getDisplayTreatmentValue(f.treatment);

      map[key] = {
        evaluation,
        treatment:
          evaluation === "Treat"
            ? savedTreatment === "-" ? "" : savedTreatment
            : "-",
      };
    });
  }

  return map;
}

function buildSubmitPayload(rows: RiskHostRow[], findingEdits: FindingEditMap) {
  return rows.map((row) => ({
    ...row,
    findings: row.findings.map((f, index) => {
      const key = getFindingKey(row.hostname, f, index);

      const evaluation =
        findingEdits[key]?.evaluation ??
        (f.evaluation && f.evaluation !== "" ? f.evaluation : getDefaultEvaluation(f));

      const treatment =
        evaluation === "Treat"
          ? ((findingEdits[key]?.treatment === "-" ? "" : (findingEdits[key]?.treatment ?? f.treatment ?? "")) as TreatmentValue)
          : ("-" as TreatmentValue);

      return {
        ...f,
        evaluation,
        treatment,
      };
    }),
  }));
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

function SimpleSelect({
  value,
  options,
  disabled = false,
  onChange,
  narrow = false,
}: {
  value?: string;
  options: string[];
  disabled?: boolean;
  onChange?: (value: string) => void;
  narrow?: boolean;
}) {
  return (
    <select
      value={value ?? ""}
      disabled={disabled}
      onChange={(e) => onChange?.(e.target.value)}
      className={`
        ${narrow ? "w-[98%]" : "w-full"} min-w-[110px]
        rounded-lg border border-indigo-400/40
        px-3 py-2 text-xs font-medium
        bg-[#1a2238] text-indigo-100
        ring-1 ring-indigo-500/30
        focus:ring-2 focus:ring-indigo-400 focus:outline-none
        ${disabled ? "opacity-50 cursor-not-allowed bg-[#111827] text-slate-400" : ""}
      `}
    >
      <option value="">Select</option>
      {options.map((opt) => (
        <option key={opt} value={opt} className="bg-[#1a2238] text-indigo-100">
          {opt}
        </option>
      ))}
    </select>
  );
}

function getDefaultEvaluation(finding: RiskFinding): EvaluationValue {
  const cve = String(finding.cve ?? "").trim();
  const risk = finding.risk;

  if (cve.startsWith("UB-WS-") && risk === "Low") return "Monitor";
  if (risk === "Low") return "Accept";
  if (risk === "Medium") return "Monitor";
  if (risk === "High" || risk === "Critical") return "Treat";
  return "";
}

function getDisplayTreatmentValue(value?: string): TreatmentValue {
  const v = String(value ?? "").trim();
  if (v === "Mitigate" || v === "Transfer" || v === "Avoid" || v === "Accept") return v;
  if (v === "-") return "-";
  return "";
}

function isTreatmentActive(evaluation: EvaluationValue): boolean {
  return evaluation === "Treat";
}

function RiskFindingsCard({
  row,
  selectedFindingIndex,
  onSelectFinding,
  findingEdits,
  onEvaluationChange,
  onTreatmentChange,
}: {
  row: RiskHostRow;
  selectedFindingIndex: number | null;
  onSelectFinding: (index: number) => void;
  findingEdits: FindingEditMap;
  onEvaluationChange: (
    hostname: string,
    finding: RiskFinding,
    index: number,
    value: EvaluationValue
  ) => void;
  onTreatmentChange: (
    hostname: string,
    finding: RiskFinding,
    index: number,
    value: TreatmentValue
  ) => void;
}) {
  const getEvaluationValue = (f: RiskFinding, index: number): EvaluationValue => {
    const key = getFindingKey(row.hostname, f, index);
    return (
      findingEdits[key]?.evaluation ??
      (f.evaluation && f.evaluation !== "" ? f.evaluation : getDefaultEvaluation(f))
    );
  };

  const getTreatmentValue = (f: RiskFinding, index: number): TreatmentValue => {
    const key = getFindingKey(row.hostname, f, index);
    const edited = findingEdits[key]?.treatment;
    if (edited !== undefined) return edited;
    return getDisplayTreatmentValue(f.treatment);
  };

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
            <div className="hidden overflow-x-auto lg:block">
              <div className="grid grid-cols-[1.1fr_2.4fr_1fr_1.2fr_1.2fr] border-b border-white/10 bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300 text-left">
                <div className="px-3 py-3 text-left justify-self-start">CVE</div>
                <div className="px-3 py-3 text-left justify-self-start">Vulnerability</div>
                <div className="px-3 py-3 text-left justify-self-start">Risk</div>
                <div className="px-3 py-3 text-left justify-self-start">Evaluation</div>
                <div className="px-3 py-3 text-left justify-self-start">Treatment</div>
              </div>

              {row.findings.map((f, index) => {
                const findingSelected = selectedFindingIndex === index;
                const evaluation = getEvaluationValue(f, index);
                const treatmentActive = isTreatmentActive(evaluation);
                const rawTreatmentValue = getTreatmentValue(f, index);
                const treatmentValue =
                  treatmentActive && rawTreatmentValue !== "-" ? rawTreatmentValue : "";
                return (
                  <div
                    key={`${row.hostname}-${f.cve}-${index}`}
                    onClick={() => onSelectFinding(index)}
                    className={`grid cursor-pointer grid-cols-[1.1fr_2.4fr_1fr_1.2fr_1.2fr] items-center transition ${
                      findingSelected
                        ? "bg-indigo-500/15 ring-1 ring-inset ring-indigo-400/40"
                        : "bg-[#11192d] hover:bg-white/5"
                    } ${index !== row.findings.length - 1 ? "border-b border-white/10" : ""}`}
                  >
                    <div className="break-words px-3 py-3 text-sm text-slate-100">{f.cve}</div>

                    <div className="break-words px-3 py-3 text-sm text-slate-200">
                      {f.vulnerability}
                    </div>

                    <div className="px-3 py-3">
                      <SeverityPill value={f.risk} />
                    </div>

                    <div
                      className="px-3 py-3 text-left"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <SimpleSelect
                        value={evaluation}
                        options={["Accept", "Monitor", "Treat"]}
                        onChange={(value) =>
                          onEvaluationChange(row.hostname, f, index, value as EvaluationValue)
                        }
                      />
                    </div>

                    <div
                      className="px-3 py-3 text-left"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {treatmentActive ? (
                        <SimpleSelect
                          value={treatmentValue}
                          options={["Mitigate", "Transfer", "Avoid", "Accept"]}
                          narrow
                          onChange={(value) =>
                            onTreatmentChange(row.hostname, f, index, value as TreatmentValue)
                          }
                        />
                      ) : (
                        <span className="text-slate-400">-</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="divide-y divide-white/10 lg:hidden">
              {row.findings.map((f, index) => {
                const findingSelected = selectedFindingIndex === index;
                const evaluation = getEvaluationValue(f, index);
                const treatmentActive = isTreatmentActive(evaluation);
                const rawTreatmentValue = getTreatmentValue(f, index);
                const treatmentValue =
                  treatmentActive && rawTreatmentValue !== "-" ? rawTreatmentValue : "";
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
                        <div className="text-[11px] uppercase tracking-wide text-slate-400">
                          CVE
                        </div>
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
                            Risk
                          </div>
                          <div>
                            <SeverityPill value={f.risk} />
                          </div>
                        </div>

                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            Evaluation
                          </div>
                          <div onClick={(e) => e.stopPropagation()}>
                            <SimpleSelect
                              value={evaluation}
                              options={["Accept", "Monitor", "Treat"]}
                              onChange={(value) =>
                                onEvaluationChange(row.hostname, f, index, value as EvaluationValue)
                              }
                            />
                          </div>
                        </div>

                        <div className="grid gap-1">
                          <div className="text-[11px] uppercase tracking-wide text-slate-400">
                            Treatment
                          </div>
                          <div onClick={(e) => e.stopPropagation()}>
                            {treatmentActive ? (
                              <SimpleSelect
                                value={treatmentValue}
                                options={["Mitigate", "Transfer", "Avoid", "Accept"]}
                                narrow
                                onChange={(value) =>
                                  onTreatmentChange(
                                    row.hostname,
                                    f,
                                    index,
                                    value as TreatmentValue
                                  )
                                }
                              />
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
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

export default function RiskEvaluationTreatment() {
  const YEAR = 2026;
  const [selectedStep, setSelectedStep] = useState<number>(6);

  const [pendingCommand, setPendingCommand] = useState<PendingCommand>(null);

  const [selectedFinding, setSelectedFinding] = useState<SelectedFinding | null>(null);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [confirmAction, setConfirmAction] = useState<null | "reinitialize-treatment">(null);

  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [rows, setRows] = useState<RiskHostRow[]>([]);
  const [findingEdits, setFindingEdits] = useState<FindingEditMap>({});

  const [popupOpen, setPopupOpen] = useState(false);
  const [popupText, setPopupText] = useState("");

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Risk Evaluation & Treatment — Command Mode\n\n" +
        "Available commands:\n" +
        "/submit     → Submit risk evaluation & treatment results\n" +
        "/help       → Explain this section\n" +
        "/commands   → Show all available commands\n" +
        "/exit       → Exit the current command mode",
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

  const handleNewRiskEvaluationTreatmentClick = async () => {
    try {
      const existsRes = await apiGetTreatmentExists(YEAR);

      if (!existsRes.exists) {
        showPopup(FINALIZE_RISK_ANALYSIS_FIRST);
        return;
      }

      openConfirm(
        "Risk Evaluation and Treatment will initialized with original states, are you sure?",
        "reinitialize-treatment"
      );
    } catch (e) {
      showPopup(e instanceof Error ? e.message : String(e));
    }
  };

  const backendEvaluationStatus = systemStatus?.sections?.risk_evaluation_treatment?.status;

  const riskEvaluationStatus: StepStatus = useMemo(() => {
    if (backendEvaluationStatus === "Completed") return "Completed";
    if (backendEvaluationStatus === "Blocked") return "Blocked";
    if (backendEvaluationStatus === "In Progress") return "In Progress";
    if (rows.length > 0) return "In Progress";
    return "Not Started";
  }, [backendEvaluationStatus, rows.length]);

  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const rowCount = rows.length;

  const openConfirm = (text: string, action: "reinitialize-treatment") => {
    setConfirmText(text);
    setConfirmAction(action);
    setConfirmOpen(true);
  };

  const closeConfirm = () => {
    setConfirmOpen(false);
    setConfirmText("");
    setConfirmAction(null);
  };

  const criticalImpactCount = useMemo(
    () =>
      rows.reduce((count, host) => {
        const hostCriticalOrHigh =
          host.findings?.filter(
            (f) => f.ciaRating === "Critical" || f.ciaRating === "High"
          ).length ?? 0;

        return count + hostCriticalOrHigh;
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
        title: "High Risk",
        value: String(highRiskCount),
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

  const scrollChatToBottom = (behavior: ScrollBehavior = "smooth") => {
    requestAnimationFrame(() => {
      chatBottomRef.current?.scrollIntoView({ behavior, block: "end" });
    });
  };

  const refreshDashboardRaw = async () => {
    try {
      const raw = await apiGetDashboardRaw(YEAR);
      setDashboardRaw(raw);
    } catch {
      setDashboardRaw(null);
    }
  };

  async function apiSetEvaluation(body: {
    year: number;
    hostname: string;
    cve: string;
    evaluation: EvaluationValue;
  }) {
    return apiPostJSONBody<any>(
      "/api/risk-evaluation-treatment/set-evaluation",
      body
    ); 
  }

  const handleEvaluationChange = async (
    hostname: string,
    finding: RiskFinding,
    index: number,
    value: EvaluationValue
  ) => {
    const key = getFindingKey(hostname, finding, index);

    const previousEvaluation =
      (findingEdits[key]?.evaluation ??
        (finding.evaluation && finding.evaluation !== ""
          ? finding.evaluation
          : getDefaultEvaluation(finding))) as EvaluationValue;

    const previousTreatment =
      (findingEdits[key]?.treatment ?? getDisplayTreatmentValue(finding.treatment)) as TreatmentValue;

    const nextTreatment: TreatmentValue =
      value === "Treat"
        ? (previousTreatment === "-" ? "" : previousTreatment)
        : "-";

    setFindingEdits((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        evaluation: value,
        treatment: nextTreatment,
      },
    }));

    try {
      const result = await apiSetEvaluation({
        year: YEAR,
        hostname,
        cve: finding.cve,
        evaluation: value,
      });

      if (result?.success === false) {
        throw new Error(result.message || "Failed to update evaluation.");
      }
    } catch (e) {
      setFindingEdits((prev) => ({
        ...prev,
        [key]: {
          ...prev[key],
          evaluation: previousEvaluation,
          treatment: previousTreatment,
        },
      }));

      showPopup(e instanceof Error ? e.message : String(e));
    }
  };

  async function apiSetTreatment(body: {
    year: number;
    hostname: string;
    cve: string;
    treatment: TreatmentValue;
  }) {
    return apiPostJSONBody<any>(
      "/api/risk-evaluation-treatment/set-treatment",
      body
    );
  }

  const handleTreatmentChange = async (
    hostname: string,
    finding: RiskFinding,
    index: number,
    value: TreatmentValue
  ) => {
    const key = getFindingKey(hostname, finding, index);

    const previousEvaluation =
      (findingEdits[key]?.evaluation ??
        (finding.evaluation && finding.evaluation !== ""
          ? finding.evaluation
          : getDefaultEvaluation(finding))) as EvaluationValue;

    const previousTreatment =
      (findingEdits[key]?.treatment ?? getDisplayTreatmentValue(finding.treatment)) as TreatmentValue;

    setFindingEdits((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        evaluation: previousEvaluation,
        treatment: value,
      },
    }));

    try {
      const result = await apiSetTreatment({
        year: YEAR,
        hostname,
        cve: finding.cve,
        treatment: value,
      });

      if (result?.success === false) {
      throw new Error(result.message || "Failed to update treatment.");
      }
    } catch (e) {
      setFindingEdits((prev) => ({
        ...prev,
        [key]: {
          ...prev[key],
          evaluation: previousEvaluation,
          treatment: previousTreatment,
        },
      }));

      showPopup(e instanceof Error ? e.message : String(e));
    }
  };
    
  const handleConfirmYes = async () => {
    if (confirmAction !== "reinitialize-treatment") {
      closeConfirm();
      return;
    }

    try {
      await apiReinitializeTreatment(YEAR);

      const refreshedInventory = await apiGetTreatmentInventory(YEAR);
      const refreshedRows = flattenInventoryToRows(refreshedInventory);

      setRows(refreshedRows);
      setFindingEdits(buildInitialFindingEdits(refreshedRows));
      setSelectedFinding(null);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Risk Evaluation and Treatment has been re-initialized successfully.",
        },
      ]);
    } catch (e) {
      showPopup(e instanceof Error ? e.message : String(e));
    } finally {
      closeConfirm();
      scrollChatToBottom();
    }
  };

  const hasMissingTreatment = (): boolean => {
    for (const row of rows) {
      for (let index = 0; index < row.findings.length; index++) {
        const finding = row.findings[index];
        const key = getFindingKey(row.hostname, finding, index);

        const evaluation =
          findingEdits[key]?.evaluation ??
          (finding.evaluation && finding.evaluation !== ""
            ? finding.evaluation
            : getDefaultEvaluation(finding));

        const treatment =
          evaluation === "Treat"
            ? (findingEdits[key]?.treatment ?? getDisplayTreatmentValue(finding.treatment) ?? "")
            : "-";

        if (evaluation === "Treat" && String(treatment).trim() === "") {
          return true;
        }
      }
    }
    return false;
  };


  const handleSubmitConfirmYes = async () => {
    if (hasMissingTreatment()) {
      setPendingCommand(null);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "You should define treatment option for all risks that need treat.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    setSending(true);

    try {
      const payload = buildSubmitPayload(rows, findingEdits);

      const data = await apiPostJSONBody<SubmitResponse>(
        "/api/risk-evaluation-treatment/submit",
        {
          year: YEAR,
          confirm: true,
          rows: payload,
        }
      );

      const doc = await loadTreatmentDataSafe(YEAR);
      const nextRows = flattenInventoryToRows(doc);

      setRows(nextRows);
      setFindingEdits(buildInitialFindingEdits(nextRows));

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setPendingCommand(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Risk evaluation & treatment submitted successfully.",
        },
      ]);
    } catch (e) {
      setPendingCommand(null);
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
        setMessages((prev) => [...prev, { role: "assistant", content: "Exited command mode." }]);
        return;
      }

      if (text.toLowerCase() === "/submit") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "The risk evaluation & treatment table is empty.",
            },
          ]);
          return;
        }

        setPendingCommand("confirm-submit");
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "Do you want to submit the Risk Evaluation & Treatment results?",
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
              "Risk Evaluation & Treatment — Overview\n\n" +
              "This section finalizes risk decisions and defines how risks will be handled.\n\n" +
              "Risk Evaluation\n" +
              "Purpose: Determine which risks are acceptable.\n\n" +
              "Risk Matrix:\n" +
              "Low (1–3) → Accept\n" +
              "Medium (4–6) → Monitor\n" +
              "High (7–9) → Treat\n\n" +
              "Risk Treatment\n" +
              "Purpose: Define actions to reduce risk.\n\n" +
              "Treatment Options:\n" +
              "Mitigate → Implement controls\n" +
              "Transfer → Insurance or third parties\n" +
              "Avoid → Remove the risk source\n" +
              "Accept → Tolerate the risk\n\n" +
              "Use this section to review findings, assign decisions, and submit final treatment actions.",
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
              "/submit     → Submit risk evaluation & treatment results\n" +
              "/help       → Explain this section\n" +
              "/commands   → Show all available commands\n" +
              "/exit       → Exit the current command mode",
          },
        ]);
        return;
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Unknown command. Type /commands to see the available operations.",
        },
      ]);
    } catch (e) {
      setPendingCommand(null);
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
        //
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
        const rawDoc = await loadTreatmentDataSafe(YEAR);

        //  await persistDefaultEvaluationsOnLoad(rawDoc, YEAR);

        const refreshedDoc = await loadTreatmentDataSafe(YEAR);
        const nextRows = flattenInventoryToRows(refreshedDoc);

        setRows(nextRows);
        setFindingEdits(buildInitialFindingEdits(nextRows));
      } catch (e) {
        setRows([]);
        setFindingEdits({});

        const msg = e instanceof Error ? e.message : String(e);

        if (msg === FINALIZE_RISK_ANALYSIS_FIRST) {
          showPopup(FINALIZE_RISK_ANALYSIS_FIRST);
        } else {
          showPopup(msg);
        }
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
  }, [messages, sending, pendingCommand]);

  const riskTableContent = (
    <div className="mt-4 min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
      {rows.length === 0 ? (
        <div className="rounded-xl border border-dashed border-white/10 bg-white/5 px-4 py-10 text-center text-sm text-slate-400">
          No risk evaluation & treatment records available.
        </div>
      ) : (
        <div className="space-y-4">
          {rows.map((row, idx) => (
            <RiskFindingsCard
              key={`${row.hostname || "row"}-${idx}-${row.findings
                .map((f, findingIndex) => {
                  const key = getFindingKey(row.hostname, f, findingIndex);
                  return `${f.cve}:${findingEdits[key]?.evaluation ?? f.evaluation}:${
                    findingEdits[key]?.treatment ?? f.treatment
                  }`;
                })
                .join("|")}`}
              row={row}
              selectedFindingIndex={
                selectedFinding?.hostname === row.hostname ? selectedFinding.index : null
              }
              onSelectFinding={(findingIndex) => {
                setSelectedFinding({ hostname: row.hostname, index: findingIndex });
              }}
              findingEdits={findingEdits}
              onEvaluationChange={handleEvaluationChange}
              onTreatmentChange={handleTreatmentChange}
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
          Command mode: /commands /submit /help /exit
        </div>
      </div>
    </ShellCard>
  );

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      <Modal open={popupOpen} title="Notice" text={popupText} onClose={closePopup} />

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
                onClick={() => void handleConfirmYes()}
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
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                Risk Evaluation & Treatment
              </h1>
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
                      {riskEvaluationStatus}
                    </span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={() => void handleNewRiskEvaluationTreatmentClick()}
              >
                <Plus className="h-4 w-4" />
                New Risk Evaluation & Treatment
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
              <div className="shrink-0 text-lg font-semibold">Risk Evaluation & Treatment Table</div>
              {riskTableContent}
            </ShellCard>

            <div className="min-h-[700px]">{assistantPanel}</div>
          </div>
        </main>
      </div>

      <div className="hidden h-full xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1.7fr)_minmax(380px,0.95fr)] xl:grid-rows-[auto_auto_minmax(0,1fr)]">
        <aside className="col-[1] row-[1/4] border-r border-white/10 bg-[#060815]">
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

        <div className="col-[2] row-[1/4] border-r border-white/10 bg-[#070A12]" />

        <header className="col-[3/5] row-[1] border-b border-white/10 bg-[#070A12]">
          <div className="flex h-[89px] items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              Risk Evaluation & Treatment
            </h1>
          </div>
        </header>

        <div className="col-[3] row-[2/4] min-h-0 flex flex-col p-3 pr-2">
          <ShellCard className="p-4">
            <div className="flex w-full flex-wrap items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
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

                    <div className="text-sm text-slate-300">({rowCount} assets)</div>

                    <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                      <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                      {riskEvaluationStatus}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </ShellCard>

          <div className="mt-3">
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

          <div className="mt-3 grid grid-cols-4 gap-3">
            {kpis.map((k) => (
              <KpiCard key={k.title} kpi={k} />
            ))}
          </div>

          <div className="mt-3 min-h-0 flex-1">
            <ShellCard className="flex h-full min-h-0 flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">
                Risk Evaluation & Treatment Table
              </div>
              {riskTableContent}
            </ShellCard>
          </div>
        </div>
        <div className="col-[4] row-[2] p-3 pl-2">
          <div className="flex justify-end">
            <button
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              onClick={() => void handleNewRiskEvaluationTreatmentClick()}
            >
              <Plus className="h-14 w-4" />
              New Risk Evaluation & Treatment
            </button>
          </div>
        </div>
          
        <div className="col-[4] row-[3] min-h-0 p-3 pl-2 pt-0">
          <div className="h-full min-h-0">{assistantPanel}</div>
        </div>
      </div>
    </div>
  );
}

