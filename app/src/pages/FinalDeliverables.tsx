import React, { useEffect, useMemo, useState } from "react";
import { ShieldCheck, ChevronDown } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeRaw from "rehype-raw";
import type { CSSProperties } from "react";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type DashboardRawDTO = {
  environment?: string;
  scope?: {
    name?: string;
    asset_count?: number;
    status?: StepStatus;
  };
  scope_context_section2?: {
    title?: string;
    bullets?: string[];
    body?: string;
  };
  scope_file_name?: string;
};

type FinalTabKey =
  | "executive-summary"
  | "asset-inventory"
  | "risk-register"
  | "risk-treatment-plan"
  | "annex-a-soa"
  | "action-plan-implementation"
  | "monitoring-improvement";

type FinalDeliveryResponse = {
  success: boolean;
  year: number;
  section: FinalTabKey;
  markdown: string;
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

const FINAL_TABS: Array<{ key: FinalTabKey; label: string; href: string }> = [
  { key: "executive-summary", label: "Executive Summary", href: "#/final-deliveries/executive-summary" },
  { key: "asset-inventory", label: "Asset Inventory", href: "#/final-deliveries/asset-inventory" },
  { key: "risk-register", label: "Risk Register", href: "#/final-deliveries/risk-register" },
  { key: "risk-treatment-plan", label: "Risk Treatment Plan", href: "#/final-deliveries/risk-treatment-plan" },
  { key: "annex-a-soa", label: "Annex A & SoA", href: "#/final-deliveries/annex-a-soa" },
  {
    key: "action-plan-implementation",
    label: "Action Plan / Implementation",
    href: "#/final-deliveries/action-plan-implementation",
  },
  {
    key: "monitoring-improvement",
    label: "Monitoring & Improvement",
    href: "#/final-deliveries/monitoring-improvement",
  },
];

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8003";

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

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      // ignore json parse errors
    }
    throw new Error(detail);
  }

  return (await res.json()) as T;
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/raw?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetFinalDeliverySection(
  section: FinalTabKey,
  year: number
): Promise<FinalDeliveryResponse> {
  return apiGetJSON<FinalDeliveryResponse>(
    `/api/final-deliveries/${encodeURIComponent(section)}?year=${encodeURIComponent(String(year))}`
  );
}

async function apiExportFinalDeliveryPdf(
  section: FinalTabKey,
  year: number
): Promise<Blob> {
  const res = await fetch(`${API_BASE}/api/final-deliveries/export-pdf?_ts=${Date.now()}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    },
    body: JSON.stringify({ section, year }),
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      try {
        detail = await res.text();
      } catch {
        // ignore
      }
    }
    throw new Error(detail || `HTTP ${res.status}`);
  }

  return await res.blob();
}

function getFinalTabFromHash(): FinalTabKey {
  const h = (window.location.hash || "").toLowerCase();

  if (h.startsWith("#/final-deliveries/asset-inventory")) return "asset-inventory";
  if (h.startsWith("#/final-deliveries/risk-register")) return "risk-register";
  if (h.startsWith("#/final-deliveries/risk-treatment-plan")) return "risk-treatment-plan";
  if (h.startsWith("#/final-deliveries/annex-a-soa")) return "annex-a-soa";
  if (h.startsWith("#/final-deliveries/action-plan-implementation")) return "action-plan-implementation";
  if (h.startsWith("#/final-deliveries/monitoring-improvement")) return "monitoring-improvement";

  return "executive-summary";
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

function TabButton({
  active,
  label,
  onClick,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-xl px-4 py-2 text-sm font-medium transition ${
        active
          ? "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25"
          : "bg-white/5 text-slate-300 ring-1 ring-white/10 hover:bg-white/10"
      }`}
    >
      {label}
    </button>
  );
}

function extractMarkdownNodeText(node: any): string {
  if (!node) return "";
  if (typeof node === "string") return node;
  if (Array.isArray(node)) {
    return node.map((child) => extractMarkdownNodeText(child)).join(" ");
  }
  if (typeof node.value === "string") return node.value;
  if (Array.isArray(node.children)) {
    return node.children.map((child: any) => extractMarkdownNodeText(child)).join(" ");
  }
  return "";
}

function parseInlineStyle(styleValue: unknown): CSSProperties | undefined {
  if (!styleValue) return undefined;
  if (typeof styleValue === "object") return styleValue as CSSProperties;
  if (typeof styleValue !== "string") return undefined;

  const style: Record<string, string> = {};

  for (const declaration of styleValue.split(";")) {
    const [rawName, ...rawValueParts] = declaration.split(":");
    const name = rawName?.trim();
    const value = rawValueParts.join(":").trim();
    if (!name || !value) continue;

    const camelName = name.replace(/-([a-z])/g, (_, letter: string) =>
      letter.toUpperCase()
    );
    style[camelName] = value;
  }

  return Object.keys(style).length ? (style as CSSProperties) : undefined;
}

function MarkdownPrintReady({
  content,
  section,
}: {
  content: string;
  section: FinalTabKey;
}) {
  return (
    <div className="h-full w-full overflow-y-scroll rounded-xl bg-[#0b1020] p-4">
      <div className="w-full rounded-lg bg-white px-10 py-10 text-black shadow-2xl">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeRaw]}
          components={{
            h1: ({ children }) => (
              <h1 className="mb-6 text-3xl font-bold leading-tight text-black">
                {children}
              </h1>
            ),
            h2: ({ children }) => (
              <h2 className="mb-4 mt-8 text-2xl font-semibold leading-tight text-black">
                {children}
              </h2>
            ),
            h3: ({ children }) => (
              <h3 className="mb-3 mt-6 text-xl font-semibold leading-tight text-black">
                {children}
              </h3>
            ),
            h4: ({ children }) => (
              <h4 className="mb-2 mt-5 text-lg font-semibold leading-tight text-black">
                {children}
              </h4>
            ),
            p: ({ children }) => (
              <p className="mb-4 text-[15px] leading-7 text-black">{children}</p>
            ),
            ul: ({ children }) => (
              <ul className="mb-4 list-disc pl-6 text-[15px] leading-7 text-black">
                {children}
              </ul>
            ),
            ol: ({ children }) => (
              <ol className="mb-4 list-decimal pl-6 text-[15px] leading-7 text-black">
                {children}
              </ol>
            ),
            li: ({ children }) => (
              <li className="mb-1 text-[15px] leading-7 text-black">{children}</li>
            ),
            strong: ({ children }) => (
              <strong className="font-semibold text-black">{children}</strong>
            ),
            em: ({ children }) => (
              <em className="italic text-black">{children}</em>
            ),
            hr: () => <hr className="my-6 border-slate-300" />,
            blockquote: ({ children }) => (
              <blockquote className="mb-4 border-l-4 border-slate-300 pl-4 italic text-slate-700">
                {children}
              </blockquote>
            ),
            code: ({ children, className, ...props }: any) => (
              <code
                className={`rounded bg-slate-100 px-1 py-0.5 font-mono text-[14px] text-black ${className ?? ""}`}
                {...props}
              >
                {children}
              </code>
            ),
            pre: ({ children }) => (
              <pre className="mb-4 overflow-x-auto rounded-lg bg-slate-100 p-4">
                {children}
              </pre>
            ),
            table: ({ children }) => (
              <div className="mb-6 overflow-x-auto">
                <table className="w-full border-collapse text-[14px] text-black">
                  {children}
                </table>
              </div>
            ),
            thead: ({ children }) => (
              <thead className="bg-slate-100">{children}</thead>
            ),
            tr: ({ children, ...props }: any) => {
              const { node, ref, style, ...rowProps } = props;
              void ref;

              const rowText = extractMarkdownNodeText(node)
                .replace(/\s+/g, " ")
                .trim();
              const isMediumRiskRow =
                section === "risk-treatment-plan" &&
                /\bMedium\b/.test(rowText) &&
                /\bMonitor\b/.test(rowText);

              return (
                <tr
                  {...rowProps}
                  className={isMediumRiskRow ? "bg-amber-100/80" : undefined}
                  style={parseInlineStyle(style)}
                >
                  {children}
                </tr>
              );
            },
            th: ({ children, ...props }: any) => {
              const { node, ref, style, ...cellProps } = props;
              void node;
              void ref;

              const isGroupedHeader =
                cellProps.colSpan && Number(cellProps.colSpan) > 1;

              return (
                <th
                  {...cellProps}
                  className={`border border-slate-300 px-3 py-2 font-semibold text-black ${
                    isGroupedHeader ? "bg-slate-200 text-center" : "text-left"
                  }`}
                  style={parseInlineStyle(style)}
                >
                  {children}
                </th>
              );
            },
            td: ({ children, ...props }: any) => {
              const { node, ref, style, ...cellProps } = props;
              void ref;

              const value = String(children ?? "").trim();
              const isConfidence =
                value.match(/^\d+(\.\d+)?$/) ||
                ["Very High", "High", "Medium", "Low"].includes(value);
              const rowText = extractMarkdownNodeText(node?.parent)
                .replace(/\s+/g, " ")
                .trim();
              const isMediumRiskRow =
                section === "risk-treatment-plan" &&
                /\bMedium\b/.test(rowText) &&
                /\bMonitor\b/.test(rowText);

              return (
                <td
                  {...cellProps}
                  className={`border border-slate-300 px-3 py-2 align-top text-black ${
                    isConfidence ? "text-center" : "text-left"
                  } ${isMediumRiskRow ? "bg-amber-100/80" : ""}`}
                  style={parseInlineStyle(style)}
                >
                  {children}
                </td>
              );
            },
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </div>
  );
}

export default function FinalDeliverables() {
  const YEAR = 2026;

  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(10);
  const [pageErr, setPageErr] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<FinalTabKey>(getFinalTabFromHash());
  const [sectionData, setSectionData] = useState<FinalDeliveryResponse | null>(null);
  const [sectionLoading, setSectionLoading] = useState(false);
  const [sectionError, setSectionError] = useState<string | null>(null);
  const [exportBusy, setExportBusy] = useState(false);

  const refreshPageData = async () => {
    try {
      setPageErr(null);
      const raw = await apiGetDashboardRaw(YEAR);
      setDashboardRaw(raw);
    } catch (e) {
      setPageErr(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    const syncSelectedStep = () => {
      const h = (window.location.hash || "").toLowerCase();

      if (
        h.startsWith("#/final-deliverables") ||
        h.startsWith("#/final-deliveries")
      ) {
        setSelectedStep(10);
        setActiveTab(getFinalTabFromHash());
      } else if (h.startsWith("#/scope")) setSelectedStep(1);
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
    void refreshPageData();

    const onHashChange = () => {
      syncSelectedStep();
    };

    const onFocus = () => {
      void refreshPageData();
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void refreshPageData();
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

  useEffect(() => {
    let cancelled = false;

    async function loadSection() {
      try {
        setSectionLoading(true);
        setSectionError(null);

        const data = await apiGetFinalDeliverySection(activeTab, YEAR);

        if (!cancelled) {
          setSectionData(data);
        }
      } catch (e) {
        if (!cancelled) {
          setSectionError(e instanceof Error ? e.message : String(e));
          setSectionData(null);
        }
      } finally {
        if (!cancelled) {
          setSectionLoading(false);
        }
      }
    }

    if (selectedStep === 10) {
      void loadSection();
    }

    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedStep]);

  const onExportPdf = async () => {
    try {
      setPageErr(null);
      setExportBusy(true);

      const blob = await apiExportFinalDeliveryPdf(activeTab, YEAR);

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${activeTab}-${YEAR}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setPageErr(e instanceof Error ? e.message : String(e));
    } finally {
      setExportBusy(false);
    }
  };

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

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      <div className="xl:hidden h-screen overflow-hidden">
        <div className="flex h-full flex-col">
          <aside className="shrink-0 border-b border-white/10 bg-[#060815]">
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
                    <span className={active ? "text-slate-50" : "text-slate-200"}>
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

          <main className="flex-1 min-h-0 overflow-hidden px-4 py-4">
            <div className="flex h-full min-h-0 flex-col space-y-4">
              <header className="shrink-0">
                <div className="rounded-2xl border border-white/10 bg-[#070A12] py-4 text-center ring-1 ring-white/10">
                  <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                    ISO 27001 Final Deliverables
                  </h1>
                </div>
              </header>

              <ShellCard className="shrink-0 p-4">
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

              <ShellCard className="shrink-0 p-4">
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

              <ShellCard className="flex flex-1 min-h-0 flex-col overflow-hidden">
                <div className="shrink-0 border-b border-white/10 p-4">
                  <div className="flex flex-col gap-3">
                    <div className="flex flex-wrap gap-2">
                      {FINAL_TABS.map((tab) => (
                        <TabButton
                          key={tab.key}
                          active={activeTab === tab.key}
                          label={tab.label}
                          onClick={() => {
                            window.location.hash = tab.href;
                          }}
                        />
                      ))}
                    </div>

                    <div className="flex justify-end">
                      <button
                        type="button"
                        onClick={onExportPdf}
                        disabled={exportBusy || sectionLoading}
                        className="rounded-xl bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60"
                      >
                        {exportBusy ? "Exporting..." : "Export PDF"}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex-1 min-h-0 overflow-hidden p-4">
                  <div className="flex h-full min-h-0 flex-col">
                    <div className="flex-1 min-h-0 overflow-hidden">
                      {sectionLoading ? (
                        <div className="text-sm text-slate-300">Loading...</div>
                      ) : sectionError ? (
                        <div className="rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                          Error: {sectionError}
                        </div>
                      ) : (
                        <MarkdownPrintReady
                          content={sectionData?.markdown ?? "No content available."}
                          section={activeTab}
                        />
                      )}
                    </div>
                  </div>
                </div>
              </ShellCard>

              {pageErr ? (
                <div className="shrink-0 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                  Error: {pageErr}
                </div>
              ) : null}
            </div>
          </main>
        </div>
      </div>

      <div className="hidden h-screen overflow-hidden xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1fr)] xl:grid-rows-[auto_auto_auto_minmax(0,1fr)]">
        <aside className="col-[1] row-[1/5] border-r border-white/10 bg-[#060815]">
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
                    <span className={active ? "text-slate-50" : "text-slate-200"}>
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

        <div className="col-[2] row-[1/5] border-r border-white/10 bg-[#070A12]" />

        <header className="col-[3] row-[1] border-b border-white/10 bg-[#070A12]">
          <div className="flex h-[89px] items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              ISO 27001 Final Deliverables
            </h1>
          </div>
        </header>

        <div className="col-[3] row-[2] p-3">
          <ShellCard className="flex min-h-[71px] min-w-0 items-center px-4">
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
        </div>

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

        <div className="col-[3] row-[4] min-h-0 p-3 pt-0">
          <ShellCard className="flex h-full min-h-0 flex-col overflow-hidden">
            <div className="shrink-0 border-b border-white/10 p-5">
              <div className="flex items-center justify-between gap-3">
                <div className="flex flex-wrap gap-2">
                  {FINAL_TABS.map((tab) => (
                    <TabButton
                      key={tab.key}
                      active={activeTab === tab.key}
                      label={tab.label}
                      onClick={() => {
                        window.location.hash = tab.href;
                      }}
                    />
                  ))}
                </div>

                <button
                  type="button"
                  onClick={onExportPdf}
                  disabled={exportBusy || sectionLoading}
                  className="rounded-xl bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60"
                >
                  {exportBusy ? "Exporting..." : "Export PDF"}
                </button>
              </div>
            </div>

            <div className="flex-1 min-h-0 overflow-hidden p-6">
              <div className="flex h-full min-h-0 flex-col">
                <div className="flex-1 min-h-0 overflow-hidden">
                  {sectionLoading ? (
                    <div className="text-sm text-slate-300">Loading...</div>
                  ) : sectionError ? (
                    <div className="rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                      Error: {sectionError}
                    </div>
                  ) : (
                    <MarkdownPrintReady
                      content={sectionData?.markdown ?? "No content available."}
                      section={activeTab}
                    />
                  )}
                </div>

                {pageErr ? (
                  <div className="mt-5 shrink-0 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                    Error: {pageErr}
                  </div>
                ) : null}
              </div>
            </div>
          </ShellCard>
        </div>
      </div>
    </div>
  );
}
