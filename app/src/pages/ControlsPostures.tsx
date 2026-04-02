import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Plus,
  Send,
  ChevronRight,
  Layers,
  Server,
} from "lucide-react";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type DashboardDTO = {
  environment?: string;
  scope?: {
    name?: string;
    asset_count?: number;
    status?: StepStatus;
  };
  scope_context_section2?: {
    title?: string;
    bullets?: string[];
  };
};

type SystemStatusDTO = {
  meta: { name: string; version: string };
  sections: Record<string, { status: StepStatus; scope_file_name?: string }>;
};

type ChatMessage =
  | { role: "user" | "assistant"; content: string }
  | {
      role: "assistant";
      type: "reset-confirmation";
      content: string;
    };

type ExistingControlsMap = Record<string, string[]>;

type HostControlPostureRow = {
  hostname: string;
  role: string;
  ip_address: string;
  cia_rating: "Critical" | "High" | "Medium" | "Low" | "Unscanned" | string;
  items_count?: number;
  existing_controls?: ExistingControlsMap;
};

type ControlPosturesDTO = {
  success?: boolean;
  year?: number;
  status?: StepStatus;
  kpis?: {
    hosts?: number;
    controls?: number;
  };
  hosts?: HostControlPostureRow[];
};

type CreateControlPostureAssessmentResponse = {
  success: boolean;
  existed_before?: boolean;
  recreated?: boolean;
  created_file?: string;
  status?: StepStatus;
  message?: string;
};

type ResetControlPostureAssessmentResponse = {
  success?: boolean;
  message?: string;
};

type Kpi = {
  title: string;
  value: string;
  icon: React.ReactNode;
  accent: "amber" | "emerald" | "rose" | "slate";
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function apiGetJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    cache: "no-store",
    headers: {
      "Cache-Control": "no-cache",
      Pragma: "no-cache",
    },
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }

  return (await res.json()) as T;
}

async function apiGetDashboard(
  env: string,
  options?: { cacheBust?: boolean }
): Promise<DashboardDTO> {
  const qs = new URLSearchParams({ env });

  if (options?.cacheBust) {
    qs.set("_ts", Date.now().toString());
  }

  return apiGetJSON<DashboardDTO>(`/api/dashboard/summary?${qs.toString()}`);
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>(`/api/system/status?_ts=${Date.now()}`);
}

/*
  Keep these API routes aligned with your backend.
  Replace them later if you create dedicated control-posture endpoints.
*/
async function apiGetControlPostures(year: number): Promise<ControlPosturesDTO> {
  return apiGetJSON<ControlPosturesDTO>(
    `/api/controls-postures/summary?year=${encodeURIComponent(
      String(year)
    )}&_ts=${Date.now()}`
  );
}

async function apiCreateControlPostureAssessment(
  year: number,
  forceReset: boolean = false
): Promise<CreateControlPostureAssessmentResponse> {
  const res = await fetch(`${API_BASE}/api/controls-postures/new`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache",
      Pragma: "no-cache",
    },
    body: JSON.stringify({
      year,
      force_reset: forceReset,
    }),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data?.detail || `HTTP ${res.status}`);
  }

  return data as CreateControlPostureAssessmentResponse;
}

async function apiResetControlPostures(
  year: number
): Promise<ResetControlPostureAssessmentResponse> {
  const res = await fetch(`${API_BASE}/api/controls-postures/reset`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache",
      Pragma: "no-cache",
    },
    body: JSON.stringify({ year }),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data?.detail || `HTTP ${res.status}`);
  }

  return data as ResetControlPostureAssessmentResponse;
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
          <div className="mt-2 text-3xl font-semibold leading-none text-white">
            {kpi.value}
          </div>
        </div>
        <div
          className={`grid h-12 w-12 shrink-0 place-items-center rounded-2xl ${badge}`}
        >
          {kpi.icon}
        </div>
      </div>
    </ShellCard>
  );
}

function CiaPill({ value }: { value: string }) {
  if (!value || value === "Unscanned") {
    return <span className="text-slate-400">-</span>;
  }

  const map: Record<string, string> = {
    Critical: "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25",
    High: "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/25",
    Medium: "bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/25",
    Low: "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25",
  };

  return (
    <span
      className={`inline-flex items-center rounded-lg px-3 py-1 text-xs ${
        map[value] || "bg-white/5 text-slate-200 ring-1 ring-white/10"
      }`}
    >
      {value}
    </span>
  );
}


function AssistantMessages({
  messages,
  sending,
  onResetConfirm,
  chatBottomRef,
}: {
  messages: ChatMessage[];
  sending: boolean;
  onResetConfirm: (confirmed: boolean) => void;
  chatBottomRef: React.RefObject<HTMLDivElement | null>;
}) {
  return (
    <div className="space-y-3">
      {messages.map((m, idx) => {
        const isUser = m.role === "user";

        if (
          m.role === "assistant" &&
          "type" in m &&
          m.type === "reset-confirmation"
        ) {
          return (
            <div key={idx} className="flex justify-start">
              <div className="max-w-[90%] rounded-2xl bg-white/5 px-4 py-4 text-sm text-slate-200 ring-1 ring-white/10">
                <div className="whitespace-pre-wrap">{m.content}</div>

                <div className="mt-4 flex items-center gap-3">
                  <button
                    onClick={() => onResetConfirm(true)}
                    className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                  >
                    Yes
                  </button>

                  <button
                    onClick={() => onResetConfirm(false)}
                    className="rounded-xl bg-white/10 px-4 py-2 text-sm font-semibold text-white transition hover:bg-white/15"
                  >
                    No
                  </button>
                </div>
              </div>
            </div>
          );
        }

        return (
          <div
            key={idx}
            className={`flex ${isUser ? "justify-end" : "justify-start"}`}
          >
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

      {sending ? (
        <div className="flex justify-start">
          <div className="max-w-[90%] rounded-2xl bg-white/5 px-4 py-3 text-sm text-slate-200 ring-1 ring-white/10">
            …
          </div>
        </div>
      ) : null}

      <div ref={chatBottomRef} />
    </div>
  );
}

function getExistingControlRows(
  existingControls?: Record<string, string[]>
): Array<{ category: string; names: string }> {
  if (!existingControls || Object.keys(existingControls).length === 0) {
    return [];
  }

  return Object.entries(existingControls).map(([category, items]) => ({
    category,
    names: Array.isArray(items) ? items.filter(Boolean).join(", ") : "",
  }));
}

export default function ControlsPostures() {
  const YEAR = 2026;

  const [selectedStep, setSelectedStep] = useState<number>(4);

  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboard, setDashboard] = useState<DashboardDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [cpData, setCpData] = useState<ControlPosturesDTO | null>(null);
  const [cpErr, setCpErr] = useState<string | null>(null);
  const [cpLoading, setCpLoading] = useState(false);

  const [creatingAssessment, setCreatingAssessment] = useState(false);
  const [resettingAssessment, setResettingAssessment] = useState(false);

  const [expandedHostname, setExpandedHostname] = useState<string | null>(null);

  const expandedRowRef = useRef<HTMLTableCellElement | null>(null);
  const tableScrollRef = useRef<HTMLDivElement | null>(null);

  const [showResetPopup, setShowResetPopup] = useState(false);
  const [resetPopupLoading, setResetPopupLoading] = useState(false);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Existing Controls & Postures — Command Mode\n\n" +
        "Available commands:\n" +
        "/help        → Explain this section\n" +
        "/commands    → Show available commands\n" +
        "/assess      → New existing controls and postures assessment\n" +
        "/submit      → Submit this section\n" +
        "/reset       → Clear controls and postures section\n" +
        "/exit        → Exit current mode",
    },
  ]);

  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement | null>(null);

  const hosts = useMemo(() => {
    return (cpData?.hosts ?? []).map((h: any) => ({
      ...h,
      cia_rating: h.cia_rating || h.CIA_rating || "Unscanned",
    }));
  }, [cpData]);
    
  const NAV_ITEMS = useMemo(
    () => [
      { step: 1, name: "Scope & Context", href: "#/scope" },
      { step: 2, name: "Asset Inventory & CIA", href: "#/assets" },
      { step: 3, name: "Threats & Vulnerabilities", href: "#/threats" },
      { step: 4, name: "Existing Controls & Posture", href: "#/controls" },
      { step: 5, name: "Risk Analysis", href: "#/" },
      { step: 6, name: "Risk Evaluation", href: "#/" },
      { step: 7, name: "Risk Treatment", href: "#/" },
      { step: 8, name: "Annex A & SoA", href: "#/" },
      { step: 9, name: "Action Plan / Implementation", href: "#/" },
      { step: 10, name: "Monitoring & Improvement", href: "#/" },
      { step: 11, name: "Final Deliverables", href: "#/" },
    ],
    []
  );
    
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
      { step: 9, name: "Monitoring & Improvement", href: "#/" },
      { step: 10, name: "Final Deliverables", href: "#/" },
    ],
    []
  );

  const displayScopeName = dashboard?.scope?.name?.trim() || "NA";

  const postureStatus: StepStatus = useMemo(() => {
    if (systemStatus?.sections?.controls_posture?.status) {
      return systemStatus.sections.controls_posture.status;
    }

    if (systemStatus?.sections?.existing_controls_postures?.status) {
      return systemStatus.sections.existing_controls_postures.status;
    }

    if (cpData?.status) return cpData.status;

    const hasAny = hosts.some(
      (h) => h.existing_controls && Object.keys(h.existing_controls).length > 0
    );
    return hasAny ? "In Progress" : "Not Started";
  }, [systemStatus, cpData?.status, hosts]);

  const totalHosts = cpData?.kpis?.hosts ?? hosts.length ?? 0;

  const orgBoundaryItems = useMemo(() => {
    return Array.isArray(dashboard?.scope_context_section2?.bullets)
      ? dashboard.scope_context_section2.bullets
          .map((x) => String(x).trim())
          .filter(Boolean)
      : [];
  }, [dashboard]);

  const totalControls = useMemo(() => {
    return hosts.reduce((sum, host) => {
      const controls = host.existing_controls;
      if (!controls) return sum;

      return (
        sum +
        Object.values(controls).reduce(
          (innerSum, arr) => innerSum + (Array.isArray(arr) ? arr.length : 0),
          0
        )
      );
    }, 0);
  }, [hosts]);
    
  const kpis: Kpi[] = useMemo(
    () => [
      {
        title: "Total Hosts",
        value: String(totalHosts),
        icon: <Server className="h-6 w-6" />,
        accent: "emerald",
      },
      {
        title: "Total Controls",
        value: String(totalControls),
        icon: <Layers className="h-6 w-6" />,
        accent: "amber",
      },
    ],
    [totalHosts, totalControls]
  );

  useEffect(() => {
    const sync = () => {
      const h = (window.location.hash || "").toLowerCase();
      if (h.startsWith("#/scope")) setSelectedStep(1);
      else if (h.startsWith("#/assets")) setSelectedStep(2);
      else if (h.startsWith("#/threats")) setSelectedStep(3);
      else if (h.startsWith("#/controls")) setSelectedStep(4);
    };

    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

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
    let cancelled = false;

    async function loadDashboard() {
      try {
        const data = await apiGetDashboard("Production", { cacheBust: true });
        if (!cancelled) setDashboard(data);
      } catch (e) {
        console.error("Failed to load dashboard summary:", e);
        if (!cancelled) setDashboard(null);
      }
    }

    loadDashboard();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadControlPosturesWithRetry() {
      setCpLoading(true);
      setCpErr(null);

      const maxAttempts = 3;

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const data = await apiGetControlPostures(YEAR);

          if (cancelled) return;

          setCpData(data);
          setCpErr(null);
          setCpLoading(false);
          return;
        } catch (e) {
          if (cancelled) return;

          const message = e instanceof Error ? e.message : String(e);

          if (attempt === maxAttempts) {
            setCpErr(message);
            setCpData(null);
            setCpLoading(false);
            return;
          }

          await new Promise((resolve) => setTimeout(resolve, 1200));
        }
      }
    }

    loadControlPosturesWithRetry();

    return () => {
      cancelled = true;
    };
  }, [YEAR]);

  useEffect(() => {
    requestAnimationFrame(() => {
      chatBottomRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "end",
      });
    });
  }, [messages, sending]);

  useEffect(() => {
    if (!expandedHostname || !expandedRowRef.current) return;

    requestAnimationFrame(() => {
      expandedRowRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
        inline: "nearest",
      });
    });
  }, [expandedHostname]);

  const refreshControlPostureSection = async () => {
    const [sys, dash, cp] = await Promise.all([
      apiGetSystemStatus().catch(() => null),
      apiGetDashboard("Production", { cacheBust: true }).catch(() => null),
      apiGetControlPostures(YEAR).catch(() => null),
    ]);

    if (sys) {
      setSystemStatus(sys);
      setScopeErr(null);
    }

    if (dash) {
      setDashboard(dash);
    }

    if (cp) {
      setCpData(cp);
      setCpErr(null);
    }
  };

  const removePendingResetConfirmation = () => {
    setMessages((prev) =>
      prev.filter(
        (m) =>
          !(
            "type" in m &&
            m.role === "assistant" &&
            m.type === "reset-confirmation"
          )
      )
    );
  };

  const onNewAssessment = async () => {
    if (creatingAssessment || resettingAssessment || resetPopupLoading) return;

    setCreatingAssessment(true);
    setCpErr(null);

    try {
      const result = await apiCreateControlPostureAssessment(YEAR, false);

      setExpandedHostname(null);
      await refreshControlPostureSection();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            result.message ||
            "Existing Controls and Postures Assessment started.",
        },
      ]);
    } catch (e: any) {
      const msg = e?.message || String(e);

      if (msg.includes("FILE_ALREADY_EXISTS_CONFIRM_RESET")) {
        setShowResetPopup(true);
        return;
      }

      setCpErr(msg);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Failed to start assessment: ${msg}`,
        },
      ]);
    } finally {
      setCreatingAssessment(false);
    }
  };
    
  const handleResetConfirm = async (confirmed: boolean) => {
    removePendingResetConfirmation();

    if (!confirmed) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Reset cancelled.",
        },
      ]);
      return;
    }

    if (resettingAssessment) return;

    setResettingAssessment(true);
    setCpErr(null);

    try {
      const result = await apiResetControlPostures(YEAR);

      setExpandedHostname(null);
      await refreshControlPostureSection();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            result.message ||
            "Existing Controls and Postures Assessment restarted. Data was cleared.",
        },
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setCpErr(msg);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Reset failed: ${msg}`,
        },
      ]);
    } finally {
      setResettingAssessment(false);
    }
  };
    
  const handlePopupCancel = () => {
    if (resetPopupLoading) return;
    setShowResetPopup(false);
  };

  const handlePopupConfirm = async () => {
    if (resetPopupLoading) return;

    setResetPopupLoading(true);
    setCpErr(null);

    try {
      const result = await apiCreateControlPostureAssessment(YEAR, true);

      setExpandedHostname(null);
      setShowResetPopup(false);
      await refreshControlPostureSection();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            result.message ||
            "Existing Controls and Postures Assessment restarted.",
        },
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setCpErr(msg);
      setShowResetPopup(false);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Reset failed: ${msg}`,
        },
      ]);
    } finally {
      setResetPopupLoading(false);
    }
  };
    
  const onSend = async () => {
    const text = input.trim();
    if (!text || sending) return;

    setMessages((prev) => [...prev, { role: "user", content: text }]);
    setInput("");
    setSending(true);

    try {
      if (text === "/help") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "Existing Controls & Postures\n\n" +
              "This section identifies the current security controls and implementation posture of each asset in the audit scope.\n\n" +
              "It builds on the Asset Inventory and Threats & Vulnerabilities sections by documenting the safeguards, configurations, security technologies, and operational protections already in place.\n\n" +
              "The system analyzes each host’s role, software, services, ports, and security configuration to determine which controls are implemented and how mature or effective the posture appears.\n\n" +
              "This section acts as the foundation for risk analysis by showing what protections already exist before calculating residual risk.",
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
              "Available commands:\n" +
              "/help        → Explain this section\n" +
              "/commands    → Show available commands\n" +
              "/assess      → New existing controls and postures assessment\n" +
              "/submit      → Submit this section\n" +
              "/reset       → Clear controls and postures section\n" +
              "/exit        → Exit current mode",
          },
        ]);
        return;
      }

      if (text === "/assess") {
        removePendingResetConfirmation();

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            type: "reset-confirmation",
            content:
              "An Existing Controls and Postures Assessment already exists.\n\nDo you want to start a new assessment?",
          },
        ]);
        return;
      }

      if (text === "/reset") {
        removePendingResetConfirmation();

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            type: "reset-confirmation",
            content: "Restart Existing Controls and Postures Assessment?",
          },
        ]);
        return;
      }

      if (text === "/exit") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "Exited current mode.",
          },
        ]);
        return;
      }

      if (text === "/submit") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "(Mock) Submit will be connected to backend next.",
          },
        ]);
        return;
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Unknown command. Type /commands to see available commands.",
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      {/* Mobile / small screens */}
      <div className="flex h-full flex-col xl:hidden">
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
            {LEFT_MENU_ITEMS.map((item) => {
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

          <div className="px-4 pb-4">
            <button
              onClick={() => (window.location.hash = "#/dashboard")}
              className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
            >
              Dashboard
            </button>
          </div>
        </aside>

        <main className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
          <header className="mb-4">
            <div className="rounded-2xl border border-white/10 bg-[#070A12] py-4 text-center ring-1 ring-white/10">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                Existing Control &amp; Postures
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
                    <span className="text-sm text-slate-300">({totalHosts} assets)</span>
                    <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                      <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                      {postureStatus}
                    </span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button
                onClick={() => void onNewAssessment()}
                disabled={creatingAssessment}
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600 disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {creatingAssessment
                  ? "Creating..."
                  : "New Existing Control and Postures Assessment"}
              </button>
            </div>

            <ShellCard className="p-4">
              <div className="text-sm font-semibold text-slate-100">
                Scope &amp; Context — Section 2 (Organizational Boundaries)
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

              {cpErr ? (
                <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                  Error loading existing control/posture data: {cpErr}
                </div>
              ) : null}

              {cpLoading ? (
                <div className="mt-3 rounded-xl bg-white/5 px-4 py-3 text-sm text-slate-300 ring-1 ring-white/10">
                  Loading existing controls / postures data...
                </div>
              ) : null}
            </ShellCard>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {kpis.map((k) => (
                <KpiCard key={k.title} kpi={k} />
              ))}
            </div>

            <ShellCard className="p-5">
              <div className="shrink-0 text-lg font-semibold">
                Existing Controls &amp; Postures
              </div>

              <div
                ref={tableScrollRef}
                className="mt-4 max-h-[60vh] overflow-y-auto overflow-x-hidden rounded-xl ring-1 ring-white/10"
              >
                <table className="w-full table-fixed text-left text-sm">
                  <thead className="sticky top-0 z-10 bg-[#0b1020]">
                    <tr className="text-slate-300">
                      <th className="w-[22%] px-4 py-3 font-medium">Hostname</th>
                      <th className="w-[26%] px-4 py-3 font-medium">Role</th>
                      <th className="w-[17%] px-4 py-3 font-medium">IP Address</th>
                      <th className="w-[15%] px-4 py-3 font-medium">CIA rating</th>
                      <th className="w-[20%] px-4 py-3 text-center font-medium">
                        Controls &amp; Postrures
                      </th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-white/5">
                    {hosts.map((r, idx) => {
                      const open = expandedHostname === r.hostname;

                      return (
                        <React.Fragment key={`${r.hostname || "row"}-${idx}`}>
                          <tr
                            className="cursor-pointer hover:bg-white/5"
                            onClick={() =>
                              setExpandedHostname((prev) =>
                                prev === r.hostname ? null : r.hostname
                              )
                            }
                          >
                            <td className="px-4 py-3 text-slate-100">{r.hostname}</td>
                            <td className="break-words px-4 py-3 text-slate-200">
                              {r.role || "-"}
                            </td>
                            <td className="break-words px-4 py-3 text-slate-200">
                              {r.ip_address || "-"}
                            </td>
                                <td className="px-4 py-3">
                                  <div className="flex justify-center">
                                    <CiaPill value={r.cia_rating || "Unscanned"} />
                                  </div>
                                </td>
                            <td className="px-4 py-3 text-center">
                              <div className="flex justify-center">
                                <ChevronRight
                                  className={`h-5 w-5 text-slate-300 transition-transform ${
                                    open ? "rotate-90" : ""
                                  }`}
                                />
                              </div>
                            </td>
                          </tr>

                          {open ? (
                            <tr>
                              <td
                                ref={expandedRowRef}
                                colSpan={5}
                                className="border-l-4 border-indigo-500 bg-[#0e162b] px-4 py-4"
                              >
                                <div className="max-h-[280px] overflow-y-auto overflow-x-hidden rounded-xl bg-[#111a33] ring-1 ring-indigo-500/20">
                                  <table className="w-full table-fixed text-left text-sm">
                                    <thead className="sticky top-0 z-10 bg-[#162040]">
                                      <tr className="text-slate-300">
                                        <th className="w-[40%] px-4 py-3 font-medium">
                                          Control &amp; Posture Category
                                        </th>
                                        <th className="w-[60%] px-4 py-3 font-medium">
                                          Name of Controls &amp; Postures
                                        </th>
                                      </tr>
                                    </thead>

                                    <tbody className="divide-y divide-white/5">
                                      {(() => {
                                        const rows = getExistingControlRows(r.existing_controls);
                                    
                                        if (!r.existing_controls || Object.keys(r.existing_controls).length === 0) {
                                          return (
                                            <tr>
                                              <td colSpan={2} className="px-4 py-3 text-slate-400">
                                                There is no record.
                                              </td>
                                            </tr>
                                          );
                                        }
                                    
                                        if (rows.length === 0) {
                                          return (
                                            <tr>
                                              <td colSpan={2} className="px-4 py-3 text-slate-400">
                                                There is no record.
                                              </td>
                                            </tr>
                                          );
                                        }
                                    
                                        return rows.map((item, i) => (
                                          <tr key={`${r.hostname}-cp-${i}`} className="hover:bg-white/5">
                                            <td className="break-words px-4 py-3 text-slate-100">
                                              {item.category}
                                            </td>
                                            <td className="break-words px-4 py-3 text-slate-200">
                                              {item.names || "-"}
                                            </td>
                                          </tr>
                                        ));
                                      })()}
                                    </tbody>
                                  </table>
                                </div>
                              </td>
                            </tr>
                          ) : null}
                        </React.Fragment>
                      );
                    })}

                    {hosts.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center text-slate-400">
                          No existing control / posture data found.
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </ShellCard>

            <ShellCard className="flex min-h-[700px] flex-col overflow-hidden">
              <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-5 py-4">
                <div className="text-lg font-semibold">Assistant</div>
                <div className="text-sm text-slate-400">Command mode</div>
              </div>

              <div className="flex min-h-0 flex-1 flex-col px-5 py-4">
                <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-[#060815] p-4 ring-1 ring-white/10">
                  <AssistantMessages
                    messages={messages}
                    sending={sending || resettingAssessment}
                    onResetConfirm={handleResetConfirm}
                    chatBottomRef={chatBottomRef}
                  />
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
                    disabled={sending || resettingAssessment}
                  >
                    <Send className="h-4 w-4" />
                    Send
                  </button>
                </div>

                <div className="mt-3 shrink-0 text-xs text-slate-500">
                  Command mode: /help /commands /assess /submit /reset /exit
                </div>
              </div>
            </ShellCard>
          </div>
        </main>
      </div>

      {/* Desktop / large screens */}
      <div className="hidden h-full overflow-hidden xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1.66fr)_minmax(380px,1fr)] xl:grid-rows-[auto_auto_auto_auto_minmax(0,1fr)]">
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
              {LEFT_MENU_ITEMS.map((item) => {
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

            <div className="p-4">
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
              Existing Control &amp; Postures
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

                  <span className="text-sm text-slate-300">- ({totalHosts} assets)</span>

                  <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                    {postureStatus}
                  </span>
                </div>
              </div>
            </div>
          </ShellCard>
        </div>

        <div className="col-[4] row-[2] p-3 pl-2">
          <div className="flex min-h-[71px] items-center justify-end">
            <button
              onClick={() => void onNewAssessment()}
              disabled={creatingAssessment}
              className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600 disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              {creatingAssessment
                ? "Creating..."
                : "New Existing Control and Postures Assessment"}
            </button>
          </div>
        </div>

        <div className="col-[3] row-[3] p-3 pr-2">
          <ShellCard className="min-h-[161px] p-4">
            <div className="text-sm font-semibold text-slate-100">
              Scope &amp; Context — Section 2 (Organizational Boundaries)
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

            {cpErr ? (
              <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Error loading existing control/posture data: {cpErr}
              </div>
            ) : null}

            {cpLoading ? (
              <div className="mt-3 rounded-xl bg-white/5 px-4 py-3 text-sm text-slate-300 ring-1 ring-white/10">
                Loading existing controls / postures data...
              </div>
            ) : null}
          </ShellCard>
        </div>

        <div className="col-[3] row-[4] p-3 pr-2">
          <div className="grid  grid-cols-1 gap-4 sm:grid-cols-2">
            {kpis.map((k) => (
              <KpiCard key={k.title} kpi={k} />
            ))}
          </div>
        </div>

        <div className="col-[3] row-[5] min-h-0 p-3 pr-2">
          <ShellCard className="flex h-full min-h-0 flex-col p-5">
            <div className="shrink-0 text-lg font-semibold">
              Existing Controls &amp; Postures
            </div>

            <div
              ref={tableScrollRef}
              className="mt-4 min-h-0 flex-1 overflow-y-auto overflow-x-hidden rounded-xl ring-1 ring-white/10"
            >
              <table className="w-full table-fixed text-left text-sm">
                <thead className="sticky top-0 z-10 bg-[#0b1020]">
                  <tr className="text-slate-300">
                    <th className="w-[22%] px-4 py-3 font-medium">Hostname</th>
                    <th className="w-[26%] px-4 py-3 font-medium">Role</th>
                    <th className="w-[17%] px-4 py-3 font-medium">IP Address</th>
                    <th className="w-[15%] px-4 py-3 font-medium">CIA rating</th>
                    <th className="w-[20%] px-4 py-3 text-center font-medium">
                      Controls &amp; Postrures
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-white/5">
                  {hosts.map((r, idx) => {
                    const open = expandedHostname === r.hostname;

                    return (
                      <React.Fragment key={`${r.hostname || "row"}-${idx}`}>
                        <tr
                          className="cursor-pointer hover:bg-white/5"
                          onClick={() =>
                            setExpandedHostname((prev) =>
                              prev === r.hostname ? null : r.hostname
                            )
                          }
                        >
                          <td className="px-4 py-3 text-slate-100">{r.hostname}</td>
                          <td className="break-words px-4 py-3 text-slate-200">
                            {r.role || "-"}
                          </td>
                          <td className="break-words px-4 py-3 text-slate-200">
                            {r.ip_address || "-"}
                          </td>
                          <td className="px-4 py-3">
                              <div className="flex justify-center">
                                <CiaPill value={r.cia_rating || "Unscanned"} />
                              </div>
                            </td>
                          <td className="px-4 py-3 text-center">
                            <div className="flex justify-center">
                              <ChevronRight
                                className={`h-5 w-5 text-slate-300 transition-transform ${
                                  open ? "rotate-90" : ""
                                }`}
                              />
                            </div>
                          </td>
                        </tr>

                        {open ? (
                          <tr>
                            <td
                              ref={expandedRowRef}
                              colSpan={5}
                              className="border-l-4 border-indigo-500 bg-[#0e162b] px-4 py-4"
                            >
                              <div className="max-h-[280px] overflow-y-auto overflow-x-hidden rounded-xl bg-[#111a33] ring-1 ring-indigo-500/20">
                                <table className="w-full table-fixed text-left text-sm">
                                  <thead className="sticky top-0 z-10 bg-[#162040]">
                                    <tr className="text-slate-300">
                                      <th className="w-[40%] px-4 py-3 font-medium">
                                        Control &amp; Posture Category
                                      </th>
                                      <th className="w-[60%] px-4 py-3 font-medium">
                                        Name of Controls &amp; Postures
                                      </th>
                                    </tr>
                                  </thead>

                                  <tbody className="divide-y divide-white/5">
                                    {(() => {
                                      const rows = getExistingControlRows(r.existing_controls);
                                
                                      if (!r.existing_controls || Object.keys(r.existing_controls).length === 0) {
                                        return (
                                          <tr>
                                            <td colSpan={2} className="px-4 py-3 text-slate-400">
                                              There is no record.
                                            </td>
                                          </tr>
                                        );
                                      }
                                
                                      if (rows.length === 0) {
                                        return (
                                          <tr>
                                            <td colSpan={2} className="px-4 py-3 text-slate-400">
                                              There is no record.
                                            </td>
                                          </tr>
                                        );
                                      }
                                
                                      return rows.map((item, i) => (
                                        <tr key={`${r.hostname}-cp-${i}`} className="hover:bg-white/5">
                                          <td className="break-words px-4 py-3 text-slate-100">
                                            {item.category}
                                          </td>
                                          <td className="break-words px-4 py-3 text-slate-200">
                                            {item.names || "-"}
                                          </td>
                                        </tr>
                                      ));
                                    })()}
                                  </tbody>
                                </table>
                              </div>
                            </td>
                          </tr>
                        ) : null}
                      </React.Fragment>
                    );
                  })}

                  {hosts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-slate-400">
                        No existing control / posture data found.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </ShellCard>
        </div>

        <div className="col-[4] row-[3/6] min-h-0 p-3 pl-2">
          <ShellCard className="flex h-full min-h-0 flex-col overflow-hidden">
            <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-5 py-4">
              <div className="text-lg font-semibold">Assistant</div>
              <div className="text-sm text-slate-400">Command mode</div>
            </div>

            <div className="flex min-h-0 flex-1 flex-col px-5 py-4">
              <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-[#060815] p-4 ring-1 ring-white/10">
                <AssistantMessages
                  messages={messages}
                  sending={sending || resettingAssessment}
                  onResetConfirm={handleResetConfirm}
                  chatBottomRef={chatBottomRef}
                />
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
                  disabled={sending || resettingAssessment}
                >
                  <Send className="h-4 w-4" />
                  Send
                </button>
              </div>

              <div className="mt-3 shrink-0 text-xs text-slate-500">
                Command mode: /help /commands /assess /submit /reset /exit
              </div>
            </div>
          </ShellCard>
        </div>
      </div>

      {showResetPopup ? (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/55 backdrop-blur-sm">
          <div className="w-[460px] max-w-[92vw] rounded-2xl border border-white/10 bg-[#0B1120] p-6 shadow-2xl ring-1 ring-white/10">
            <div className="text-[22px] font-semibold tracking-tight text-slate-100">
              Confirm Reset
            </div>

            <div className="mt-4 text-[15px] leading-7 text-slate-300">
              An Existing Controls and Postures Assessment already exists.
              <br />
              <br />
              Do you want to start new{" "}
              <span className="font-semibold text-white">
                existing controls and postures
              </span>{" "}
              assessment?
            </div>

            <div className="mt-8 flex items-center justify-end gap-3">
              <button
                onClick={handlePopupCancel}
                disabled={resetPopupLoading}
                className="rounded-xl bg-white/10 px-5 py-2.5 text-sm font-semibold text-slate-100 ring-1 ring-white/10 transition hover:bg-white/15 disabled:opacity-60"
              >
                Cancel
              </button>

              <button
                onClick={() => void handlePopupConfirm()}
                disabled={resetPopupLoading}
                className="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60"
              >
                {resetPopupLoading ? "Resetting..." : "Yes"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}