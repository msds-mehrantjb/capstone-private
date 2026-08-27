import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Send,
} from "lucide-react";
import CommandHelpMessage, {
  isCommandHelpMessage,
} from "../components/CommandHelpMessage";
import StepStatusBadge from "../components/StepStatusBadge";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  confirmAction?:
    | "recreate_annex"
    | "reset_annex"
    | "delete_annex_row"
    | "delete_evidence"
    | "submit_annex";
};

type MonitoringImprovementCVE = {
  CVE: string;
  vulnerability: string;
  implementation_status:
    | ""
    | "Not Implemented"
    | "Planned"
    | "In Progress"
    | "Implemented"
    | "Not Applicable";
  justification?: string;
  recommended_action?: string;
  hosts?: MonitoringImprovementHost[];
};

type MonitoringImprovementEvidenceForm = {
  responsible: string;
  date: string;
  resources: string;
  url: string;
  desc: string;
};

type RecommendActionResponse = {
  success?: boolean;
  message?: string;
  inventory?: MonitoringInventoryResponse;
  control?: MonitoringImprovementCVE;
};

async function apiRecommendAction(
  year: number,
  control_id: string
): Promise<RecommendActionResponse> {
  return apiPostJSONBody<RecommendActionResponse>(
    "/api/monitoring-improvement/recommend",
    {
      year,
      control_id,
    }
  );
}

type MonitoringImprovementEvidence = {
  responsible?: string;
  resources?: string;
  date?: string;
  url?: string;
  desc?: string;
};

type MonitoringImprovementHost = {
  hostname?: string;
  ip_address?: string;
  role?: string;
  vulnerability_name?: string;
  ["CIA rating"]?: string;
  evidence?: MonitoringImprovementEvidence[];
};

function hasMeaningfulEvidence(
  ev: MonitoringImprovementEvidence | null | undefined
): boolean {
  if (!ev || typeof ev !== "object") return false;

  return Boolean(
    (ev.responsible && ev.responsible.trim() !== "") ||
      (ev.resources && ev.resources.trim() !== "") ||
      (ev.date && ev.date.trim() !== "") ||
      (ev.url && ev.url.trim() !== "") ||
      (ev.desc && ev.desc.trim() !== "")
  );
}

function getMeaningfulEvidence(
  evidence: MonitoringImprovementEvidence[] | null | undefined
): Array<{ ev: MonitoringImprovementEvidence; rawIndex: number }> {
  if (!Array.isArray(evidence)) return [];

  return evidence
    .map((ev, rawIndex) => ({ ev, rawIndex }))
    .filter(({ ev }) => hasMeaningfulEvidence(ev));
}

function getTodayDateInputValue(): string {
  return new Date().toISOString().slice(0, 10);
}


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

type MonitoringInventoryResponse = {
  cves?: MonitoringImprovementCVE[];
};

type AnnexCreateResponse = {
  success?: boolean;
  message?: string;
  inventory?: MonitoringInventoryResponse;
};

type AnnexUpdateResponse = {
  success?: boolean;
  message?: string;
  inventory?: MonitoringInventoryResponse;
  guide_id?: string;
  guide_key?: string;
  guide_deleted?: boolean;
};

type AnnexSubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: MonitoringInventoryResponse;
  requires_confirmation?: boolean;
};

type AddEvidenceResponse = {
  success?: boolean;
  message?: string;
  inventory?: MonitoringInventoryResponse;
  guide_id?: string;
  guide_key?: string;
};

  type EditEvidenceForm = {
    responsible: string;
    date: string;
    resources: string;
    url: string;
    desc: string;
  };


type EvidenceDefaultsResponse = {
  success?: boolean;
  message?: string;
  evidence?: {
    responsible?: string;
    resources?: string;
    date?: string;
    url?: string;
    desc?: string;
  };
  inventory?: MonitoringInventoryResponse;
};

async function apiGetEvidenceDefaults(
  year: number,
  control_id: string,
  hostname: string,
  vulnerability_name: string
): Promise<EvidenceDefaultsResponse> {
  return apiPostJSONBody<EvidenceDefaultsResponse>(
    "/api/monitoring-improvement/evidence-defaults",
    {
      year,
      control_id,
      hostname,
      vulnerability_name,
    }
  );
}

async function apiAddEvidence(
  year: number,
  control_id: string,
  hostname: string,
  vulnerability_name: string,  
  evidence: {
    responsible: string;
    resources: string;
    date: string;
    url: string;
    desc: string;
  }
): Promise<AddEvidenceResponse> {
  return apiPostJSONBody<AddEvidenceResponse>(
    "/api/monitoring-improvement/add-evidence",
    {
      year,
      control_id,
      hostname,
      vulnerability_name,  
      evidence,
    }
  );
}

async function apiEditEvidence(
  year: number,
  control_id: string,
  hostname: string,
  vulnerability_name: string,
  evidence_index: number,
  evidence: {
    responsible: string;
    resources: string;
    date: string;
    url: string;
    desc: string;
  }
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>(
    "/api/monitoring-improvement/edit-evidence",
    {
      year,
      control_id,
      hostname,
      vulnerability_name,
      evidence_index,
      evidence,
    }
  );
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8003";

async function apiGetJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function apiDeleteEvidence(
  year: number,
  control_id: string,
  hostname: string,
  vulnerability_name: string,
  evidence_index: number
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>(
    "/api/monitoring-improvement/delete-evidence",
    {
      year,
      control_id,
      hostname,
      vulnerability_name,
      evidence_index,
    }
  );
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

async function apiUploadEvidence(file: File): Promise<string> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/monitoring-improvement/upload-evidence`, {
    method: "POST",
    body: formData,
  });

  const data = await res.json();
  return data.path;
}

async function apiDeleteMonitoringImprovementControl(
  year: number,
  control_id: string
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/monitoring-improvement/delete", {
    year,
    control_id,
  });
}

async function apiGetMonitoringImprovementInventory(year: number): Promise<MonitoringInventoryResponse> {
  return apiGetJSON<MonitoringInventoryResponse>(
    `/api/monitoring-improvement/inventory?year=${encodeURIComponent(String(year))}`
  );
}
async function apiCreateMonitoringImprovementInventory(year: number): Promise<AnnexCreateResponse> {
  return apiPostJSONBody<AnnexCreateResponse>("/api/monitoring-improvement/create", {
    year,
  });
}

async function apiUpdateMonitoringImprovementStatus(
  year: number,
  control_id: string,
  implementation_status: MonitoringImprovementCVE["implementation_status"]
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/monitoring-improvement/update-status", {
    year,
    control_id,
    implementation_status,
  });
}

async function apiResetMonitoringImprovement(year: number, confirm = false): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/monitoring-improvement/reset", {
    year,
    confirm,
  });
}

async function apiSubmitMonitoringImprovement(year: number, confirm = false): Promise<AnnexSubmitResponse> {
  return apiPostJSONBody<AnnexSubmitResponse>("/api/monitoring-improvement/submit", {
    year,
    confirm,
  });
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  let lastErr: unknown;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await apiGetJSON<SystemStatusDTO>("/api/system/status");
    } catch (e) {
      lastErr = e;
      if (attempt === 3) break;
      await new Promise((resolve) => setTimeout(resolve, attempt * 400));
    }
  }

  throw lastErr instanceof Error ? lastErr : new Error("Failed to fetch system status");
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/summary?year=${encodeURIComponent(String(year))}`
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

function ConfirmModal({
  open,
  title,
  text,
  onYes,
  onNo,
}: {
  open: boolean;
  title: string;
  text: string;
  onYes: () => void;
  onNo: () => void;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4">
      <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0b1020] p-6 shadow-2xl ring-1 ring-white/10">
        <div className="mb-3 text-lg font-semibold text-white">{title}</div>
        <div className="whitespace-pre-wrap text-sm text-slate-300">{text}</div>

        <div className="mt-5 flex justify-end gap-3">
          <button
            onClick={onNo}
            className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/10"
          >
            No
          </button>

          <button
            onClick={onYes}
            className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
          >
            Yes
          </button>
        </div>
      </div>
    </div>
  );
}

function AddEvidenceModal({
  open,
  hostLabel,
  form,
  onChange,
  onCancel,
  onSubmit,
  submitting = false,
}: {
  open: boolean;
  hostLabel: string;
  form: MonitoringImprovementEvidenceForm;
  onChange: (field: keyof MonitoringImprovementEvidenceForm, value: string) => void;
  onCancel: () => void;
  onSubmit: () => void;
  submitting?: boolean;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4">
      <div className="w-full max-w-3xl rounded-2xl border border-white/10 bg-[#0b1020] p-6 shadow-2xl ring-1 ring-white/10">
        <div className="mb-1 text-lg font-semibold text-white">
          Add evidence for host - {hostLabel}
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-200">
                Responsible
              </label>
              <input
                value={form.responsible}
                onChange={(e) => onChange("responsible", e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
                placeholder="Enter responsible person/team"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-200">
                Date
              </label>
              <input
                type="date"
                value={form.date}
                onChange={(e) => onChange("date", e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-200">
              Resources
            </label>
            <input
              value={form.resources}
              onChange={(e) => onChange("resources", e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              placeholder="Enter resources"
            />
          </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-200">
                URL/PATH
              </label>
            
              <div className="space-y-3">
                <input
                  value={form.url}
                  onChange={(e) => onChange("url", e.target.value)}
                  className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
                  placeholder="Enter URL or file path"
                />
            
                <div className="flex items-center gap-3">
                  <input
                    type="file"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
            
                      try {
                        const uploadedPath = await apiUploadEvidence(file);
                        onChange("url", uploadedPath);
                      } catch (err) {
                        console.error(err);
                        alert("Upload failed");
                      }
                    }}
                    className="block w-full text-sm text-slate-200 file:mr-4 file:rounded-xl file:border-0 file:bg-indigo-600/90 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-indigo-600"
                  />
                </div>
              </div>
            </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-200">
              Description
            </label>
            <textarea
              value={form.desc}
              onChange={(e) => onChange("desc", e.target.value)}
              rows={4}
              className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              placeholder="Enter description"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>

          <button
            onClick={onSubmit}
            disabled={submitting}
            className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Submitting..." : "Submit"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EditEvidenceModal({
  open,
  hostLabel,
  form,
  onChange,
  onCancel,
  onSubmit,
  submitting = false,
}: {
  open: boolean;
  hostLabel: string;
  form: EditEvidenceForm;
  onChange: (field: keyof EditEvidenceForm, value: string) => void;
  onCancel: () => void;
  onSubmit: () => void;
  submitting?: boolean;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4">
      <div className="w-full max-w-3xl rounded-2xl border border-white/10 bg-[#0b1020] p-6 shadow-2xl ring-1 ring-white/10">
        <div className="mb-1 text-lg font-semibold text-white">
          Edit evidence for host - {hostLabel}
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-200">
                Responsible
              </label>
              <input
                value={form.responsible}
                onChange={(e) => onChange("responsible", e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
                placeholder="Enter responsible person/team"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-200">
                Date
              </label>
              <input
                type="date"
                value={form.date}
                onChange={(e) => onChange("date", e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-200">
              Resources
            </label>
            <input
              value={form.resources}
              onChange={(e) => onChange("resources", e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              placeholder="Enter resources"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-200">
              URL/PATH
            </label>

            <div className="space-y-3">
              <input
                value={form.url}
                onChange={(e) => onChange("url", e.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
                placeholder="Enter URL or file path"
              />

              <div className="flex items-center gap-3">
                <input
                  type="file"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;

                    try {
                      const uploadedPath = await apiUploadEvidence(file);
                      onChange("url", uploadedPath);
                    } catch (err) {
                      console.error(err);
                      alert("Upload failed");
                    }
                  }}
                  className="block w-full text-sm text-slate-200 file:mr-4 file:rounded-xl file:border-0 file:bg-indigo-600/90 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-indigo-600"
                />
              </div>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-200">
              Description
            </label>
            <textarea
              value={form.desc}
              onChange={(e) => onChange("desc", e.target.value)}
              rows={4}
              className="w-full rounded-xl border border-white/10 bg-[#0f172a] px-3 py-2 text-sm text-slate-200 outline-none ring-0 focus:border-indigo-500"
              placeholder="Enter description"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>

          <button
            onClick={onSubmit}
            disabled={submitting}
            className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Updating..." : "Update"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function MonitoringImprovement() {
  const YEAR = 2026;

  const [confirmRecreateOpen, setConfirmRecreateOpen] = useState(false);

  const [confirmDeleteEvidenceOpen, setConfirmDeleteEvidenceOpen] = useState(false);
    
  const [selectedStep, setSelectedStep] = useState<number>(9);
  const [selectedControlIndex, setSelectedControlIndex] = useState<number | null>(null);

  const [selectedHostIndex, setSelectedHostIndex] = useState<number | null>(null);
  const [selectedEvidenceIndex, setSelectedEvidenceIndex] = useState<number | null>(null);
  const [monitoringImprovementControls, setMonitoringImprovementControls] = useState<MonitoringImprovementCVE[]>([]);

  // Reset when data refreshes
  useEffect(() => {
    setSelectedEvidenceIndex(null);
  }, [monitoringImprovementControls]);

  // Reset when user changes selection
  useEffect(() => {
    setSelectedEvidenceIndex(null);
  }, [selectedControlIndex, selectedHostIndex]);

  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [editEvidenceForm, setEditEvidenceForm] = useState<EditEvidenceForm>({
    responsible: "",
    date: "",
    resources: "",
    url: "",
    desc: "",
  });

  const [popupOpen, setPopupOpen] = useState(false);
  const [popupText] = useState("");

  const [pendingAssistantAction, setPendingAssistantAction] = useState<
    null | "recreate_annex" | "reset_annex" | "delete_annex_row" | "delete_evidence" | "submit_annex"
  >(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Monitoring and Improvement — Command Mode\n\n" +
        "Available commands:\n" +
        "/create     → Create new Monitoring / Improvement table\n" +
        "/recommend  → Recommend the monitoring action for selected row\n" +
        "/delete     → Delete the selected evidence\n" +
        "/add        → Add an evidence for selected host\n" +
        "/evidence   → Add evidence with auto-filled responsible, resources, and description\n" + 
        "/evidence-all → Add one auto-filled evidence item for every host row in the table\n" +
        "/edit       → Edit evidence for selected host\n" +
        "/submit     → Submit the table\n" +
        "/commands   → Display available commands\n" +
        "/help       → Explain this section",
    },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement | null>(null);

  const [addEvidenceModalOpen, setAddEvidenceModalOpen] = useState(false);

  const [editEvidenceModalOpen, setEditEvidenceModalOpen] = useState(false);
  const [evidenceForm, setEvidenceForm] = useState<MonitoringImprovementEvidenceForm>({
    responsible: "",
    date: "",
    resources: "",
    url: "",
    desc: "",
  });

    
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

  const handleDeleteSelectedEvidence = async () => {
    if (
      selectedControlIndex === null ||
      selectedHostIndex === null ||
      selectedEvidenceIndex === null
    ) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Please select an evidence row first.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const control = monitoringImprovementControls[selectedControlIndex];
    const host = control?.hosts?.[selectedHostIndex];

    if (!control || !host?.hostname) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Selected evidence context is invalid.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    try {
      setSending(true);

      const data = await apiDeleteEvidence(
        YEAR,
        control.CVE,
        host.hostname,
        host.vulnerability_name || "",
        selectedEvidenceIndex
      );

      if (data?.success === false) {
        throw new Error(data.message || "Failed to delete evidence.");
      }

      const updated = Array.isArray(data?.inventory?.cves)
        ? data.inventory.cves
        : [];
    
      setMonitoringImprovementControls([...updated]); // 🔥 FORCE NEW REFERENCE
      setSelectedEvidenceIndex(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            "Selected evidence and its linked monitoring guide were deleted successfully.",
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : "Failed to delete evidence.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };
    
  const resetEvidenceForm = () => {
    setEvidenceForm({
      responsible: "",
      date: "",
      resources: "",
      url: "",
      desc: "",
    });
  };

  const buildAutoEvidenceForm = (
    control: MonitoringImprovementCVE,
    host: MonitoringImprovementHost
  ): MonitoringImprovementEvidenceForm => {
    const controlId = (control.CVE || "").trim();
    const vulnerability = (control.vulnerability || host.vulnerability_name || "").trim();
    const recommendedAction = (control.recommended_action || "").trim();
    const hostname = (host.hostname || "").trim();
    const role = (host.role || "").trim();

    const responsibleByRole = (() => {
      const roleL = role.toLowerCase();

      if (
        roleL.includes("server") ||
        roleL.includes("domain controller") ||
        roleL.includes("dns") ||
        roleL.includes("database") ||
        roleL.includes("web")
      ) {
        return "System Administrator + Security Monitoring Team";
      }

      if (
        roleL.includes("workstation") ||
        roleL.includes("endpoint") ||
        roleL.includes("user") ||
        roleL.includes("employee")
      ) {
        return "Endpoint Administrator + Security Monitoring Team";
      }

      if (
        roleL.includes("network") ||
        roleL.includes("firewall") ||
        roleL.includes("router") ||
        roleL.includes("switch")
      ) {
        return "Network Administrator + Security Monitoring Team";
      }

      return "Asset Responsible Team + Security Monitoring Team";
    })();

    const briefDesc = (() => {
      if (recommendedAction) {
        const firstLine = recommendedAction
          .split("\n")
          .map((x) => x.trim())
          .find((x) => x && x !== "Recommended monitoring actions:" && x !== "-");

        const cleaned = (firstLine || recommendedAction)
          .replace(/^[-•]\s*/, "")
          .trim();

        return cleaned
          ? `Monitoring evidence for ${hostname} under ${controlId}: ${cleaned}.`
          : `Monitoring evidence for ${hostname} under ${controlId} related to ${vulnerability}.`;
      }

      return `Monitoring evidence for ${hostname} under ${controlId} related to ${vulnerability}.`;
    })();

    return {
      responsible: responsibleByRole,
      resources: [hostname ? `Host: ${hostname}` : "", role ? `Role: ${role}` : ""]
        .filter(Boolean)
        .join(" | "),
      date: "",
      url: "",
      desc: briefDesc,
    };
  };

  const selectedMonitoringImprovementControl =
    selectedControlIndex !== null ? monitoringImprovementControls[selectedControlIndex] : null;

  const selectedHost =
    selectedMonitoringImprovementControl &&
    selectedHostIndex !== null &&
    Array.isArray(selectedMonitoringImprovementControl.hosts) &&
    selectedMonitoringImprovementControl.hosts[selectedHostIndex]
      ? selectedMonitoringImprovementControl.hosts[selectedHostIndex]
      : null;

  const selectedEvidence =
    selectedHost &&
    selectedEvidenceIndex !== null &&
    Array.isArray(selectedHost.evidence) &&
    selectedHost.evidence[selectedEvidenceIndex]
      ? selectedHost.evidence[selectedEvidenceIndex]
      : null;
    
  const selectedHostLabel = selectedHost?.hostname?.trim() || "selected host";
 
  const handleOpenAddEvidence = async (autoFill = false) => {
    if (!selectedMonitoringImprovementControl) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select a CVE row first." },
     ]);
      scrollChatToBottom();
      return;
    }

    if (!selectedHost) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select a host row first." },
      ]);
      scrollChatToBottom();
      return;
    }

    if (!autoFill) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            `Add evidence for host - ${selectedHostLabel}\n` +
            `- Responsible: Who is responsible for this action\n` +
            `- Resources: Which resources used for this action\n` +
            `- Date: When this action happened\n` +
            `- URL/PATH: URL/Path for screenshot, log, file, ...`,
        },
      ]);

      resetEvidenceForm();
      setAddEvidenceModalOpen(true);
      scrollChatToBottom();
      return;
    }

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is using RAG over ISO 27001:2022 controls and Qwen3.8 27B reasoning to prepare evidence fields for the selected host.",
      },
    ]);
    scrollChatToBottom();

    try {
      setSending(true);

      const data = await apiGetEvidenceDefaults(
        YEAR,
        selectedMonitoringImprovementControl.CVE,
        selectedHost.hostname || "",
        selectedHost.vulnerability_name || ""
      );

      setEvidenceForm({
        responsible: data?.evidence?.responsible || "",
        date: "",
        resources: data?.evidence?.resources || "",
        url: data?.evidence?.url || "",
        desc: data?.evidence?.desc || "",
      });

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Evidence fields prepared for host ${selectedHostLabel}.`,
        },
      ]);

      setAddEvidenceModalOpen(true);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Failed to prepare evidence fields.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };
    
  const handleEvidenceFormChange = (
    field: keyof MonitoringImprovementEvidenceForm,
    value: string
  ) => {
    setEvidenceForm((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSubmitAddEvidence = async () => {
    if (!selectedMonitoringImprovementControl || !selectedHost) {
      setAddEvidenceModalOpen(false);
      return;
    }

    const hasAnyValue = Object.values(evidenceForm).some((v) => v.trim() !== "");
    if (!hasAnyValue) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please fill at least one evidence field." },
      ]);
      scrollChatToBottom();
      return;
    }

    try {
      setSending(true);

      const data = await apiAddEvidence(
        YEAR,
        selectedMonitoringImprovementControl.CVE,
        selectedHost.hostname || "",
        selectedHost.vulnerability_name || "",
        {
          responsible: evidenceForm.responsible,
          resources: evidenceForm.resources,
          date: evidenceForm.date,
          url: evidenceForm.url,
          desc: evidenceForm.desc,
        }
      );

      if (data?.success === false) {
        throw new Error(data.message || "Failed to add evidence.");
      }

      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Evidence added for host ${selectedHostLabel} and the linked monitoring guide was generated.`,
        },
      ]);

      setAddEvidenceModalOpen(false);
      resetEvidenceForm();
      scrollChatToBottom();
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : "Failed to add evidence.",
        },
      ]);
      scrollChatToBottom();
    } finally {
      setSending(false);
    }
  };

  const handleAddEvidenceAll = async () => {
    if (monitoringImprovementControls.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "No Monitoring and Improvement rows are available.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const pendingRows = monitoringImprovementControls.flatMap((control) => {
      const controlId = (control.CVE || "").trim();
      if (!controlId || !Array.isArray(control.hosts)) {
        return [];
      }

      return control.hosts
        .filter((host) => {
          const hostname = (host.hostname || "").trim();
          return hostname && getMeaningfulEvidence(host.evidence).length === 0;
        })
        .map((host) => ({
          control,
          controlId,
          hostname: (host.hostname || "").trim(),
          vulnerabilityName: (host.vulnerability_name || "").trim(),
          evidence: buildAutoEvidenceForm(control, host),
        }));
    });

    if (pendingRows.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Every host row already has at least one evidence item.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    setSending(true);
    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          `Please wait while the system generates one evidence item for ${pendingRows.length} host row(s) that do not already have evidence.`,
      },
    ]);

    try {
      let addedCount = 0;
      let failedCount = 0;
      const failedItems: string[] = [];

      for (let index = 0; index < pendingRows.length; index += 1) {
        const row = pendingRows[index];

        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: `Generating evidence ${index + 1} of ${pendingRows.length} for ${row.hostname} under ${row.controlId}...`,
          };
          return updated;
        });

        try {
          const defaults = await apiGetEvidenceDefaults(
            YEAR,
            row.controlId,
            row.hostname,
            row.vulnerabilityName
          );

          const data = await apiAddEvidence(
            YEAR,
            row.controlId,
            row.hostname,
            row.vulnerabilityName,
            {
              responsible:
                defaults?.evidence?.responsible || row.evidence.responsible,
              resources: defaults?.evidence?.resources || row.evidence.resources,
              date: defaults?.evidence?.date || row.evidence.date,
              url: defaults?.evidence?.url || row.evidence.url,
              desc: defaults?.evidence?.desc || row.evidence.desc,
            }
          );

          if (Array.isArray(data?.inventory?.cves)) {
            setMonitoringImprovementControls(data.inventory.cves);
          }

          if (data?.success === false) {
            failedCount += 1;
            failedItems.push(`${row.controlId} / ${row.hostname}`);
          } else {
            addedCount += 1;
          }
        } catch (error) {
          failedCount += 1;
          failedItems.push(`${row.controlId} / ${row.hostname}`);

          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = {
              role: "assistant",
              content:
                error instanceof Error
                  ? `${error.message} Continuing with the remaining host rows.`
                  : "Failed to generate evidence for one host row. Continuing with the remaining host rows.",
            };
            return updated;
          });
        }
      }

      setMessages((prev) => {
        const updated = [...prev];
        const failurePreview =
          failedItems.length > 0
            ? ` Failed rows: ${failedItems.slice(0, 5).join(", ")}${failedItems.length > 5 ? ", ..." : ""}`
            : "";
        updated[updated.length - 1] = {
          role: "assistant",
          content: `Evidence generation completed. Added ${addedCount} evidence item(s) across ${pendingRows.length} host row(s). Failed ${failedCount}.${failurePreview}`,
        };
        return updated;
      });
    } catch (e) {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Failed to generate evidence for all hosts.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleRecommendForSelectedRow = async () => {
    if (
      selectedControlIndex === null ||
      !monitoringImprovementControls[selectedControlIndex]
    ) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Please select a CVE first.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const selectedControl = monitoringImprovementControls[selectedControlIndex];

    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
        `Please wait, while system is using RAG over ISO 27001:2022 controls and Qwen3.8 27B reasoning to generate recommended action for selected row ${selectedControl.CVE}.`,
      },
    ]);

    try {
      const data = await apiRecommendAction(YEAR, selectedControl.CVE);

      setMonitoringImprovementControls(
        Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []
      );

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            data?.message ||
            `Recommended action generated for selected row ${selectedControl.CVE}.`,
        };
        return updated;
      });
    } catch (e) {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Error generating recommended action for selected row.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };  
    

  const handleConfirmRecreateYes = async () => {
    setConfirmRecreateOpen(false);
    await createMonitoringImprovementTableConfirmed();
  };

  const handleConfirmRecreateNo = () => {
    setConfirmRecreateOpen(false);
  };

  const hasAnyMonitoringImprovementStatus = monitoringImprovementControls.some(
    (c) => (c.implementation_status ?? "").trim() !== ""
  );

  const handleAssistantConfirmYes = async () => {
    if (pendingAssistantAction === "recreate_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await createMonitoringImprovementTableConfirmed();
      return;
    }

    if (pendingAssistantAction === "reset_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleResetMonitoringImprovement();
      return;
    }

    if (pendingAssistantAction === "delete_annex_row") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleDeleteSelectedMonitoringImprovementRow();
      return;
    }

    if (pendingAssistantAction === "delete_evidence") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleDeleteSelectedEvidence();
      return;
    }

    if (pendingAssistantAction === "submit_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleSubmitMonitoringImprovement();
    }
  };

  const resetEditEvidenceForm = () => {
    setEditEvidenceForm({
      responsible: "",
      date: "",
      resources: "",
      url: "",
      desc: "",
    });
  };

  const handleEditEvidenceFormChange = (
    field: keyof EditEvidenceForm,
    value: string
  ) => {
    setEditEvidenceForm((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleOpenEditEvidence = () => {
    if (!selectedMonitoringImprovementControl) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select a control row first." },
      ]);
      scrollChatToBottom();
      return;
    }

    if (!selectedHost) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select a host row first." },
      ]);
      scrollChatToBottom();
      return;
    }

    if (selectedEvidenceIndex === null || !selectedEvidence) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select an evidence row first." },
      ]);
      scrollChatToBottom();
      return;
    }

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          `Edit evidence for host - ${selectedHostLabel}\n` +
          `- Responsible: Who is responsible for this action\n` +
          `- Resources: Which resources used for this action\n` +
          `- Date: When this action happened\n` +
          `- URL/PATH: URL/Path for screenshot, log, file, ...`,
      },
    ]);

    setEditEvidenceForm({
      responsible: selectedEvidence.responsible || "",
      date: selectedEvidence.date || "",
      resources: selectedEvidence.resources || "",
      url: selectedEvidence.url || "",
      desc: selectedEvidence.desc || "",
    });

    setEditEvidenceModalOpen(true);
    scrollChatToBottom();
  };

  const handleSubmitEditEvidence = async () => {
    if (!selectedMonitoringImprovementControl || !selectedHost || selectedEvidenceIndex === null) {
      setEditEvidenceModalOpen(false);
      return;
    }

    const hasAnyValue = Object.values(editEvidenceForm).some((v) => v.trim() !== "");
    if (!hasAnyValue) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please fill at least one evidence field." },
      ]);
      scrollChatToBottom();
      return;
    }

    try {
      setSending(true);
      const editedUrl = editEvidenceForm.url.trim();
      const editedDate = editEvidenceForm.date.trim() || (editedUrl ? getTodayDateInputValue() : "");

      const data = await apiEditEvidence(
        YEAR,
        selectedMonitoringImprovementControl.CVE,
        selectedHost.hostname || "",
        selectedHost.vulnerability_name || "",
        selectedEvidenceIndex,
        {
          responsible: editEvidenceForm.responsible,
          resources: editEvidenceForm.resources,
          date: editedDate,
          url: editedUrl,
          desc: editEvidenceForm.desc,
        }
      );

      if (data?.success === false) {
        throw new Error(data.message || "Failed to edit evidence.");
      }

      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Evidence updated for host ${selectedHostLabel} and the linked monitoring guide was regenerated.`,
        },
      ]);

      setEditEvidenceModalOpen(false);
      resetEditEvidenceForm();
      scrollChatToBottom();
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : "Failed to edit evidence.",
        },
      ]);
      scrollChatToBottom();
    } finally {
      setSending(false);
    }
  };
    
  const handleAssistantConfirmNo = () => {
    if (pendingAssistantAction === "recreate_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "No" },
        { role: "assistant", content: "Recreate operation cancelled." },
      ]);

      scrollChatToBottom();
      return;
    }

    if (pendingAssistantAction === "reset_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "No" },
        { role: "assistant", content: "Reset operation cancelled." },
      ]);

      scrollChatToBottom();
      return;
    }

    if (pendingAssistantAction === "delete_annex_row") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "No" },
        { role: "assistant", content: "Delete operation cancelled." },
      ]);

      scrollChatToBottom();
      return;
    }

    if (pendingAssistantAction === "delete_evidence") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "No" },
        { role: "assistant", content: "Delete operation cancelled." },
      ]);

      scrollChatToBottom();
      return;
    }

    if (pendingAssistantAction === "submit_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "No" },
        { role: "assistant", content: "Submit operation cancelled." },
      ]);

      scrollChatToBottom();
    }
  };

  const monitoringImprovementStatus: StepStatus = useMemo(() => {
    const backendStatus = systemStatus?.sections?.monitoring_improvement?.status ?? systemStatus?.sections?.action_plan_implementation?.status;
    if (backendStatus === "Completed") return "Completed";
    if (backendStatus === "In Progress") return "In Progress";
    if (monitoringImprovementControls.length > 0) return "In Progress";
    return "Not Started";
  }, [systemStatus, monitoringImprovementControls.length]);

  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const monitoringImprovementCount = monitoringImprovementControls.length;

  const orgBoundaryItems = useMemo(() => {
    return dashboardRaw?.scope_context_section2?.bullets ?? [];
  }, [dashboardRaw]);

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

  const refreshMonitoringImprovementControls = async () => {
    try {
      const doc = await apiGetMonitoringImprovementInventory(YEAR);
      setMonitoringImprovementControls(Array.isArray(doc?.cves) ? doc.cves : []);
    } catch {
      setMonitoringImprovementControls([]);
    }
  };

  const createMonitoringImprovementTableConfirmed = async () => {
    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is using Qwen reasoning and RAG technology to create the Monitoring / Improverment table",
      },
    ]);

    try {
      const data = await apiCreateMonitoringImprovementInventory(YEAR);

      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content: data.message || "Monitoring and Improvement table initialized successfully.",
        };
        return updated;
      });
    } catch (e) {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while creating Monitoring and Improvement table.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleDeleteSelectedMonitoringImprovementRow = async () => {
    if (selectedControlIndex === null || !monitoringImprovementControls[selectedControlIndex]) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Please select a row first.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const selectedControl = monitoringImprovementControls[selectedControlIndex];
    setSending(true);

    try {
      const data = await apiDeleteMonitoringImprovementControl(YEAR, selectedControl.CVE);

      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);
      setSelectedControlIndex(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message || `Selected row ${selectedControl.CVE} was deleted successfully.`,
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            e instanceof Error ? e.message : "Backend error while deleting the selected row.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleResetMonitoringImprovement = async () => {
    setSending(true);

    try {
      const data = await apiResetMonitoringImprovement(YEAR, true);
      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Monitoring and Improvement table has been reset.",
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while resetting Monitoring and Improvement.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

    
  const handleSubmitMonitoringImprovement = async () => {
    setSending(true);

    try {
      const data = await apiSubmitMonitoringImprovement(YEAR, true);
      setMonitoringImprovementControls(Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "The Monitoring / Improvement table data submitted succcesfully.",
        },
      ]);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while submitting Monitoring and Improvement.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleStatusChange = async (
    index: number,
    value: MonitoringImprovementCVE["implementation_status"]
  ) => {
    const control = monitoringImprovementControls[index];
    if (!control) return;

    try {
      const data = await apiUpdateMonitoringImprovementStatus(
        YEAR,
        control.CVE,
        value
      );
      setMonitoringImprovementControls(
        Array.isArray(data?.inventory?.cves) ? data.inventory.cves : []
      );
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: e instanceof Error ? e.message : "Failed to update control status.",
        },
      ]);
      scrollChatToBottom();
     }
  };

  const onSend = async () => {
    const trimmed = input.trim();

    if (!trimmed) return;

    setMessages((prev) => [...prev, { role: "user", content: trimmed }]);
    setInput("");

    if (trimmed === "/commands") {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Available commands:\n" +
            "/create     → Create new Monitoring / Improvement table\n" +
            "/recommend  → Recommend the monitoring action for all vulnerabilities \n" +
            "/delete     → Delete the selected evidence\n" +
            "/add        → Add an evidence for selected host\n" +
            "/evidence   → Add evidence with auto-filled responsible, resources, and description\n" + 
            "/evidence-all → Add one auto-filled evidence item for every host row in the table\n" +
            "/edit       → Edit evidence for selected host\n" +
            "/submit     → Submit the table\n" +
            "/commands   → Display available commands\n" +
            "/help       → Explain this section",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    if (trimmed === "/create") {
      setPendingAssistantAction("recreate_annex");
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Existing Monitoring and Improvement table will be replaced. Are your sure?",
          confirmAction: "recreate_annex",
        },
      ]);
      scrollChatToBottom();
      return;
    }
      
    if (trimmed === "/add") {
      await handleOpenAddEvidence(false);
      return;
    }
    
    if (trimmed === "/evidence") {
      await handleOpenAddEvidence(true);
      return;
    }

    if (trimmed === "/evidence-all") {
      await handleAddEvidenceAll();
      return;
    }
 
    if (trimmed === "/edit") {
      handleOpenEditEvidence();
      return;
    }

    if (trimmed === "/delete") {
      if (
        selectedControlIndex === null ||
        selectedHostIndex === null ||
        selectedEvidenceIndex === null
      ) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "Please select an evidence row first.",
          },
        ]);
        scrollChatToBottom();
        return;
      }

      setPendingAssistantAction("delete_evidence");
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Are you sure you want to delete the selected evidence?",
          confirmAction: "delete_evidence",
        },
      ]);
      scrollChatToBottom();
      return;
    }
   
    if (trimmed === "/recommend") {
      await handleRecommendForSelectedRow();
      return;
    }

    if (trimmed === "/submit") {
      setPendingAssistantAction("submit_annex");
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Are you sure you want to submit the Monitoring and Improvement table?",
          confirmAction: "submit_annex",
        },
      ]);
      scrollChatToBottom();
      return;
    }
      
    if (trimmed === "/help") {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Monitoring & Improvement\n\n" +
            "What this page is about:\n" +
            "This stage checks whether implemented controls are actually operating as intended and whether they are reducing risk over time. It records monitoring evidence, recommended monitoring actions, implementation status, and improvement follow-up.\n\n" +
            "Why it is important:\n" +
            "ISO 27001 expects the ISMS to be monitored, measured, and continually improved. A control is not complete just because it was implemented once. This page shows whether the control remains effective in the live environment.\n\n" +
            "Its place in the ISO 27001 lifecycle:\n" +
            "This comes after Action Plan / Implementation and before final reporting. Implementation proves that controls were deployed. Monitoring & Improvement proves that they are working, sustained, and improved when weaknesses are found.",
        },
      ]);
      scrollChatToBottom();
      return;
    } 
      
    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content: `Unknown command: ${trimmed}\nUse /commands to see available commands.`,
      },
    ]);
    scrollChatToBottom();
  };

    
  useEffect(() => {
    void refreshMonitoringImprovementControls();
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
    scrollChatToBottom("smooth");
  }, [messages, sending]);

  const monitoringImprovementTable = (
    <div className="mt-4 overflow-x-auto">
      <div className="min-w-full rounded-2xl border border-white/10 bg-[#0a0f1d] ring-1 ring-white/10">
        <div className="grid grid-cols-[2fr_3fr_2.5fr] bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">
          <div className="px-3 py-3">CVE</div>
          <div className="px-3 py-3">Vulnerability</div>
          <div className="px-3 py-3">Implementation Status</div>
        </div>

        {monitoringImprovementControls.length === 0 ? (
          <div className="px-4 py-6 text-sm text-slate-400">
            No Monitoring and Improvement records available.
          </div>
        ) : (
          monitoringImprovementControls.map((c, idx) => (
            <React.Fragment key={c.CVE}>
              <div
                onClick={() => {
                  setSelectedControlIndex((prev) => (prev === idx ? null : idx));
                  setSelectedHostIndex(null);
                  setSelectedEvidenceIndex(null);
                }}
                className={`grid cursor-pointer grid-cols-[2fr_3fr_2.5fr] border-t border-white/10 text-sm transition ${
                  selectedControlIndex === idx
                    ? "bg-indigo-500/15 ring-1 ring-inset ring-indigo-400/40 text-white"
                    : "text-slate-200 hover:bg-white/5"
                }`}
              >
                <div className="px-3 py-3">{c.CVE || "-"}</div>
                <div className="px-3 py-3">{c.vulnerability || "-"}</div>
                <div className="px-3 py-3">
                  <select
                    onClick={(e) => e.stopPropagation()}
                    value={c.implementation_status}
                    onChange={(e) =>
                      handleStatusChange(
                        idx,
                        e.target.value as MonitoringImprovementCVE["implementation_status"]
                      )
                    }
                    className="w-full rounded-lg border border-white/10 bg-[#0f172a] px-2 py-1 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="">-- Select --</option>
                    <option value="Not Implemented">Not Implemented</option>
                    <option value="Planned">Planned</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Implemented">Implemented</option>
                    <option value="Not Applicable">Not Applicable</option>
                  </select>
                </div>
              </div>
                {selectedControlIndex === idx ? (
                  <div className="border-t border-white/10 bg-[#0b1220] px-4 py-4">
                    <div className="overflow-x-auto rounded-xl border border-white/10">
                        <div className="grid grid-cols-[1.2fr_2fr] bg-[#1a2540] text-xs font-semibold uppercase tracking-wide text-slate-300">
                          <div className="px-3 py-3">Justification</div>
                          <div className="px-3 py-3">Recommended Action</div>
                        </div>
                
                      <div className="grid grid-cols-[1.2fr_2fr] border-t border-white/10 text-sm text-slate-200">
                        <div className="px-3 py-3 whitespace-pre-line">
                          {c.justification?.trim() ? c.justification : "-"}
                        </div>
                        <div className="px-3 py-3 whitespace-pre-line">
                          {c.recommended_action?.trim() ? c.recommended_action : "-"}
                        </div>
                      </div>
                
                      <div className="grid grid-cols-[20%_25%_25%_30%] border-t border-white/10 bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">  
                        <div className="px-3 py-3">Host Name</div>
                        <div className="px-3 py-3">Role</div>
                        <div className="px-3 py-3">Location</div>
                        <div className="px-3 py-3">Risk</div>
                      </div>
                
                        {!c.hosts || c.hosts.length === 0 ? (
                          <div className="px-3 py-4 text-sm text-slate-400">
                            No host records available.
                          </div>
                        ) : (
                          c.hosts.map((host, hostIdx) => {
                            const validEvidence = getMeaningfulEvidence(host.evidence);
                            return (
                              <React.Fragment key={`${c.CVE}-${hostIdx}`}>
                                <div
                                  onClick={() => {
                                    setSelectedHostIndex((prev) => (prev === hostIdx ? null : hostIdx));
                                    setSelectedEvidenceIndex(null);
                                  }}
                                  className={`grid cursor-pointer grid-cols-[15%_30%_55%] border-t border-white/10 text-sm transition ${
                                    selectedHostIndex === hostIdx
                                      ? "bg-sky-500/15 ring-1 ring-inset ring-sky-400/40 text-white"
                                      : "text-slate-200 hover:bg-white/5"
                                  }`}
                                >
                                  <div className="px-3 py-3">{host.hostname || "-"}</div>
                                  <div className="px-3 py-3">{host.role || "-"}</div>
                                  <div className="px-3 py-3">{host["CIA rating"] || "-"}</div>
                                </div>
                        
                                {validEvidence.length > 0 && (
                                  <>
                                    <div className="grid grid-cols-[16%_16%_14%_24%_30%] border-t border-white/10 bg-[#101a31] text-xs font-semibold uppercase tracking-wide text-slate-300">
                                      <div className="px-3 py-3">Responsible</div>
                                      <div className="px-3 py-3">Resources</div>
                                      <div className="px-3 py-3">Date</div>
                                      <div className="px-3 py-3">URL/PATH</div>
                                      <div className="px-3 py-3">Desc</div>
                                    </div>
                        
                                    {validEvidence.map(({ ev, rawIndex }, evIdx) => (
                                      <div
                                        key={`${c.CVE}-${hostIdx}-evidence-${evIdx}`}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setSelectedControlIndex(idx);
                                          setSelectedHostIndex(hostIdx);
                                          setSelectedEvidenceIndex(rawIndex);
                                        }}
                                        className={`grid cursor-pointer grid-cols-[16%_16%_14%_24%_30%] border-t border-white/10 text-sm transition ${
                                          selectedControlIndex === idx &&
                                          selectedHostIndex === hostIdx &&
                                          selectedEvidenceIndex === rawIndex
                                            ? "bg-emerald-500/15 ring-1 ring-inset ring-emerald-400/40 text-white"
                                            : "text-slate-200 hover:bg-white/5"
                                        }`}
                                      >
                                        <div className="px-3 py-3">{ev.responsible || "-"}</div>
                                        <div className="px-3 py-3">{ev.resources || "-"}</div>
                                        <div className="px-3 py-3">{ev.date || "-"}</div>
                                        <div className="px-3 py-3 break-all">{ev.url || "-"}</div>
                                        <div className="px-3 py-3">{ev.desc || "-"}</div>
                                      </div>
                                    ))}
                                  </>
                                )}
                              </React.Fragment>
                            );
                          })
                        )}
                    </div>
                  </div>
                ) : null}
            </React.Fragment>
          ))
        )}
      </div>
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
              const isCommandMessage = !isUser && isCommandHelpMessage(m.content);

              return (
                <div key={idx} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm ring-1 ${
                      isCommandMessage ? "font-mono text-[13px] leading-6" : ""
                    } ${
                      isUser
                        ? "max-w-[90%] bg-indigo-600/30 text-slate-50 ring-indigo-500/30"
                        : "w-full bg-white/5 text-slate-200 ring-white/10"
                    }`}
                  >
                    {isCommandMessage ? (
                      <CommandHelpMessage content={m.content} />
                    ) : (
                      <div>{m.content}</div>
                    )}

                    {!isUser &&
                    m.confirmAction === pendingAssistantAction &&
                    (m.confirmAction === "recreate_annex" ||
                      m.confirmAction === "reset_annex" ||
                      m.confirmAction === "delete_annex_row" ||
                      m.confirmAction === "delete_evidence" ||
                      m.confirmAction === "submit_annex") ? (
                      <div className="mt-3 flex gap-2">
                        <button
                          onClick={() => void handleAssistantConfirmYes()}
                          className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
                        >
                          Yes
                        </button>

                        <button
                          onClick={handleAssistantConfirmNo}
                          className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-white/10"
                        >
                          No
                        </button>
                      </div>
                    ) : null}
                  </div>
                </div>
              );
            })}

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
          Command mode: /create /recommend /delete /add /evidence /evidence-all /edit /submit /commands /help
        </div>
      </div>
    </ShellCard>
  );

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      <Modal open={popupOpen} title="Message" text={popupText} onClose={closePopup} />
      <ConfirmModal
        open={confirmRecreateOpen}
        title="Confirm Recreate"
        text="Existing Monitoring and Improvement table data will be replaced. Are you sure?"
        onYes={handleConfirmRecreateYes}
        onNo={handleConfirmRecreateNo}
      />
      <AddEvidenceModal
        open={addEvidenceModalOpen}
        hostLabel={selectedHostLabel}
        form={evidenceForm}
        onChange={handleEvidenceFormChange}
        onCancel={() => {
          setAddEvidenceModalOpen(false);
          resetEvidenceForm();
        }}
        onSubmit={handleSubmitAddEvidence}
        submitting={sending}
      />
      <EditEvidenceModal
        open={editEvidenceModalOpen}
        hostLabel={selectedHostLabel}
        form={editEvidenceForm}
        onChange={handleEditEvidenceFormChange}
        onCancel={() => {
          setEditEvidenceModalOpen(false);
          resetEditEvidenceForm();
        }}
        onSubmit={handleSubmitEditEvidence}
        submitting={sending}
      />
      <ConfirmModal
        open={confirmDeleteEvidenceOpen}
        title="Confirm Delete"
        text="Selected evidence will be deleted, Are you sure?"
        onYes={() => {
          setConfirmDeleteEvidenceOpen(false);
          void handleDeleteSelectedEvidence();
        }}
        onNo={() => {
          setConfirmDeleteEvidenceOpen(false);
        }}
      />
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
                Monitoring and Improvement
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
                    <span className="text-sm text-slate-300">({monitoringImprovementCount} controls)</span>
                    <StepStatusBadge status={monitoringImprovementStatus} />
                  </div>
                </div>
              </div>
            </ShellCard>

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

            <ShellCard className="flex min-h-[420px] flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">Monitoring and Improvement</div>
              {monitoringImprovementTable}
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

            <div className="p-4 space-y-2">
              <button
                onClick={() => (window.location.hash = "#/performance")}
                className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              >
                Performance Dashboard
              </button>
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
              Monitoring and Improvement
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

                  <span className="text-sm text-slate-300">- ({monitoringImprovementCount} CVEs)</span>

                  <StepStatusBadge status={monitoringImprovementStatus} />
                </div>
              </div>
            </div>
          </ShellCard>
        </div>

        <div className="col-[4] row-[2] p-3 pl-2 pb-0">
          <div className="flex h-14 items-center justify-end">
            <button
              onClick={() => {
                if (hasAnyMonitoringImprovementStatus) {
                  setConfirmRecreateOpen(true);
                } else {
                  void createMonitoringImprovementTableConfirmed();
                }
              }}
              className="h-full rounded-xl bg-indigo-600/90 px-4 text-sm font-semibold text-white hover:bg-indigo-600"
            >
              + Create New Monitoring / Improvement Table
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

        <div className="col-[3] row-[4/6] min-h-0 p-3 pr-2 pt-0">
          <ShellCard className="flex h-full min-h-0 flex-col p-5">
            <div className="shrink-0 text-lg font-semibold">Monitoring and Improvement</div>
            {monitoringImprovementTable}
            <AddEvidenceModal
              open={addEvidenceModalOpen}
              hostLabel={selectedHostLabel}
              form={evidenceForm}
              onChange={handleEvidenceFormChange}
              onCancel={() => {
                setAddEvidenceModalOpen(false);
                resetEvidenceForm();
              }}
              onSubmit={handleSubmitAddEvidence}
              submitting={sending}
            />
          </ShellCard>

        </div>

        <div className="col-[4] row-[3/6] min-h-0 p-3 pl-2 pt-0">{assistantPanel}</div>
      </div>
    </div>
  );
}
