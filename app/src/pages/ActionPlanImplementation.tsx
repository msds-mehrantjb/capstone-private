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

type ActionPlanControl = {
  control_id?: string;
  control: string;
  control_name: string;
  implementation_status:
    | ""
    | "Not Implemented"
    | "Planned"
    | "In Progress"
    | "Implemented"
    | "Not Applicable";
  justification?: string;
  treatment_action?: string;
  hosts?: ActionPlanHost[];
};

type ActionPlanEvidenceForm = {
  responsible: string;
  date: string;
  resources: string;
  url: string;
  desc: string;
};

type ActionPlanEvidence = {
  evidence_id?: string;
  responsible?: string;
  resources?: string;
  date?: string;
  url?: string;
  desc?: string;
};

type ActionPlanHost = {
  hostname?: string;
  role?: string;
  vulnerability_name?: string;
  evidence?: ActionPlanEvidence[];
};

function hasMeaningfulEvidence(ev: ActionPlanEvidence | null | undefined): boolean {
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
  evidence: ActionPlanEvidence[] | null | undefined
): Array<{ ev: ActionPlanEvidence; rawIndex: number }> {
  if (!Array.isArray(evidence)) return [];

  return evidence
    .map((ev, rawIndex) => ({ ev, rawIndex }))
    .filter(({ ev }) => hasMeaningfulEvidence(ev));
}

function getTodayDateInputValue(): string {
  return new Date().toISOString().slice(0, 10);
}

function formatActionPlanControlLabel(control: ActionPlanControl): string {
  const controlId = (control.control || control.control_id || "Unknown Control").trim();
  const controlName = (control.control_name || "").trim();
  return controlName ? `${controlId} (${controlName})` : controlId;
}

function previewMissingItems(items: string[], limit = 8): string {
  const preview = items.slice(0, limit).join(", ");
  const remaining = items.length - limit;
  return remaining > 0 ? `${preview}, and ${remaining} more` : preview;
}

function getActionPlanSubmitBlockMessage(controls: ActionPlanControl[]): string | null {
  if (!Array.isArray(controls) || controls.length === 0) {
    return "The Action Plan / Implementation table is empty.";
  }

  const missingTreatment = controls
    .filter((control) => !(control.treatment_action || "").trim())
    .map(formatActionPlanControlLabel);

  if (missingTreatment.length > 0) {
    return (
      "Please add a treatment action for every control before submitting the Action Plan / " +
      `Implementation table. Missing treatment action: ${previewMissingItems(missingTreatment)}`
    );
  }

  const missingEvidence = controls.flatMap((control) => {
    const controlId = (control.control || control.control_id || "Unknown Control").trim();
    if (!Array.isArray(control.hosts)) return [];

    return control.hosts
      .filter((host) => getMeaningfulEvidence(host.evidence).length === 0)
      .map((host) => `${controlId} / ${(host.hostname || "Unknown Host").trim()}`);
  });

  if (missingEvidence.length > 0) {
    return (
      "Please add at least one evidence item for every host before submitting the Action Plan / " +
      `Implementation table. Missing evidence: ${previewMissingItems(missingEvidence)}`
    );
  }

  return null;
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

type AnnexInventoryResponse = {
  controls?: ActionPlanControl[];
};

type AnnexCreateResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
};

type AnnexUpdateResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
  evidence_id?: string;
  guide_id?: string;
  guide_key?: string;
  guide_deleted?: boolean;
};

type AnnexSubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
  requires_confirmation?: boolean;
};

type AddEvidenceResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
  evidence_id?: string;
  guide_id?: string;
  guide_key?: string;
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
  inventory?: AnnexInventoryResponse;
};

  type EditEvidenceForm = {
    responsible: string;
    date: string;
    resources: string;
    url: string;
    desc: string;
  };


async function apiGetEvidenceDefaults(
  year: number,
  control_id: string,
  hostname: string,
  vulnerability_name: string
): Promise<EvidenceDefaultsResponse> {
  return apiPostJSONBody<EvidenceDefaultsResponse>(
    "/api/action-plan-implementation/evidence-defaults",
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
    "/api/action-plan-implementation/add-evidence",
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
    "/api/action-plan-implementation/edit-evidence",
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
    "/api/action-plan-implementation/delete-evidence",
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

  const res = await fetch(`${API_BASE}/api/action-plan-implementation/upload-evidence`, {
    method: "POST",
    body: formData,
  });

  const data = await res.json();
  return data.path;
}

async function apiDeleteActionPlanControl(
  year: number,
  control_id: string
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/action-plan-implementation/delete", {
    year,
    control_id,
  });
}

async function apiGetActionPlanInventory(year: number): Promise<AnnexInventoryResponse> {
  return apiGetJSON<AnnexInventoryResponse>(
    `/api/action-plan-implementation/inventory?year=${encodeURIComponent(String(year))}`
  );
}

async function apiCreateActionPlanInventory(year: number): Promise<AnnexCreateResponse> {
  return apiPostJSONBody<AnnexCreateResponse>("/api/action-plan-implementation/create", {
    year,
  });
}

async function apiUpdateActionPlanStatus(
  year: number,
  control_id: string,
  implementation_status: ActionPlanControl["implementation_status"]
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/action-plan-implementation/update-status", {
    year,
    control_id,
    implementation_status,
  });
}

async function apiResetActionPlan(year: number, confirm = false): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/action-plan-implementation/reset", {
    year,
    confirm,
  });
}

async function apiSubmitActionPlan(year: number, confirm = false): Promise<AnnexSubmitResponse> {
  return apiPostJSONBody<AnnexSubmitResponse>("/api/action-plan-implementation/submit", {
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

type TreatmentRecommendResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
  control?: ActionPlanControl;
};

async function apiRecommendTreatmentAction(
  year: number,
  control_id: string
): Promise<TreatmentRecommendResponse> {
  return apiPostJSONBody<TreatmentRecommendResponse>(
    "/api/action-plan-implementation/recommend-treatment",
    {
      year,
      control_id,
    }
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
  form: ActionPlanEvidenceForm;
  onChange: (field: keyof ActionPlanEvidenceForm, value: string) => void;
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

export default function ActionPlanImplentation() {
  const YEAR = 2026;
  const ANNEX_SOA_REQUIRED_MESSAGE = "You need to submit the Annex A & SoA table first.";

  const [confirmRecreateOpen, setConfirmRecreateOpen] = useState(false);

  const [confirmDeleteEvidenceOpen, setConfirmDeleteEvidenceOpen] = useState(false);
    
  const [selectedStep, setSelectedStep] = useState<number>(8);
  const [selectedControlIndex, setSelectedControlIndex] = useState<number | null>(null);

  const [selectedHostIndex, setSelectedHostIndex] = useState<number | null>(null);
  const [selectedEvidenceIndex, setSelectedEvidenceIndex] = useState<number | null>(null);
  const [controls, setControls] = useState<ActionPlanControl[]>([]);

  // Reset when data refreshes
  useEffect(() => {
    setSelectedEvidenceIndex(null);
  }, [controls]);

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
  const [popupText, setPopupText] = useState("");
  const emptyActionPlanPopupShownRef = useRef(false);

  const [pendingAssistantAction, setPendingAssistantAction] = useState<
    null | "recreate_annex" | "reset_annex" | "delete_annex_row" | "delete_evidence" | "submit_annex"
  >(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Action Plan / Implementation — Command Mode\n\n" +
        "Available commands:\n" +
        "/treatment  → Recommend the treatment action for selected row in table\n" +
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
  const [evidenceForm, setEvidenceForm] = useState<ActionPlanEvidenceForm>({
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

    const control = controls[selectedControlIndex];
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
        control.control,
        host.hostname,
        host.vulnerability_name || "",
        selectedEvidenceIndex
      );

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);
      setSelectedEvidenceIndex(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            "Selected evidence and its linked implementation guide were deleted successfully.",
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


  const buildAutoEvidenceForm = (
    control: ActionPlanControl,
    host: ActionPlanHost
  ): ActionPlanEvidenceForm => {
    const controlId = (control.control_id || control.control || "").trim();
    const controlName = (control.control_name || "").trim();
    const treatmentAction = (control.treatment_action || "").trim();

    const hostname = (host.hostname || "").trim();
    const role = (host.role || "").trim();
    const vulnerability = (host.vulnerability_name || "").trim();

    const responsibleByRole = (() => {
      const roleL = role.toLowerCase();

      if (
        roleL.includes("domain controller") ||
        roleL.includes("server") ||
        roleL.includes("dns") ||
        roleL.includes("dhcp") ||
        roleL.includes("database") ||
        roleL.includes("web")
      ) {
        return `System Administrator + ISMS Auditor Team`;
      }

      if (
        roleL.includes("workstation") ||
        roleL.includes("client") ||
        roleL.includes("endpoint") ||
        roleL.includes("user")
      ) {
        return `Endpoint Administrator + ISMS Auditor Team`;
      }

      if (
        roleL.includes("firewall") ||
        roleL.includes("router") ||
        roleL.includes("switch") ||
        roleL.includes("network")
      ) {
        return `Network Administrator + ISMS Auditor Team`;
      }

      if (
        roleL.includes("security") ||
        roleL.includes("siem") ||
        roleL.includes("soc") ||
        roleL.includes("defender")
      ) {
        return `Security Team + ISMS Auditor Team`;
      }

      return `Asset Responsible Team + ISMS Auditor Team`;
    })();

    const briefDesc = (() => {
      if (treatmentAction) {
        const firstLine = treatmentAction
          .split("\n")
          .map((x) => x.trim())
          .find((x) => x && x !== "Recommended treatment actions:" && x !== "-");

        const cleaned = (firstLine || treatmentAction)
          .replace(/^[-•]\s*/, "")
          .trim();

        return cleaned
          ? `Evidence for ${hostname} under control ${controlId}${controlName ? ` (${controlName})` : ""}: ${cleaned}.`
          : `Evidence for ${hostname} under control ${controlId}${controlName ? ` (${controlName})` : ""}.`;
      }

      if (vulnerability) {
        return `Evidence for ${hostname} under control ${controlId}${controlName ? ` (${controlName})` : ""} related to ${vulnerability}.`;
      }

      return `Evidence for ${hostname} under control ${controlId}${controlName ? ` (${controlName})` : ""}.`;
    })();

    return {
      responsible: responsibleByRole,
      resources: [
        hostname ? `Host: ${hostname}` : "",
        role ? `Role: ${role}` : "",
      ]
        .filter(Boolean)
        .join(" | "),
      date: "",
      url: "",
      desc: briefDesc,
    };
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

  const selectedControl =
    selectedControlIndex !== null ? controls[selectedControlIndex] : null;

  const selectedHost =
    selectedControl &&
    selectedHostIndex !== null &&
    Array.isArray(selectedControl.hosts) &&
    selectedControl.hosts[selectedHostIndex]
      ? selectedControl.hosts[selectedHostIndex]
      : null;

  const selectedEvidence =
    selectedHost &&
    selectedEvidenceIndex !== null &&
    Array.isArray(selectedHost.evidence) &&
    selectedHost.evidence[selectedEvidenceIndex]
      ? selectedHost.evidence[selectedEvidenceIndex]
      : null;
    
  const selectedHostLabel = selectedHost?.hostname?.trim() || "selected host";
 
  const handleOpenAddEvidence = async (autoFill: boolean) => {
    if (!selectedControl) {
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

    if (!autoFill) {
      resetEvidenceForm();
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            `Evidence form opened for host - ${selectedHostLabel}\n` +
            `Fill the evidence fields, then submit the form.`,
        },
      ]);

      setAddEvidenceModalOpen(true);
      scrollChatToBottom();
      return;
    }

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content: `Preparing evidence defaults for host ${selectedHostLabel}...`,
      },
    ]);

    try {
      setSending(true);

      const data = await apiGetEvidenceDefaults(
        YEAR,
        selectedControl.control,
        selectedHost.hostname || "",
        selectedHost.vulnerability_name || ""
      );

      if (data?.success === false) {
        throw new Error(data.message || "Failed to prepare evidence fields.");
      }

      const fallbackForm = buildAutoEvidenceForm(selectedControl, selectedHost);
      setEvidenceForm({
        responsible: data?.evidence?.responsible || fallbackForm.responsible,
        resources: data?.evidence?.resources || fallbackForm.resources,
        date: data?.evidence?.date || "",
        url: data?.evidence?.url || "",
        desc: data?.evidence?.desc || fallbackForm.desc,
      });

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            data.message ||
            `Evidence fields prepared for host ${selectedHostLabel}.`,
        };
        return updated;
      });

      setAddEvidenceModalOpen(true);
    } catch (e) {
      const fallbackForm = buildAutoEvidenceForm(selectedControl, selectedHost);
      setEvidenceForm(fallbackForm);

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            (e instanceof Error ? e.message : "Failed to prepare evidence fields.") +
            " The form was opened with local fallback defaults.",
        };
        return updated;
      });

      setAddEvidenceModalOpen(true);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };
    
  const handleEvidenceFormChange = (
    field: keyof ActionPlanEvidenceForm,
    value: string
  ) => {
    setEvidenceForm((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleSubmitAddEvidence = async () => {
    if (!selectedControl || !selectedHost) {
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
        selectedControl.control,
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

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Evidence added for host ${selectedHostLabel} and the linked implementation guide was generated.`,
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
    if (controls.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "No Action Plan / Implementation rows are available.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const pendingRows = controls.flatMap((control) => {
      const controlId = (control.control || control.control_id || "").trim();
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
          "Please wait while the system generates one evidence item for every host under every control.",
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
            content: `Generating evidence ${index + 1} of ${pendingRows.length} for ${row.hostname} under control ${row.controlId}...`,
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

          if (Array.isArray(data?.inventory?.controls)) {
            setControls(data.inventory.controls);
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
          failedItems.length > 0 ? ` Failed rows: ${failedItems.slice(0, 5).join(", ")}${failedItems.length > 5 ? ", ..." : ""}` : "";
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


  const handleTreatmentForSelectedControl = async () => {
    if (selectedControlIndex === null) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Please select a control first.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    const control = controls[selectedControlIndex];

    if (!control?.control) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Selected control row is invalid.",
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
          `Please wait, while system is using RAG over ISO 27001:2022 controls and ${"Qwen3.8 27B"} reasoning to generate treatment action for selected control ${control.control}.`,
      },
    ]);

    try {
      const data = await apiRecommendTreatmentAction(YEAR, control.control);

      const refreshedControls = Array.isArray(data?.inventory?.controls)
        ? data.inventory.controls
        : [];

      setControls(refreshedControls);

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            data?.message ||
            `Treatment action was generated and saved for selected control ${control.control}.`,
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
              : "Backend error while generating treatment action for selected row.",
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
    await createAnnexTableConfirmed();
  };

  const handleConfirmRecreateNo = () => {
    setConfirmRecreateOpen(false);
  };

  const handleAssistantConfirmYes = async () => {
    if (pendingAssistantAction === "recreate_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await createAnnexTableConfirmed();
      return;
    }

    if (pendingAssistantAction === "reset_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleResetAnnex();
      return;
    }

    if (pendingAssistantAction === "delete_annex_row") {
      setPendingAssistantAction(null);

      setMessages((prev) => [...prev, { role: "user", content: "Yes" }]);
      await handleDeleteSelectedRow();
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
      await handleSubmitAnnex();
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
    if (!selectedControl) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Please select a control first." },
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
    if (!selectedControl || !selectedHost || selectedEvidenceIndex === null) {
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
        selectedControl.control,
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

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Evidence updated for host ${selectedHostLabel} and the linked implementation guide was regenerated.`,
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

  const actionPlanStatus: StepStatus = useMemo(() => {
    const backendStatus = systemStatus?.sections?.action_plan_implementation?.status;
    if (backendStatus === "Completed") return "Completed";
    if (backendStatus === "In Progress") return "In Progress";
    if (controls.length > 0) return "In Progress";
    return "Not Started";
  }, [systemStatus, controls.length]);

  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const controlCount = controls.length;

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

  const refreshActionPlanControls = async (showEmptyTablePopup = false) => {
    try {
      const doc = await apiGetActionPlanInventory(YEAR);
      const nextControls = Array.isArray(doc?.controls) ? doc.controls : [];
      setControls(nextControls);

      if (
        showEmptyTablePopup &&
        nextControls.length === 0 &&
        !emptyActionPlanPopupShownRef.current
      ) {
        emptyActionPlanPopupShownRef.current = true;
        setPopupText(ANNEX_SOA_REQUIRED_MESSAGE);
        setPopupOpen(true);
      }
    } catch {
      setControls([]);
      if (showEmptyTablePopup && !emptyActionPlanPopupShownRef.current) {
        emptyActionPlanPopupShownRef.current = true;
        setPopupText(ANNEX_SOA_REQUIRED_MESSAGE);
        setPopupOpen(true);
      }
    }
  };

  const createAnnexTableConfirmed = async () => {
    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is using Qwen3.8 27B reasoning and RAG technology to find most accurate controls",
      },
    ]);

    try {
      const data = await apiCreateActionPlanInventory(YEAR);

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content: data.message || "Action Plan / Implementation table initialized successfully.",
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
              : "Backend error while creating Action Plan / Implementation table.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleDeleteSelectedRow = async () => {
    if (selectedControlIndex === null || !controls[selectedControlIndex]) {
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

    const selectedControl = controls[selectedControlIndex];
    setSending(true);

    try {
      const data = await apiDeleteActionPlanControl(YEAR, selectedControl.control);

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);
      setSelectedControlIndex(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message || `Selected row ${selectedControl.control} was deleted successfully.`,
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

  const handleResetAnnex = async () => {
    setSending(true);

    try {
      const data = await apiResetActionPlan(YEAR, true);
      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Action Plan / Implementation table has been reset.",
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
              : "Backend error while resetting Action Plan / Implementation.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleSubmitAnnex = async () => {
    const blockMessage = getActionPlanSubmitBlockMessage(controls);
    if (blockMessage) {
      setMessages((prev) => [...prev, { role: "assistant", content: blockMessage }]);
      scrollChatToBottom();
      return;
    }

    setSending(true);

    try {
      const data = await apiSubmitActionPlan(YEAR, true);

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      try {
        const sys = await apiGetSystemStatus();
        setSystemStatus(sys);
      } catch {
        // keep previous state if refresh fails
      }

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message || "The Action Plan / Implementation table data submitted succcesfully.",
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
              : "Backend error while submitting Action Plan / Implementation.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };
    
  const handleStatusChange = async (
    index: number,
    value: ActionPlanControl["implementation_status"]
  ) => {
    const control = controls[index];
    if (!control) return;

    try {
      const data = await apiUpdateActionPlanStatus(YEAR, control.control, value);
      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);
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
            "/treatment  → Recommend the treatment action for selected row in table\n" +
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

    const command = input.trim().toLowerCase();
    
    if (command === "/add") {
      await handleOpenAddEvidence(false);
      return;
    }

    if (command === "/evidence") {
      await handleOpenAddEvidence(true);
      return;
    }

    if (command === "/evidence-all") {
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
   
    if (command === "/treatment") {
      await handleTreatmentForSelectedControl();
      return;
    }

    if (trimmed === "/submit") {
      const blockMessage = getActionPlanSubmitBlockMessage(controls);
      if (blockMessage) {
        setMessages((prev) => [...prev, { role: "assistant", content: blockMessage }]);
        scrollChatToBottom();
        return;
      }

      setPendingAssistantAction("submit_annex");
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Are you sure you want to submit the Action Plan / Implementation table?",
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
            "Action Plan / Implementation\n\n" +
            "What this page is about:\n" +
            "This stage turns the selected Annex A controls into operational work. It tracks treatment actions, implementation status, host-level evidence, and the practical steps required to put the chosen controls into effect.\n\n" +
            "Why it is important:\n" +
            "ISO 27001 requires more than selecting controls on paper. The organization has to implement them, prove they were implemented, and keep a traceable link back to the risks they were meant to address. This page is where that execution happens.\n\n" +
            "Its place in the ISO 27001 lifecycle:\n" +
            "This comes after Annex A & SoA and before Monitoring & Improvement. The SoA says which controls apply. Action Plan / Implementation is where those controls are executed and evidenced.",
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
    void refreshActionPlanControls(true);
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

  const actionPlanTable = (
    <div className="mt-4 overflow-x-auto">
      <div className="min-w-full rounded-2xl border border-white/10 bg-[#0a0f1d] ring-1 ring-white/10">
        <div className="grid grid-cols-[2fr_3fr_2.5fr] bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">
          <div className="px-3 py-3">Control</div>
          <div className="px-3 py-3">Control Name</div>
          <div className="px-3 py-3">Implementation Status</div>
        </div>

        {controls.length === 0 ? (
          <div className="px-4 py-6 text-sm text-slate-400">
            No Action Plan / Implementation records available.
          </div>
        ) : (
          controls.map((c, idx) => (
            <React.Fragment key={c.control}>
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
                <div className="px-3 py-3">{c.control}</div>
                <div className="px-3 py-3">{c.control_name}</div>

                <div className="px-3 py-3">
                  <select
                    onClick={(e) => e.stopPropagation()}
                    value={c.implementation_status}
                    onChange={(e) =>
                      handleStatusChange(
                        idx,
                        e.target.value as ActionPlanControl["implementation_status"]
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
                        <div className="px-3 py-3">Treatment Action</div>
                      </div>
                
                      <div className="grid grid-cols-[1.2fr_2fr] border-t border-white/10 text-sm text-slate-200">
                        <div className="px-3 py-3">
                          {c.justification?.trim() ? c.justification : "-"}
                        </div>
                        <div className="px-3 py-3 whitespace-pre-wrap">
                          {c.treatment_action?.trim() ? c.treatment_action : "-"}
                        </div>
                      </div>
                
                      <div className="grid grid-cols-[15%_30%_55%] border-t border-white/10 bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">
                        <div className="px-3 py-3">Host Name</div>
                        <div className="px-3 py-3">Role</div>
                        <div className="px-3 py-3">Vulnerability</div>
                      </div>
                
                        {!c.hosts || c.hosts.length === 0 ? (
                          <div className="px-3 py-4 text-sm text-slate-400">
                            No host records available.
                          </div>
                        ) : (
                          c.hosts.map((host, hostIdx) => {
                            const validEvidence = getMeaningfulEvidence(host.evidence);
                            return (
                              <React.Fragment key={`${c.control}-${hostIdx}`}>
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
                                  <div className="px-3 py-3">{host.vulnerability_name || "-"}</div>
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
                                        key={`${c.control}-${hostIdx}-evidence-${evIdx}`}
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
          Command mode: /treatment /delete /add /evidence /evidence-all /edit /submit /commands /help
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
        text="The table will be recreated, are you sure?"
        onYes={() => void handleConfirmRecreateYes()}
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
                Action Plan / Implementation
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
                    <span className="text-sm text-slate-300">({controlCount} controls)</span>
                    <StepStatusBadge status={actionPlanStatus} />
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
              <div className="shrink-0 text-lg font-semibold">Action Plan / Implementation</div>
              {actionPlanTable}
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
              Action Plan / Implementation
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

                  <span className="text-sm text-slate-300">- ({controlCount} controls)</span>

                  <StepStatusBadge status={actionPlanStatus} />
                </div>
              </div>
            </div>
          </ShellCard>
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
            <div className="shrink-0 text-lg font-semibold">Action Plan / Implementation</div>
            {actionPlanTable}
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
