import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Plus,
  Send,
} from "lucide-react";

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  confirmAction?: "recreate_annex" | "reset_annex" | "delete_annex_row" | "submit_annex";
};

type AnnexControl = {
  control_id: string;
  control_name: string;
  applicable: boolean;
  implementation_status:
    | ""
    | "Not Implemented"
    | "Planned"
    | "In Progress"
    | "Implemented"
    | "Not Applicable";
  justification: string;
  related_risks: string[];
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

type AnnexRecommendItem = {
  control_id: string;
  control_name: string;
  related_cves?: string[];
  justification?: string;
};

type AnnexRecommendResponse = {
  success?: boolean;
  message?: string;
  recommendations?: AnnexRecommendItem[];
};

type AnnexAddResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
};

type AnnexInventoryResponse = {
  controls?: AnnexControl[];
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
};

type AnnexSubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: AnnexInventoryResponse;
  requires_confirmation?: boolean;
};

type AnnexInfoResponse = {
  success?: boolean;
  message?: string;
  control?: {
    control_id?: string;
    control_name?: string;
    domain?: string;
    concern?: string;
    justification?: string;
  } | null;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function apiGetJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
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

async function apiGetRecommendedControlInfo(
  year: number,
  control_id: string
): Promise<AnnexInfoResponse> {
  return apiPostJSONBody<AnnexInfoResponse>("/api/annex-a-soa/info", {
    year,
    control_id,
  });
}

async function apiAddAnnexControl(
  year: number,
  control_id: string
): Promise<AnnexAddResponse> {
  return apiPostJSONBody<AnnexAddResponse>("/api/annex-a-soa/add", {
    year,
    control_id,
  });
}

async function apiRecommendAnnexControls(
  year: number
): Promise<AnnexRecommendResponse> {
  return apiPostJSONBody<AnnexRecommendResponse>("/api/annex-a-soa/recommend", {
    year,
  });
}

async function apiDeleteAnnexControl(
  year: number,
  control_id: string
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/annex-a-soa/delete", {
    year,
    control_id,
  });
}

async function apiGetAnnexInventory(year: number): Promise<AnnexInventoryResponse> {
  return apiGetJSON<AnnexInventoryResponse>(
    `/api/annex-a-soa/inventory?year=${encodeURIComponent(String(year))}`
  );
}

async function apiCreateAnnexInventory(year: number, force = false): Promise<AnnexCreateResponse> {
  return apiPostJSONBody<AnnexCreateResponse>("/api/annex-a-soa/create", {
    year,
    force,
  });
}

async function apiUpdateAnnexStatus(
  year: number,
  control_id: string,
  implementation_status: AnnexControl["implementation_status"]
): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/annex-a-soa/update-status", {
    year,
    control_id,
    implementation_status,
  });
}

async function apiResetAnnex(year: number, confirm = false): Promise<AnnexUpdateResponse> {
  return apiPostJSONBody<AnnexUpdateResponse>("/api/annex-a-soa/reset", {
    year,
    confirm,
  });
}

async function apiSubmitAnnex(year: number, confirm = false): Promise<AnnexSubmitResponse> {
  return apiPostJSONBody<AnnexSubmitResponse>("/api/annex-a-soa/submit", {
    year,
    confirm,
  });
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>("/api/system/status");
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

export default function AnnexASoA() {
  const YEAR = 2026;
    
  const [confirmRecreateOpen, setConfirmRecreateOpen] = useState(false);

  const [recommendedControls, setRecommendedControls] = useState<AnnexRecommendItem[]>([]);
  const [assistantMode, setAssistantMode] = useState<
    null | "awaiting_add_control_id" | "awaiting_info_control_id"
  >(null);
    
  const [selectedStep, setSelectedStep] = useState<number>(7);
  const [selectedControlIndex, setSelectedControlIndex] = useState<number | null>(null);

  const [controls, setControls] = useState<AnnexControl[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [popupOpen, setPopupOpen] = useState(false);
  const [popupText, setPopupText] = useState("");

  const [pendingAssistantAction, setPendingAssistantAction] = useState<
    null | "recreate_annex" | "reset_annex" | "delete_annex_row" | "submit_annex"
  >(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Annex A & SoA — Command Mode\n\n" +
        "Available commands:\n" +
        "/create    → Initialize a new Annex A & SoA table\n" +
        "/reset     → Reset all implementation status values\n" +
        "/delete    → Delete the selected row\n" +
        "/recommend → Recommend missing controls not already in the table\n" +
        "/add       → Add a control from the recommendation list\n" +
        "/info      → Show information about a control\n" +
        "/submit    → Finalize and lock the table\n" +
        "/help      → Provide an overview of this section\n" +
        "/commands  → Display available commands",
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
      { step: 9, name: "Monitoring & Improvement", href: "#/" },
      { step: 10, name: "Final Deliverables", href: "#/" },
    ],
    []
  );


  const handleShowRecommendedControlInfo = async (controlId: string) => {
    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is using RAG over ISO 27001:2022 controls and Llama3 reasoning to generate control information.",
      },
    ]);

    try {
      const data = await apiGetRecommendedControlInfo(YEAR, controlId);
      const control = data?.control;

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            "Control Information\n\n" +
            `Control ID: ${control?.control_id || controlId}\n` +
            `Control Name: ${control?.control_name || "NA"}\n` +
            `Domain: ${control?.domain || "NA"}\n` +
            `Concern: ${control?.concern || "NA"}\n\n` +  
            `Justification: ${control?.justification || "NA"}`
        };
        return updated;
      });

      setAssistantMode(null);
    } catch (e) {
      setMessages((prev) => {
        const updated = [...prev];
         updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while generating control information.",
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

  const hasAnyImplementationStatus = controls.some(
    (c) => (c.implementation_status ?? "").trim() !== ""
  );

  const handleStartInfoCommand = () => {
    if (!Array.isArray(recommendedControls) || recommendedControls.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Recommendation list is empty. Run /recommend first, then use /info.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    setAssistantMode("awaiting_info_control_id");

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Enter control id from the recommendation list to show control information.\n\nAvailable control ids:\n" +
          recommendedControls.map((item) => item.control_id).join(", "),
      },
    ]);

    scrollChatToBottom();
  };
    
  const handleAssistantConfirmYes = async () => {
    if (pendingAssistantAction === "recreate_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "Yes" },
      ]);

      await createAnnexTableConfirmed();
      return;
    }

    if (pendingAssistantAction === "reset_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "Yes" },
      ]);

      await handleResetAnnex();
      return;
    }

    if (pendingAssistantAction === "delete_annex_row") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "Yes" },
      ]);

      await handleDeleteSelectedRow();
      return;
    }

    if (pendingAssistantAction === "submit_annex") {
      setPendingAssistantAction(null);

      setMessages((prev) => [
        ...prev,
        { role: "user", content: "Yes" },
      ]);

      await handleSubmitAnnex();
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

  const annexStatus: StepStatus = useMemo(() => {
    const backendStatus = systemStatus?.sections?.annex_a_soa?.status;
    if (backendStatus === "Completed") return "Completed";
    if (backendStatus === "Blocked") return "Blocked";
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

  const refreshAnnexControls = async () => {
    try {
      const doc = await apiGetAnnexInventory(YEAR);
      setControls(Array.isArray(doc?.controls) ? doc.controls : []);
    } catch {
      setControls([]);
    }
  };

  const createAnnexTableConfirmed  = async () => {
    setSending(true);

    // ✅ ADD THIS BLOCK HERE
    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is using Llama3 reasoning and RAG technology to find most accurate controls",
      },
    ]);

    try {
      const data = await apiCreateAnnexInventory(YEAR, true);

      setControls(
        Array.isArray(data?.inventory?.controls)
          ? data.inventory.controls
          : []
      );

      // ✅ OPTIONAL: replace last message instead of adding new one
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            data.message ||
            "Annex A & SoA table initialized successfully.",
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
              : "Backend error while creating Annex A & SoA table.",
        };
        return updated;
      });

    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleCreateAnnexTable = async () => {
    if (controls.length > 0) {
      setConfirmRecreateOpen(true);   // 👉 modal only
      return;
    }

    await createAnnexTableConfirmed();
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
      const data = await apiDeleteAnnexControl(YEAR, selectedControl.control_id);

      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);
      setSelectedControlIndex(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message || `Selected row ${selectedControl.control_id} was deleted successfully.`,
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
             : "Backend error while deleting the selected row.",
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
      const data = await apiResetAnnex(YEAR, true);
      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Annex A & SoA table has been reset.",
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
              : "Backend error while resetting Annex A & SoA.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleRecommendControls = async () => {
    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is running the recommendation pipeline and checking which recommended controls do not already exist in the table.",
      },
    ]);

    try {
      const data = await apiRecommendAnnexControls(YEAR);

      const backendRecommendations = Array.isArray(data?.recommendations)
        ? data.recommendations
        : [];

      const existingControlIds = new Set(
        controls.map((c) => (c.control_id || "").trim().toLowerCase())
      );

      const missingControls = backendRecommendations.filter(
        (item) =>
          !existingControlIds.has((item.control_id || "").trim().toLowerCase())
      );

      // IMPORTANT: always persist the filtered list here
      setRecommendedControls(missingControls);

      const message =
        missingControls.length === 0
          ? (data?.message ||
            "No additional recommended controls were found outside the current table.")
          : "Recommended controls not currently in the table:\n\n" +
            missingControls
              .map((item) => `${item.control_id} - ${item.control_name}`)
              .join("\n");

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content: message,
        };
        return updated;
      });
    } catch (e) {
      setRecommendedControls([]);

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while generating recommended controls.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleStartAddCommand = () => {
    if (!Array.isArray(recommendedControls) || recommendedControls.length === 0) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Recommendation list is empty. Run /recommend first, then use /add.",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    setAssistantMode("awaiting_add_control_id");

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Enter control id from the recommendation list.\n\nAvailable control ids:\n" +
          recommendedControls.map((item) => item.control_id).join(", "),
      },
    ]);

    scrollChatToBottom();
  };

  const handleAddControlToTable = async (controlId: string) => {
    setSending(true);

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content:
          "Please wait, while system is adding the selected control to the table using Llama3 reasoning.",
      },
    ]);

    try {
      const data = await apiAddAnnexControl(YEAR, controlId);

      setControls(
        Array.isArray(data?.inventory?.controls)
          ? data.inventory.controls
          : []
      );

      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            data?.message || `Control ${controlId} was added successfully.`,
        };
        return updated;
      });

      setAssistantMode(null);
    } catch (e) {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: "assistant",
          content:
            e instanceof Error
              ? e.message
              : "Backend error while adding the selected control.",
        };
        return updated;
      });
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleSubmitAnnex = async () => {
    setSending(true);

    try {
      const data = await apiSubmitAnnex(YEAR, true);
      setControls(Array.isArray(data?.inventory?.controls) ? data.inventory.controls : []);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || "Annex A & SoA finalized.",
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
              : "Backend error while submitting Annex A & SoA.",
        },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleStatusChange = async (
    index: number,
    value: AnnexControl["implementation_status"]
  ) => {
    const control = controls[index];
    if (!control) return;

    try {
      const data = await apiUpdateAnnexStatus(YEAR, control.control_id, value);
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
    const text = input.trim();
    if (!text || sending) return;

    setMessages((prev) => [...prev, { role: "user", content: text }]);
    setInput("");

    if (text.toLowerCase() === "/create") {
      if (controls.length > 0) {
        setPendingAssistantAction("recreate_annex");
    
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "The table will be recreated, are you sure?",
            confirmAction: "recreate_annex",
          },
        ]);
    
        scrollChatToBottom();
        return;
      }
    
      await createAnnexTableConfirmed();
      return;
    }

    if (assistantMode === "awaiting_info_control_id") {
      const selectedId = text.trim().toLowerCase();
    
      const selectedRecommendation = recommendedControls.find(
        (item) => (item.control_id || "").trim().toLowerCase() === selectedId
      );
    
      if (!selectedRecommendation) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "Invalid control id. Please choose a control id only from the current recommendation list.",
          },
        ]);
        scrollChatToBottom();
        return;
      }
    
      setAssistantMode(null);
      await handleShowRecommendedControlInfo(selectedRecommendation.control_id);
      return;
    }

      
    if (assistantMode === "awaiting_add_control_id") {
      const selectedId = text.trim().toLowerCase();
    
      const selectedRecommendation = recommendedControls.find(
        (item) => (item.control_id || "").trim().toLowerCase() === selectedId
      );
    
      if (!selectedRecommendation) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "Invalid control id. Please choose a control id only from the current recommendation list.",
          },
        ]);
        scrollChatToBottom();
        return;
      }
    
      setAssistantMode(null);
      await handleAddControlToTable(selectedRecommendation.control_id);
      return;
    }
      
    if (text.toLowerCase() === "/reset") {
      if (hasAnyImplementationStatus) {
        setPendingAssistantAction("reset_annex");
    
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "The implementation status will be reset. Are you sure?",
            confirmAction: "reset_annex",
          },
        ]);
    
        scrollChatToBottom();
        return;
      }
    
      await handleResetAnnex();
      return;
    }

    if (text.toLowerCase() === "/delete") {
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
    
      setPendingAssistantAction("delete_annex_row");
    
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `The selected row (${selectedControl.control_id}) will be deleted. Are you sure?`,
          confirmAction: "delete_annex_row",
        },
      ]);
    
      scrollChatToBottom();
      return;
    }

    if (text.toLowerCase() === "/recommend") {
      await handleRecommendControls();
      return;
    }

    if (text.toLowerCase() === "/add") {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `recommendation count = ${recommendedControls.length}`,
        },
      ]);
    
      handleStartAddCommand();
      return;
    }

    if (text.toLowerCase() === "/info") {
      handleStartInfoCommand();
      return;
    }
      
    if (text.toLowerCase() === "/submit") {
      setPendingAssistantAction("submit_annex");
    
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "The Annex A & SoA results will be finalized and locked. Are you sure?",
          confirmAction: "submit_annex",
        },
      ]);
    
      scrollChatToBottom();
      return;
    }

    if (text.toLowerCase() === "/help") {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "This section creates the Annex A & SoA table from RiskEvaluationTreatment.json.\n\n" +
            "The table is empty by default.\n\n" +
            "When you use /create or click the Create New Annex A & SoA Table button, " +
            "the backend reads RiskEvaluationTreatment.json and extracts only records where:\n" +
            'evaluation = "Treat"\n' +
            'treatment = "Mitigate"\n\n' +
            "Those records are then used to build the Annex A & SoA control table.\n\n" +
            "When you use /recommend, the system shows recommended controls that do not already exist in the current table.\n\n" +
            "When you use /add, the system asks for a control id from the recommendation list, then adds that control to the table.",
        },
      ]);
      scrollChatToBottom();
      return;
    }
      
    if (text.toLowerCase() === "/commands") {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Annex A & SoA — Command Mode\n\n" +
            "Available commands:\n" +
            "/create: Initialize a new Annex A & SoA table\n" +
            "/reset: Reset all implementation status values\n" +
            "/delete: Delete the selected row\n" +
            "/recommend: Recommend missing controls not already in the table\n" +
            "/add: Add a control from the recommendation list\n" +
            "/info: Show information about a control\n" +
            "/submit: Finalize and lock the table\n" +
            "/help: Provide an overview of this section\n" +
            "/commands: Display available commands",
        },
      ]);
      scrollChatToBottom();
      return;
    }

    setMessages((prev) => [
      ...prev,
      {
        role: "assistant",
        content: "Unknown command. Type /commands to see the available operations.",
      },
    ]);
    scrollChatToBottom();
  };

  useEffect(() => {
    void refreshAnnexControls();
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

  const annexTable = (
    <div className="mt-4 overflow-x-auto">
      <div className="min-w-full rounded-2xl border border-white/10 bg-[#0a0f1d] ring-1 ring-white/10">
        <div className="grid grid-cols-[2fr_2.5fr_2.7fr_3.25fr_2fr] bg-[#16213a] text-xs font-semibold uppercase tracking-wide text-slate-300">
          <div className="px-3 py-3">Control</div>
          <div className="px-3 py-3">Control Name</div>
          <div className="px-3 py-3">Implementation Status</div>
          <div className="px-3 py-3">Justification</div>
          <div className="px-3 py-3">Risks</div>
        </div>

        {controls.length === 0 ? (
          <div className="px-4 py-6 text-sm text-slate-400">
            No Annex A / SoA records available.
          </div>
        ) : (
          controls.map((c, idx) => (
            <div
              key={c.control_id}
              onClick={() => setSelectedControlIndex(idx)}
              className={`grid cursor-pointer grid-cols-[2fr_2.5fr_2.7fr_3.25fr_2fr] border-t border-white/10 text-sm transition ${
                selectedControlIndex === idx
                  ? "bg-indigo-500/15 ring-1 ring-inset ring-indigo-400/40 text-white"
                  : "text-slate-200 hover:bg-white/5"
              }`}
            >
              <div className="px-3 py-3">{c.control_id}</div>
              <div className="px-3 py-3">{c.control_name}</div>

              <div className="px-3 py-3">
                <select
                  onClick={(e) => e.stopPropagation()}
                  value={c.implementation_status}
                  onChange={(e) =>
                    handleStatusChange(
                      idx,
                      e.target.value as AnnexControl["implementation_status"]
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

              <div className="px-3 py-3">{c.justification}</div>
              <div className="px-3 py-3">{c.related_risks.join(", ")}</div>
            </div>
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
                    <div>{m.content}</div>

                        {!isUser &&
                        m.confirmAction === pendingAssistantAction &&
                        (
                          m.confirmAction === "recreate_annex" ||
                          m.confirmAction === "reset_annex" ||
                          m.confirmAction === "delete_annex_row" ||
                          m.confirmAction === "submit_annex"
                        ) ? (                      <div className="mt-3 flex gap-2">
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
          Command mode: /create /reset /delete /recommend /add /info /submit /help /commands
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
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Annex A &amp; SoA</h1>
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
                    <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                      <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                      {annexStatus}
                    </span>
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

            <div className="flex justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={() => void handleCreateAnnexTable()}
                disabled={sending}
              >
                <Plus className="h-4 w-4" />
                Create New AnnexA & SoA Table
              </button>
            </div>

            <ShellCard className="flex min-h-[420px] flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">Annex A & Statement of Applicability</div>
              {annexTable}
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
              Annex A &amp; SoA
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

                  <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                    {annexStatus}
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
              onClick={() => void handleCreateAnnexTable()}
              disabled={sending}
            >
              <Plus className="h-4 w-4" />
              Create New AnnexA & SoA Table
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
            <div className="shrink-0 text-lg font-semibold">Annex A & Statement of Applicability</div>
            {annexTable}
          </ShellCard>
        </div>

        <div className="col-[4] row-[3/6] min-h-0 p-3 pl-2 pt-0">{assistantPanel}</div>
      </div>
    </div>
  );
}