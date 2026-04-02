import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Plus,
  Server,
  Monitor,
  Database,
  CircleCheck,
  CircleOff,
  Send,
  HelpCircle,
} from "lucide-react";

type RoleOptionsResponse = {
  success?: boolean;
  server_roles?: string[];
  workstation_roles?: string[];
  server_kb_path?: string;
  workstation_kb_path?: string;
};

type SubmitCleanupResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  removed_unknown?: number;
  removed_inactive?: number;
};

type EditRoleResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  hostname?: string;
  role?: string;
};

type HostType = "server" | "workstation" | "unknown";

type Kpi = {
  title: string;
  value: string;
  icon: React.ReactNode;
  accent: "amber" | "emerald" | "rose" | "slate";
};

type AssetRow = {
  hostname: string;
  role: string;
  originalRole: string;
  location: string;
  os: string;
  cia: "Critical" | "High" | "Medium" | "Unscanned";
  status: "Active" | "Not Active" | "Unknown";
  hostType: HostType;
  ipAddress?: string;
  openPorts?: Array<number | string>;
  runningServices?: string[];
  installedSoftware?: string[];
  department?: string;
};

type ChatMessage = { role: "user" | "assistant"; content: string };

type StepStatus = "Blocked" | "Not Started" | "In Progress" | "Completed";

type SystemStatusDTO = {
  meta: { name: string; version: string };
  sections: Record<string, { status: StepStatus; scope_file_name?: string }>;
};

type ScopeDocDTO = {
  meta?: Record<string, any>;
  sections?: Array<{
    id?: string;
    title?: string;
    body?: string;
    bullets?: string[];
  }>;
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

type AssetInventoryWorkDTO = {
  meta?: any;
  network_mask?: string | null;
  subnets?: Array<{
    id?: string;
    subnet_mask?: string;
    location?: { name?: string; ip_range?: string };
    assets?: Array<{
      hostname?: string;
      role?: string;
      operating_system?: string;
      device_type?: string;
      location?: { name?: string; ip_address?: string };
      cia_rating?: { criticality?: string };
      status?: "Active" | "Not Active" | "Unknown";
      detail?: {
        technical_indicators?: {
          open_ports?: Array<number | string>;
          running_services?: string[];
          installed_software?: string[];
        };
        business_context?: {
          department?: string;
        };
      };
    }>;
  }>;
};

type DiscoveredSubnet = {
  id: string;
  label: string;
  host_count?: number;
};

type ExploreResponse = {
  success?: boolean;
  message?: string;
  subnets?: Array<{
    id?: string;
    label?: string;
    host_count?: number;
  }>;
};

type TrainModelResponse = {
  success?: boolean;
  message?: string;
  model_path?: string;
};

type AssessResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  subnet_id?: string;
  replaced?: boolean;
  host_count?: number;
};

type SetStatusResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  hostname?: string;
  status?: "Active" | "Not Active" | "Unknown";
};

type DeleteResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  hostname?: string;
};

type AssignRolesResponse = {
  success?: boolean;
  message?: string;
  kb_status?: "created" | "updated" | "up_to_date" | "error";
  rows_embedded?: number;
  inventory?: AssetInventoryWorkDTO;
  processed_hosts?: number;
  updated_hosts?: number;
};

type SubmitResponse = {
  success?: boolean;
  message?: string;
  inventory?: AssetInventoryWorkDTO;
  requires_confirmation?: boolean;
  unknown_count?: number;
  inactive_count?: number;
  invalid_active_count?: number;
  removed_unknown?: number;
  removed_inactive?: number;
  removed_invalid_active?: number;
  kept_records?: number;
  kept_valid?: number;
  rows_added?: {
    server_rows_added?: number;
    workstation_rows_added?: number;
    total_rows_added?: number;
  };
  train_result?: unknown;
  train_error?: string;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

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

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}${txt ? ` - ${txt}` : ""}`);
  }

  return (await res.json()) as T;
}

async function apiGetRoleOptions(): Promise<RoleOptionsResponse> {
  return apiGetJSON<RoleOptionsResponse>("/api/assets/role-options");
}

async function apiGetSystemStatus(): Promise<SystemStatusDTO> {
  return apiGetJSON<SystemStatusDTO>("/api/system/status");
}

async function apiGetDashboardRaw(year: number): Promise<DashboardRawDTO> {
  return apiGetJSON<DashboardRawDTO>(
    `/api/dashboard/summary?year=${encodeURIComponent(String(year))}`
  );
}

async function apiGetScopeFile(year: number, filename: string): Promise<ScopeDocDTO> {
  return apiGetJSON<ScopeDocDTO>(
    `/api/scope/file?year=${encodeURIComponent(String(year))}&filename=${encodeURIComponent(filename)}`
  );
}

async function apiGetAssetInventory(year: number): Promise<AssetInventoryWorkDTO> {
  return apiGetJSON<AssetInventoryWorkDTO>(
    `/api/assets/inventory?year=${encodeURIComponent(String(year))}`
  );
}

async function apiCreateBlankAssetInventory(
  year: number,
  force?: boolean
): Promise<AssetInventoryWorkDTO> {
  const qs = new URLSearchParams({ year: String(year) });
  if (force) qs.set("force", "true");
  return apiPostJSON<AssetInventoryWorkDTO>(`/api/assets/inventory/new?${qs.toString()}`);
}

function detectHostType(asset: {
  hostname?: string;
  role?: string;
  operating_system?: string;
  device_type?: string;
}): HostType {
  const hostname = (asset.hostname ?? "").toLowerCase();
  const role = (asset.role ?? "").toLowerCase();
  const os = (asset.operating_system ?? "").toLowerCase();
  const deviceType = (asset.device_type ?? "").toLowerCase();

  if (deviceType.includes("server")) return "server";
  if (deviceType.includes("workstation")) return "workstation";
  if (hostname.startsWith("srv-")) return "server";
  if (hostname.startsWith("ws-")) return "workstation";
  if (os.includes("windows server")) return "server";
  if (os.includes("windows 10") || os.includes("windows 11") || os.includes("workstation")) {
    return "workstation";
  }
  if (role.includes("server") || role.includes("domain controller")) return "server";

  return "unknown";
}

function flattenInventoryToRows(doc: AssetInventoryWorkDTO | null): AssetRow[] {
  const out: AssetRow[] = [];
  const subnets = doc?.subnets ?? [];

  for (const s of subnets) {
    const assets = s?.assets ?? [];

    for (const a of assets) {
      const backendRole = a?.role ?? "";
      const hostType = detectHostType(a);

      out.push({
        hostname: a?.hostname ?? "",
        role: backendRole,
        originalRole: backendRole,
        location: s?.location?.name ?? "",
        os: a?.operating_system ?? "",
        cia:
          a?.cia_rating?.criticality === "Critical"
            ? "Critical"
            : a?.cia_rating?.criticality === "High"
            ? "High"
            : a?.cia_rating?.criticality === "Medium"
            ? "Medium"
            : "Unscanned",
        status:
          a?.status === "Active"
            ? "Active"
            : a?.status === "Not Active"
            ? "Not Active"
            : "Unknown",
        hostType,
        ipAddress: a?.location?.ip_address ?? "",
        openPorts: a?.detail?.technical_indicators?.open_ports ?? [],
        runningServices: a?.detail?.technical_indicators?.running_services ?? [],
        installedSoftware: a?.detail?.technical_indicators?.installed_software ?? [],
        department: a?.detail?.business_context?.department ?? "",
      });
    }
  }

  return out;
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

function CiaPill({ value }: { value: AssetRow["cia"] }) {
  if (value === "Unscanned") return <span className="text-slate-400">-</span>;

  const map: Record<Exclude<AssetRow["cia"], "Unscanned">, string> = {
    Critical: "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25",
    High: "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/25",
    Medium: "bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/25",
  };

  return (
    <span className={`inline-flex items-center rounded-lg px-3 py-1 text-xs ${map[value]}`}>
      {value}
    </span>
  );
}

function StatusCell({ value }: { value: AssetRow["status"] }) {
  if (value === "Active") {
    return <CircleCheck className="h-5 w-5 text-emerald-300" title="Active" />;
  }

  if (value === "Not Active") {
    return <CircleOff className="h-5 w-5 text-slate-400" title="Inactive" />;
  }

  return <HelpCircle className="h-5 w-5 text-amber-300" title="Unknown" />;
}

export default function AssetInventoryCIA() {
  const YEAR = 2026;
  const [selectedStep, setSelectedStep] = useState<number>(2);

  const [pendingCommand, setPendingCommand] = useState<
    | null
    | "explore"
    | "assess"
    | "confirm-reassess"
    | "confirm-reset"
    | "confirm-submit"
    | "setstatus-host"
    | "setstatus-value"
    | "delete-host"
    | "confirm-delete"
    | "details-host"
  >(null);

  const [serverRoles, setServerRoles] = useState<string[]>([]);
  const [workstationRoles, setWorkstationRoles] = useState<string[]>([]);
  const [roleCatalogError, setRoleCatalogError] = useState<string | null>(null);

  const [discoveredSubnets, setDiscoveredSubnets] = useState<DiscoveredSubnet[]>([]);
  const [assessedSubnets, setAssessedSubnets] = useState<Record<string, boolean>>({});
  const [confirmSubnetId, setConfirmSubnetId] = useState<string | null>(null);
  const [pendingHostname, setPendingHostname] = useState<string | null>(null);

  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [dashboardRaw, setDashboardRaw] = useState<DashboardRawDTO | null>(null);
  const [scopeDoc, setScopeDoc] = useState<ScopeDocDTO | null>(null);
  const [scopeErr, setScopeErr] = useState<string | null>(null);

  const [rows, setRows] = useState<AssetRow[]>([]);

  const [popupOpen, setPopupOpen] = useState(false);
  const [popupText, setPopupText] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [confirmAction, setConfirmAction] = useState<null | "new-inventory" | "reset-inventory">(
    null
  );

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Asset Inventory & CIA — Command Mode\n\n" +
        "Available commands:\n" +
        "/explore     → Discover organizational subnets\n" +
        "/assess      → Scan a subnet and discover hosts\n" +
        "/setstatus   → Set host status (Active / Not Active / Unknown)\n" +
        "/assignroles → Detect server roles and assign CIA\n" +
        "/detail      → Show detailed host information\n" +
        "/train       → Train the ML role prediction model\n" +
        "/delete      → Remove a host from the table\n" +
        "/submit      → Submit Asset Inventory & CIA results\n" +
        "/reset       → Clear the inventory table\n" +
        "/help        → Explain this section\n" +
        "/commands    → Show all available commands\n" +
        "/exit        → Exit assess mode\n\n" +
        "Tip: Use /explore first, then /assess.",
    },
  ]);

  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement | null>(null);

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

  const backendAssetsCiaStatus = systemStatus?.sections?.assets_cia?.status;

  const assetsCiaStatus: StepStatus = useMemo(() => {
    if (backendAssetsCiaStatus === "Completed") return "Completed";
    if (backendAssetsCiaStatus === "Blocked") return "Blocked";
    if (backendAssetsCiaStatus === "In Progress") return "In Progress";
    if (rows.length > 0) return "In Progress";
    return "Not Started";
  }, [backendAssetsCiaStatus, rows.length]);

  const scopeFileName = systemStatus?.sections?.scope_context?.scope_file_name;
  const displayScopeName = dashboardRaw?.scope?.name ?? "NA";
  const assetCount = rows.length;

  const totalServers = useMemo(() => rows.filter((r) => r.hostType === "server").length, [rows]);

  const criticalAssets = useMemo(() => rows.filter((r) => r.cia === "Critical").length, [rows]);

  const ciaCoverage = useMemo(() => {
    if (rows.length === 0) return 0;
    const covered = rows.filter((r) => r.cia !== "Unscanned").length;
    return Math.round((covered / rows.length) * 100);
  }, [rows]);

  const manualOverrideCount = useMemo(
    () => rows.filter((r) => (r.role || "").trim() !== (r.originalRole || "").trim()).length,
    [rows]
  );

  const orgBoundaryItems = useMemo(() => {
    return dashboardRaw?.scope_context_section2?.bullets ?? [];
  }, [dashboardRaw]);

  const kpis: Kpi[] = useMemo(
    () => [
      {
        title: "Total Assets",
        value: String(assetCount),
        icon: <Database className="h-6 w-6" />,
        accent: "amber",
      },
      {
        title: "Total Servers",
        value: String(totalServers),
        icon: <Server className="h-6 w-6" />,
        accent: "emerald",
      },
      {
        title: "Critical Assets",
        value: String(criticalAssets),
        icon: <Monitor className="h-6 w-6" />,
        accent: "slate",
      },
      {
        title: "CIA Coverage",
        value: `${ciaCoverage}%`,
        icon: <CircleCheck className="h-6 w-6" />,
        accent: "rose",
      },
    ],
    [assetCount, totalServers, criticalAssets, ciaCoverage]
  );

  const showPopup = (text: string) => {
    setPopupText(text);
    setPopupOpen(true);
  };

  const closePopup = () => setPopupOpen(false);

  const openConfirm = (text: string, action: "new-inventory" | "reset-inventory") => {
    setConfirmText(text);
    setConfirmAction(action);
    setConfirmOpen(true);
  };

  const closeConfirm = () => {
    setConfirmOpen(false);
    setConfirmAction(null);
  };

  const scrollChatToBottom = (behavior: ScrollBehavior = "smooth") => {
    requestAnimationFrame(() => {
      chatBottomRef.current?.scrollIntoView({ behavior, block: "end" });
    });
  };

  const findRowByHostname = (hostname: string): AssetRow | null => {
    const normalized = hostname.trim().toLowerCase();
    if (!normalized) return null;
    return rows.find((r) => (r.hostname || "").trim().toLowerCase() === normalized) ?? null;
  };

  const getRoleOptionsForRow = (row: AssetRow): string[] => {
    const merged = new Set<string>();

    if (row.hostType === "server") {
      for (const role of serverRoles) merged.add(role);
    } else if (row.hostType === "workstation") {
      for (const role of workstationRoles) merged.add(role);
    }

    if (row.originalRole?.trim()) merged.add(row.originalRole.trim());
    if (row.role?.trim()) merged.add(row.role.trim());

    return Array.from(merged)
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b));
  };

  const formatList = (items?: Array<string | number>) => {
    if (!items || items.length === 0) return "NA";
    return items.map((x) => String(x)).join(", ");
  };

  const formatHostDetails = (row: AssetRow) => {
    return (
      `Host Details — ${row.hostname}\n\n` +
      `IP address: ${row.ipAddress?.trim() ? row.ipAddress : "NA"}\n` +
      `Open Ports: ${formatList(row.openPorts)}\n` +
      `Running Service(s): ${formatList(row.runningServices)}\n` +
      `Installed Software(s): ${formatList(row.installedSoftware)}\n` +
      `Department: ${row.department?.trim() ? row.department : "NA"}`
    );
  };

  const refreshInventoryRows = async () => {
    const doc = await apiGetAssetInventory(YEAR);
    setRows(flattenInventoryToRows(doc));
  };

  const executeSubmitInventory = async () => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<SubmitResponse>("/api/assets/submit", {
        year: YEAR,
        confirm: true,
      });

      if (data.requires_confirmation) {
        setPendingCommand("confirm-submit");
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              data.message ||
              "Submit still requires confirmation.",
          },
        ]);
        return;
      }

      if (data.inventory) {
        setRows(flattenInventoryToRows(data.inventory));
      } else {
        await refreshInventoryRows();
      }

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setPendingCommand(null);
      setPendingHostname(null);
      setConfirmSubnetId(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            "Submit completed successfully. Unknown and inactive hosts were removed. Remaining valid hosts were added to the training datasets and the model was retrained.",
        },
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Backend error while submitting the inventory.";
      setPendingCommand(null);
      setMessages((prev) => [...prev, { role: "assistant", content: msg }]);
    } finally {
      setSending(false);
      scrollChatToBottom();
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

  const handleRoleChange = async (hostname: string, nextRole: string) => {
    const previousRows = rows;

    setRows((prev) =>
      prev.map((row) => (row.hostname === hostname ? { ...row, role: nextRole } : row))
    );

    try {
      const data = await apiPostJSONBody<EditRoleResponse>("/api/assets/editrole", {
        year: YEAR,
        hostname,
        role: nextRole,
      });

      if (data.inventory) {
        setRows(flattenInventoryToRows(data.inventory));
      } else {
        await refreshInventoryRows();
      }
    } catch {
      setRows(previousRows);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Backend error while updating role for ${hostname}.`,
        },
      ]);
      scrollChatToBottom();
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const data = await apiGetRoleOptions();

        setServerRoles(Array.isArray(data.server_roles) ? data.server_roles : []);
        setWorkstationRoles(Array.isArray(data.workstation_roles) ? data.workstation_roles : []);

        if (
          !Array.isArray(data.server_roles) ||
          !Array.isArray(data.workstation_roles) ||
          data.server_roles.length === 0 ||
          data.workstation_roles.length === 0
        ) {
          setRoleCatalogError("Role options were loaded, but no valid roles were returned.");
          return;
        }

        setRoleCatalogError(null);
      } catch (e) {
        setServerRoles([]);
        setWorkstationRoles([]);
        setRoleCatalogError(e instanceof Error ? e.message : "Unable to load role catalogs.");
      }
    })();
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
    (async () => {
      try {
        if (!scopeFileName) {
          setScopeDoc(null);
          return;
        }
        const doc = await apiGetScopeFile(YEAR, scopeFileName);
        setScopeDoc(doc);
      } catch {
        setScopeDoc(null);
      }
    })();
  }, [scopeFileName]);

  useEffect(() => {
    (async () => {
      try {
        const doc = await apiGetAssetInventory(YEAR);
        setRows(flattenInventoryToRows(doc));

        const existingSubnetMap: Record<string, boolean> = {};
        for (const subnet of doc?.subnets ?? []) {
          const id = subnet?.id?.trim();
          if (id) existingSubnetMap[id] = true;
        }
        setAssessedSubnets(existingSubnetMap);
      } catch {
        setRows([]);
      }
    })();
  }, []);

  useEffect(() => {
    if (rows.length === 0) return;

    setSystemStatus((prev) => {
      if (!prev?.sections?.assets_cia) return prev;
      return {
        ...prev,
        sections: {
          ...prev.sections,
          assets_cia: {
            ...prev.sections.assets_cia,
            status: "In Progress",
          },
        },
      };
    });
  }, [rows.length]);

  useEffect(() => {
    scrollChatToBottom("smooth");
  }, [messages, sending, pendingCommand, discoveredSubnets, confirmSubnetId, pendingHostname]);

  const runAssessSubnet = async (subnetId: string) => {
    setSending(true);

    try {
      const res = await fetch(`${API_BASE}/api/assets/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ year: YEAR, subnet_id: subnetId }),
      });

      const data = (await res.json()) as AssessResponse;

      if (data.inventory) {
        setRows(flattenInventoryToRows(data.inventory));
      } else {
        const refreshed = await apiGetAssetInventory(YEAR);
        setRows(flattenInventoryToRows(refreshed));
      }

      const sys = await apiGetSystemStatus();
      setSystemStatus({
        ...sys,
        sections: {
          ...sys.sections,
          assets_cia: {
            ...sys.sections.assets_cia,
            status: "In Progress",
          },
        },
      });

      setAssessedSubnets((prev) => ({
        ...prev,
        [subnetId]: true,
      }));

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || `Subnet ${subnetId} assessed successfully.`,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while assessing the subnet." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleAssessSubnetClick = async (subnetId: string) => {
    if (assessedSubnets[subnetId]) {
      setConfirmSubnetId(subnetId);
      setPendingCommand("confirm-reassess");

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "You assessed this network once. If you assess it again I will replace them. Continue?",
        },
      ]);
      return;
    }

    await runAssessSubnet(subnetId);
  };

  const handleResetConfirmYes = async () => {
    setSending(true);

    try {
      await apiCreateBlankAssetInventory(YEAR, true);

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      const doc = await apiGetAssetInventory(YEAR);
      setRows(flattenInventoryToRows(doc));

      setDiscoveredSubnets([]);
      setAssessedSubnets({});
      setConfirmSubnetId(null);
      setPendingCommand(null);
      setPendingHostname(null);

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Inventory table has been cleared." },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while resetting the inventory table." },
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

  const handleSubmitConfirmNo = () => {
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Submit cancelled." }]);
    scrollChatToBottom();
  };

  const handleSetStatus = async (hostname: string, status: AssetRow["status"]) => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<SetStatusResponse>("/api/assets/setstatus", {
        year: YEAR,
        hostname,
        status,
      });

      if (data.inventory) {
        setRows(flattenInventoryToRows(data.inventory));
      } else {
        await refreshInventoryRows();
      }

      setPendingCommand(null);
      setPendingHostname(null);

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.message || `${hostname} status updated to ${status}.` },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while updating the host status." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleDeleteNo = () => {
    setPendingHostname(null);
    setPendingCommand(null);
    setMessages((prev) => [...prev, { role: "assistant", content: "Delete cancelled." }]);
    scrollChatToBottom();
  };

  const handleDeleteYes = async () => {
    if (!pendingHostname) return;

    setSending(true);

    try {
      const data = await apiPostJSONBody<DeleteResponse>("/api/assets/delete", {
        year: YEAR,
        hostname: pendingHostname,
      });

      const nextRows = data.inventory ? flattenInventoryToRows(data.inventory) : [];

      if (data.inventory) {
        setRows(nextRows);
      } else {
        await refreshInventoryRows();
      }

      const sys = await apiGetSystemStatus();
      setSystemStatus({
        ...sys,
        sections: {
          ...sys.sections,
          assets_cia: {
            ...sys.sections.assets_cia,
            status: nextRows.length === 0 ? "Not Started" : "In Progress",
          },
        },
      });

      const deletedHost = pendingHostname;
      setPendingHostname(null);
      setPendingCommand(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message || `${deletedHost} has been deleted from the table.`,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while deleting the host." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
  };

  const handleSubmitConfirmYes = async () => {
    setSending(true);

    try {
      const data = await apiPostJSONBody<SubmitCleanupResponse>("/api/assets/submit", {
        year: YEAR,
        confirm: true,
      });

      if (data.inventory) {
        setRows(flattenInventoryToRows(data.inventory));
      } else {
        await refreshInventoryRows();
      }

      const sys = await apiGetSystemStatus();
      setSystemStatus(sys);

      setPendingCommand(null);
      setPendingHostname(null);
      setConfirmSubnetId(null);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            data.message ||
            `Removed ${data.removed_unknown ?? 0} Unknown host(s) and ${data.removed_inactive ?? 0} Inactive host(s).`,
        },
      ]);
    } catch {
      setPendingCommand(null);
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Backend error while submitting the inventory." },
      ]);
    } finally {
      setSending(false);
      scrollChatToBottom();
    }
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
        setConfirmSubnetId(null);
        setPendingHostname(null);

        setMessages((prev) => [...prev, { role: "assistant", content: "Exited command mode." }]);
        return;
      }

      if (pendingCommand === "explore") {
        setPendingCommand(null);

        const res = await fetch(`${API_BASE}/api/assets/explore`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ year: YEAR, network_mask: text }),
        });

        const data = (await res.json()) as ExploreResponse;

        setDiscoveredSubnets(
          Array.isArray(data.subnets)
            ? data.subnets.map((s) => ({
                id: String(s.id ?? ""),
                label: String(s.label ?? s.id ?? ""),
                host_count: typeof s.host_count === "number" ? s.host_count : undefined,
              }))
            : []
        );

        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: data.message || "Explore completed." },
        ]);
        return;
      }

      if (pendingCommand === "setstatus-host") {
        const found = findRowByHostname(text);

        if (!found) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content:
                "Hostname not found. Please enter a valid hostname from the table, or type /exit.",
            },
          ]);
          return;
        }

        setPendingHostname(found.hostname);
        setPendingCommand("setstatus-value");

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: `Host found: ${found.hostname}\n\nCurrent status: ${found.status}\n\nSelect the new status.`,
          },
        ]);
        return;
      }

      if (pendingCommand === "setstatus-value") {
        const normalized = text.trim().toLowerCase();
        let mappedStatus: AssetRow["status"] | null = null;

        if (normalized === "active") mappedStatus = "Active";
        else if (normalized === "inactive" || normalized === "not active")
          mappedStatus = "Not Active";
        else if (normalized === "unknown") mappedStatus = "Unknown";

        if (!mappedStatus || !pendingHostname) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "Invalid status. Please choose Active, Inactive, or Unknown, or type /exit.",
            },
          ]);
          return;
        }

        await handleSetStatus(pendingHostname, mappedStatus);
        return;
      }

      if (pendingCommand === "delete-host") {
        const found = findRowByHostname(text);

        if (!found) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content:
                "Hostname not found. Please enter a valid hostname from the table, or type /exit.",
            },
          ]);
          return;
        }

        setPendingHostname(found.hostname);
        setPendingCommand("confirm-delete");

        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: `Are you sure you want to delete ${found.hostname}?` },
        ]);
        return;
      }

      if (pendingCommand === "details-host") {
        const found = findRowByHostname(text);

        if (!found) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content:
                "Hostname not found. Please enter a valid hostname from the table, or type /exit.",
            },
          ]);
          return;
        }

        setPendingCommand(null);
        setMessages((prev) => [...prev, { role: "assistant", content: formatHostDetails(found) }]);
        return;
      }

      if (text.toLowerCase() === "/train") {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "Training the ML role prediction model based on the latest datasets...",
          },
        ]);

        try {
          const data = await apiPostJSONBody<TrainModelResponse>("/api/assets/train", {
            year: YEAR,
          });

          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: data.message || "ML role prediction model is ready to use.",
            },
          ]);
        } catch {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "Backend error while training the ML role prediction model.",
            },
          ]);
        }
        return;
      }

      if (text.toLowerCase() === "/submit") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "The inventory table is empty. Please run /assess first.",
            },
          ]);
          return;
        }
    
        const unknownCount = rows.filter((r) => r.status === "Unknown").length;
        const inactiveCount = rows.filter((r) => r.status === "Not Active").length;
    
        setPendingCommand("confirm-submit");
    
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              `There are ${unknownCount} Unknown host(s) and ${inactiveCount} Inactive host(s).\n\n` +
              `They will be removed and will no longer exist in future operations.\n\n` +
              `Do you want to continue?`,
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
              "Asset Inventory & CIA\n\n" +
              "This section discovers network hosts, identifies their roles, and assigns CIA criticality ratings to build the organization's asset inventory.\n\n" +
              "Use /commands to see available operations.",
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
              "/explore     → Discover organizational subnets\n" +
              "/assess      → Scan a subnet and discover hosts\n" +
              "/setstatus   → Set host status (Active / Not Active / Unknown)\n" +
              "/assignroles → Detect server roles and assign CIA\n" +
              "/detail      → Show detailed host information\n" +
              "/train       → Train the ML role prediction model\n" +
              "/delete      → Remove a host from the table\n" +
              "/submit      → Submit Asset Inventory & CIA results\n" +
              "/reset       → Clear the inventory table\n" +
              "/help        → Explain this section\n" +
              "/commands    → Show all available commands\n" +
              "/exit        → Exit assess mode",
          },
        ]);
        return;
      }

      if (text.toLowerCase() === "/explore") {
        setPendingCommand("explore");
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Please enter the network address (IPv4)." },
        ]);
        return;
      }

      if (text.toLowerCase() === "/assess") {
        if (discoveredSubnets.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "No discovered subnets found. Please run /explore first." },
          ]);
          return;
        }

        setPendingCommand("assess");
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Select a subnet to assess, or click /exit to leave assess mode." },
        ]);
        return;
      }

      if (text.toLowerCase() === "/setstatus") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The inventory table is empty. Please run /assess first." },
          ]);
          return;
        }

        setPendingHostname(null);
        setPendingCommand("setstatus-host");
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Please enter the hostname that you want to update." },
        ]);
        return;
      }

      if (text.toLowerCase() === "/detail") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The inventory table is empty. Please run /assess first." },
          ]);
          return;
        }

        setPendingCommand("details-host");
        setMessages((prev) => [...prev, { role: "assistant", content: "Please enter the hostname." }]);
        return;
      }

      if (text.toLowerCase() === "/delete") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The inventory table is empty. There is nothing to delete." },
          ]);
          return;
        }

        setPendingHostname(null);
        setPendingCommand("delete-host");
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Please enter the hostname that you want to delete." },
        ]);
        return;
      }

      if (text.toLowerCase() === "/assignroles" || text.toLowerCase() === "/assignrole") {
        if (rows.length === 0) {
          setMessages((prev) => [
            ...prev,
            { role: "assistant", content: "The inventory table is empty. Please run /assess first." },
          ]);
          return;
        }

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "Checking knowledge base, detecting roles from indicators, running ML role prediction, and updating inventory table...",
          },
        ]);

        try {
          const data = await apiPostJSONBody<AssignRolesResponse>("/api/assets/assignroles", {
            year: YEAR,
          });

          if (data.inventory) {
            setRows(flattenInventoryToRows(data.inventory));
          } else {
            await refreshInventoryRows();
          }

          const sys = await apiGetSystemStatus();
          setSystemStatus({
            ...sys,
            sections: {
              ...sys.sections,
              assets_cia: {
                ...sys.sections.assets_cia,
                status: "In Progress",
              },
            },
          });

          let kbMessage = "";

          if (data.kb_status === "created") {
            kbMessage = "Knowledge base created successfully.";
            if (typeof data.rows_embedded === "number" && data.rows_embedded > 0) {
              kbMessage += ` Embedded ${data.rows_embedded} records into ChromaDB.`;
            }
          } else if (data.kb_status === "updated") {
            kbMessage = "Knowledge base updated successfully.";
            if (typeof data.rows_embedded === "number" && data.rows_embedded > 0) {
              kbMessage += ` Re-embedded ${data.rows_embedded} records into ChromaDB.`;
            }
          } else if (data.kb_status === "up_to_date") {
            kbMessage = "Knowledge base is already up to date.";
          }

          let roleMessage =
            data.message || `Role assignment completed. Processed ${data.processed_hosts ?? 0} host(s)`;

          if (!data.message && typeof data.updated_hosts === "number") {
            roleMessage += ` and updated ${data.updated_hosts} host(s)`;
          }

          if (kbMessage) roleMessage += `\n\n${kbMessage}`;
          if (!roleMessage.endsWith(".")) roleMessage += ".";

          setMessages((prev) => [...prev, { role: "assistant", content: roleMessage }]);
        } catch {
          setMessages((prev) => [
            ...prev,
            {
              role: "assistant",
              content: "Backend error while assigning roles and updating the inventory table.",
            },
          ]);
        }

        return;
      }

      if (text.toLowerCase() === "/reset") {
        setPendingCommand("confirm-reset");
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: "The content of the inventory table will be erased. Are you sure?",
          },
        ]);
        return;
      }

      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "(Mock) Command received. Backend agent execution will be connected later." },
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

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
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
                Asset Inventory & CIA
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
                    <span className="text-sm text-slate-300">({assetCount} assets)</span>
                    <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                      <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                      {assetsCiaStatus}
                    </span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button
                className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
                onClick={async () => {
                  if (assetsCiaStatus === "Blocked") {
                    showPopup("You should submit Scope & Context document first");
                    return;
                  }

                  if (assetsCiaStatus === "In Progress") {
                    openConfirm(
                      "You are in the middle of assess inventory operation.\n\nSelect Yes to start a new one.\nSelect No to return.",
                      "new-inventory"
                    );
                    return;
                  }

                  try {
                    if (assetsCiaStatus === "Not Started") {
                      openConfirm(
                        "A new Asset Inventory file will be created.\n\nDo you want to continue?",
                        "new-inventory"
                      );
                      return;
                    }

                    const doc = await apiGetAssetInventory(YEAR);
                    setRows(flattenInventoryToRows(doc));
                    setMessages((prev) => [
                      ...prev,
                      { role: "assistant", content: "(Loaded) AssetInventory.json" },
                    ]);
                  } catch (e) {
                    showPopup(e instanceof Error ? e.message : String(e));
                  }
                }}
              >
                <Plus className="h-4 w-4" />
                New Inventory Assessment
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

              {roleCatalogError ? (
                <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                  Role catalog load error: {roleCatalogError}
                </div>
              ) : null}

              {manualOverrideCount > 0 ? (
                <div className="mt-3 rounded-xl bg-sky-500/10 px-4 py-3 text-sm text-sky-200 ring-1 ring-sky-500/20">
                  Manual role overrides: {manualOverrideCount}
                </div>
              ) : null}
            </ShellCard>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {kpis.map((k) => (
                <KpiCard key={k.title} kpi={k} />
              ))}
            </div>

            <ShellCard className="flex min-h-[420px] flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">Asset Inventory</div>

              <div className="mt-4 min-h-0 flex-1 overflow-y-auto overflow-x-hidden rounded-xl ring-1 ring-white/10">
                <table className="w-full table-fixed text-left text-sm">
                  <thead className="sticky top-0 z-10 bg-[#0b1020]">
                    <tr className="text-slate-300">
                      <th className="w-[15%] px-3 py-3 font-medium">Hostname</th>
                      <th className="w-[23%] px-3 py-3 font-medium">Role</th>
                      <th className="w-[14%] px-3 py-3 font-medium">Location</th>
                      <th className="w-[24%] px-3 py-3 font-medium">Operating System</th>
                      <th className="w-[16%] px-3 py-3 font-medium">CIA Rating</th>
                      <th className="w-[8%] px-3 py-3 text-center font-medium">Status</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-white/5">
                    {rows.map((r, idx) => {
                      const isManualOverride =
                        (r.role || "").trim() !== (r.originalRole || "").trim();
                      const roleOptions = getRoleOptionsForRow(r);

                      return (
                        <tr key={`${r.hostname || "row"}-${idx}`} className="hover:bg-white/5">
                          <td className="break-words px-3 py-2 text-slate-100">{r.hostname || "-"}</td>

                          <td className="px-3 py-2 align-top">
                            <select
                              value={r.role}
                              onChange={(e) => handleRoleChange(r.hostname, e.target.value)}
                              className={[
                                "block w-full min-w-0",
                                "rounded-lg border bg-[#1a1f2e] px-2 py-1.5 text-sm outline-none",
                                isManualOverride
                                  ? "border-amber-500/50 text-amber-200 ring-1 ring-amber-500/30"
                                  : "border-white/10 text-slate-100 ring-1 ring-white/10",
                              ].join(" ")}
                              title={r.role || ""}
                            >
                              {roleOptions.length === 0 ? (
                                <option value={r.role}>{r.role || "-"}</option>
                              ) : (
                                roleOptions.map((roleName) => {
                                  const isBackendRole =
                                    roleName.trim() === (r.originalRole || "").trim();
                                  const isSelectedRole =
                                    roleName.trim() === (r.role || "").trim();

                                  return (
                                    <option
                                      key={roleName}
                                      value={roleName}
                                      style={{
                                        fontWeight: isBackendRole ? "700" : "400",
                                        color: isSelectedRole
                                          ? "#facc15"
                                          : isBackendRole
                                          ? "#22c55e"
                                          : "#ffffff",
                                        backgroundColor: "#0f172a",
                                      }}
                                    >
                                      {roleName}
                                    </option>
                                  );
                                })
                              )}
                            </select>
                          </td>

                          <td className="break-words px-3 py-2 text-slate-200">{r.location || "-"}</td>

                          <td className="break-words px-3 py-2 text-slate-200">
                            {r.os === "Unknown" || !r.os ? "-" : r.os}
                          </td>

                          <td className="px-3 py-2">
                            <div className="min-w-0">
                              <CiaPill value={r.cia} />
                            </div>
                          </td>

                          <td className="px-3 py-2 text-center">
                            <div className="flex justify-center">
                              <StatusCell value={r.status} />
                            </div>
                          </td>
                        </tr>
                      );
                    })}
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

                    {pendingCommand === "assess" && discoveredSubnets.length > 0 ? (
                      <div className="flex flex-wrap gap-2 pt-1">
                        {discoveredSubnets.map((s) => (
                          <button
                            key={s.id}
                            onClick={() => void handleAssessSubnetClick(s.id)}
                            className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                          >
                            {s.label}
                          </button>
                        ))}

                        <button
                          onClick={() => {
                            setPendingCommand(null);
                            setConfirmSubnetId(null);
                            setMessages((prev) => [
                              ...prev,
                              { role: "assistant", content: "Exited assess mode." },
                            ]);
                            scrollChatToBottom();
                          }}
                          className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                        >
                          /exit
                        </button>
                      </div>
                    ) : null}

                    {pendingCommand === "confirm-reassess" && confirmSubnetId ? (
                      <div className="flex flex-wrap gap-2 pt-1">
                        <button
                          onClick={async () => {
                            const subnetId = confirmSubnetId;
                            setConfirmSubnetId(null);
                            setPendingCommand("assess");
                            await runAssessSubnet(subnetId);
                          }}
                          className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                        >
                          Yes
                        </button>

                        <button
                          onClick={() => {
                            setConfirmSubnetId(null);
                            setPendingCommand("assess");
                            setMessages((prev) => [
                              ...prev,
                              {
                                role: "assistant",
                                content: "Reassess cancelled. Select another subnet or click /exit.",
                              },
                            ]);
                            scrollChatToBottom();
                          }}
                          className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                        >
                          No
                        </button>
                      </div>
                    ) : null}

                    {pendingCommand === "setstatus-value" && pendingHostname ? (
                      <div className="flex flex-wrap gap-2 pt-1">
                        <button
                          onClick={() => void handleSetStatus(pendingHostname, "Active")}
                          className="rounded-xl bg-emerald-600/20 px-3 py-2 text-sm text-emerald-100 ring-1 ring-emerald-500/30 hover:bg-emerald-600/30"
                        >
                          Active
                        </button>

                        <button
                          onClick={() => void handleSetStatus(pendingHostname, "Not Active")}
                          className="rounded-xl bg-slate-600/20 px-3 py-2 text-sm text-slate-100 ring-1 ring-slate-500/30 hover:bg-slate-600/30"
                        >
                          Inactive
                        </button>

                        <button
                          onClick={() => void handleSetStatus(pendingHostname, "Unknown")}
                          className="rounded-xl bg-amber-600/20 px-3 py-2 text-sm text-amber-100 ring-1 ring-amber-500/30 hover:bg-amber-600/30"
                        >
                          Unknown
                        </button>

                        <button
                          onClick={() => {
                            setPendingHostname(null);
                            setPendingCommand(null);
                            setMessages((prev) => [
                              ...prev,
                              { role: "assistant", content: "Set status cancelled." },
                            ]);
                            scrollChatToBottom();
                          }}
                          className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                        >
                          /exit
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
                          onClick={() => void executeSubmitInventory()}
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
                  Command mode: /explore /assess /setstatus /assignroles /detail /train /delete
                  /submit /reset /help /commands /exit
                </div>
              </div>
            </ShellCard>
          </div>
        </main>
      </div>

      {/* Desktop / large screens */}
      <div className="hidden h-full xl:grid xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1.66fr)_minmax(380px,1fr)] xl:grid-rows-[auto_auto_auto_auto_minmax(0,1fr)]">
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
              Asset Inventory & CIA
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

                  <span className="text-sm text-slate-300">- ({assetCount} assets)</span>

                  <span className="inline-flex items-center gap-2 rounded-full bg-orange-500/15 px-3 py-1 text-xs text-orange-200 ring-1 ring-orange-500/25">
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-orange-400" />
                    {assetsCiaStatus}
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
              onClick={async () => {
                if (assetsCiaStatus === "Blocked") {
                  showPopup("You should submit Scope & Context document first");
                  return;
                }

                if (assetsCiaStatus === "In Progress") {
                  openConfirm(
                    "You are in the middle of assess inventory operation.\n\nSelect Yes to start a new one.\nSelect No to return.",
                    "new-inventory"
                  );
                  return;
                }

                try {
                  if (assetsCiaStatus === "Not Started") {
                    openConfirm(
                      "A new Asset Inventory file will be created.\n\nDo you want to continue?",
                      "new-inventory"
                    );
                    return;
                  }

                  const doc = await apiGetAssetInventory(YEAR);
                  setRows(flattenInventoryToRows(doc));
                  setMessages((prev) => [
                    ...prev,
                    { role: "assistant", content: "(Loaded) AssetInventory.json" },
                  ]);
                } catch (e) {
                  showPopup(e instanceof Error ? e.message : String(e));
                }
              }}
            >
              <Plus className="h-4 w-4" />
              New Inventory Assessment
            </button>
          </div>
        </div>

        <div className="col-[3] row-[3] p-3 pr-2">
          <ShellCard className="min-h-[161px] p-4">
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

            {roleCatalogError ? (
              <div className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-500/20">
                Role catalog load error: {roleCatalogError}
              </div>
            ) : null}

            {manualOverrideCount > 0 ? (
              <div className="mt-3 rounded-xl bg-sky-500/10 px-4 py-3 text-sm text-sky-200 ring-1 ring-sky-500/20">
                Manual role overrides: {manualOverrideCount}
              </div>
            ) : null}
          </ShellCard>
        </div>

        <div className="col-[3] row-[4] p-3 pr-2">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 2xl:grid-cols-4">
            {kpis.map((k) => (
              <KpiCard key={k.title} kpi={k} />
            ))}
          </div>
        </div>

        <div className="col-[3] row-[5] p-3 pr-2">
          <ShellCard className="flex h-full min-h-[460px] flex-col p-5">
            <div className="shrink-0 text-lg font-semibold">Asset Inventory</div>
            <div className="mt-4 min-h-0 flex-1 overflow-y-auto overflow-x-hidden rounded-xl ring-1 ring-white/10">
              <table className="w-full table-fixed text-left text-sm">
                <thead className="sticky top-0 z-10 bg-[#0b1020]">
                  <tr className="text-slate-300">
                    <th className="w-[15%] px-3 py-3 font-medium">Hostname</th>
                    <th className="w-[23%] px-3 py-3 font-medium">Role</th>
                    <th className="w-[14%] px-3 py-3 font-medium">Location</th>
                    <th className="w-[24%] px-3 py-3 font-medium">Operating System</th>
                    <th className="w-[16%] px-3 py-3 font-medium">CIA Rating</th>
                    <th className="w-[8%] px-3 py-3 text-center font-medium">Status</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-white/5">
                  {rows.map((r, idx) => {
                    const isManualOverride =
                      (r.role || "").trim() !== (r.originalRole || "").trim();
                    const roleOptions = getRoleOptionsForRow(r);

                    return (
                      <tr key={`${r.hostname || "row"}-${idx}`} className="hover:bg-white/5">
                        <td className="break-words px-3 py-2 text-slate-100">{r.hostname || "-"}</td>

                        <td className="px-3 py-2 align-top">
                          <select
                            value={r.role}
                            onChange={(e) => handleRoleChange(r.hostname, e.target.value)}
                            className={[
                              "block w-full min-w-0",
                              "rounded-lg border bg-[#1a1f2e] px-2 py-1.5 text-sm outline-none",
                              isManualOverride
                                ? "border-amber-500/50 text-amber-200 ring-1 ring-amber-500/30"
                                : "border-white/10 text-slate-100 ring-1 ring-white/10",
                            ].join(" ")}
                            title={r.role || ""}
                          >
                            {roleOptions.length === 0 ? (
                              <option value={r.role}>{r.role || "-"}</option>
                            ) : (
                              roleOptions.map((roleName) => {
                                const isBackendRole =
                                  roleName.trim() === (r.originalRole || "").trim();
                                const isSelectedRole =
                                  roleName.trim() === (r.role || "").trim();

                                return (
                                  <option
                                    key={roleName}
                                    value={roleName}
                                    style={{
                                      fontWeight: isBackendRole ? "700" : "400",
                                      color: isSelectedRole
                                        ? "#facc15"
                                        : isBackendRole
                                        ? "#22c55e"
                                        : "#ffffff",
                                      backgroundColor: "#0f172a",
                                    }}
                                  >
                                    {roleName}
                                  </option>
                                );
                              })
                            )}
                          </select>
                        </td>

                        <td className="break-words px-3 py-2 text-slate-200">{r.location || "-"}</td>

                        <td className="break-words px-3 py-2 text-slate-200">
                          {r.os === "Unknown" || !r.os ? "-" : r.os}
                        </td>

                        <td className="px-3 py-2">
                          <div className="min-w-0">
                            <CiaPill value={r.cia} />
                          </div>
                        </td>

                        <td className="px-3 py-2 text-center">
                          <div className="flex justify-center">
                            <StatusCell value={r.status} />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
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

                  {pendingCommand === "assess" && discoveredSubnets.length > 0 ? (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {discoveredSubnets.map((s) => (
                        <button
                          key={s.id}
                          onClick={() => void handleAssessSubnetClick(s.id)}
                          className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                        >
                          {s.label}
                        </button>
                      ))}

                      <button
                        onClick={() => {
                          setPendingCommand(null);
                          setConfirmSubnetId(null);
                          setMessages((prev) => [
                            ...prev,
                            { role: "assistant", content: "Exited assess mode." },
                          ]);
                          scrollChatToBottom();
                        }}
                        className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                      >
                        /exit
                      </button>
                    </div>
                  ) : null}

                  {pendingCommand === "confirm-reassess" && confirmSubnetId ? (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        onClick={async () => {
                          const subnetId = confirmSubnetId;
                          setConfirmSubnetId(null);
                          setPendingCommand("assess");
                          await runAssessSubnet(subnetId);
                        }}
                        className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                      >
                        Yes
                      </button>

                      <button
                        onClick={() => {
                          setConfirmSubnetId(null);
                          setPendingCommand("assess");
                          setMessages((prev) => [
                            ...prev,
                            {
                              role: "assistant",
                              content: "Reassess cancelled. Select another subnet or click /exit.",
                            },
                          ]);
                          scrollChatToBottom();
                        }}
                        className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                      >
                        No
                      </button>
                    </div>
                  ) : null}

                  {pendingCommand === "setstatus-value" && pendingHostname ? (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        onClick={() => void handleSetStatus(pendingHostname, "Active")}
                        className="rounded-xl bg-emerald-600/20 px-3 py-2 text-sm text-emerald-100 ring-1 ring-emerald-500/30 hover:bg-emerald-600/30"
                      >
                        Active
                      </button>

                      <button
                        onClick={() => void handleSetStatus(pendingHostname, "Not Active")}
                        className="rounded-xl bg-slate-600/20 px-3 py-2 text-sm text-slate-100 ring-1 ring-slate-500/30 hover:bg-slate-600/30"
                      >
                        Inactive
                      </button>

                      <button
                        onClick={() => void handleSetStatus(pendingHostname, "Unknown")}
                        className="rounded-xl bg-amber-600/20 px-3 py-2 text-sm text-amber-100 ring-1 ring-amber-500/30 hover:bg-amber-600/30"
                      >
                        Unknown
                      </button>

                      <button
                        onClick={() => {
                          setPendingHostname(null);
                          setPendingCommand(null);
                          setMessages((prev) => [
                            ...prev,
                            { role: "assistant", content: "Set status cancelled." },
                          ]);
                          scrollChatToBottom();
                        }}
                        className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                      >
                        /exit
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
                        onClick={async () => {
                          setSending(true);
                
                          try {
                            const data = await apiPostJSONBody<SubmitCleanupResponse>("/api/assets/submit", {
                              year: YEAR,
                              confirm: true,
                            });
                
                            if (data.inventory) {
                              setRows(flattenInventoryToRows(data.inventory));
                            } else {
                              await refreshInventoryRows();
                            }
                
                            const sys = await apiGetSystemStatus();
                            setSystemStatus(sys);
                
                            setPendingCommand(null);
                            setPendingHostname(null);
                            setConfirmSubnetId(null);
                
                            setMessages((prev) => [
                              ...prev,
                              {
                                role: "assistant",
                                content:
                                  data.message ||
                                  `Removed ${data.removed_unknown ?? 0} Unknown host(s) and ${data.removed_inactive ?? 0} Inactive host(s).`,
                              },
                            ]);
                          } catch {
                            setPendingCommand(null);
                            setMessages((prev) => [
                              ...prev,
                              { role: "assistant", content: "Backend error while submitting the inventory." },
                            ]);
                          } finally {
                            setSending(false);
                            scrollChatToBottom();
                          }
                        }}
                        className="rounded-xl bg-indigo-600/20 px-3 py-2 text-sm text-indigo-100 ring-1 ring-indigo-500/30 hover:bg-indigo-600/30"
                      >
                        Yes
                      </button>
                
                      <button
                        onClick={() => {
                          setPendingCommand(null);
                          setMessages((prev) => [
                            ...prev,
                            { role: "assistant", content: "Submit cancelled." },
                          ]);
                          scrollChatToBottom();
                        }}
                        className="rounded-xl bg-white/10 px-3 py-2 text-sm text-slate-200 ring-1 ring-white/10 hover:bg-white/15"
                      >
                        No
                      </button>
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
                Command mode: /explore /assess /setstatus /assignroles /detail /train /delete
                /submit /reset /help /commands /exit
              </div>
            </div>
          </ShellCard>
        </div>
      </div>

      {confirmOpen ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0b1020] p-5 shadow-2xl ring-1 ring-white/10">
            <div className="text-lg font-semibold text-slate-100">Confirm</div>
            <div className="mt-2 whitespace-pre-wrap text-sm text-slate-300">{confirmText}</div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                className="rounded-xl bg-white/10 px-4 py-2 text-sm font-semibold text-slate-100 ring-1 ring-white/10 hover:bg-white/15"
                onClick={closeConfirm}
              >
                No
              </button>

              <button
                className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
                onClick={async () => {
                  try {
                    if (confirmAction === "new-inventory") {
                      await apiCreateBlankAssetInventory(YEAR, true);

                      const sys = await apiGetSystemStatus();
                      setSystemStatus(sys);

                      const doc = await apiGetAssetInventory(YEAR);
                      setRows(flattenInventoryToRows(doc));

                      setDiscoveredSubnets([]);
                      setAssessedSubnets({});
                      setConfirmSubnetId(null);
                      setPendingCommand(null);
                      setPendingHostname(null);

                      setMessages((prev) => [
                        ...prev,
                        { role: "assistant", content: `(Created) data/work/${YEAR}/AssetInventory.json` },
                      ]);
                    } else if (confirmAction === "reset-inventory") {
                      await apiCreateBlankAssetInventory(YEAR, true);

                      const sys = await apiGetSystemStatus();
                      setSystemStatus({
                        ...sys,
                        sections: {
                          ...sys.sections,
                          assets_cia: {
                            ...sys.sections.assets_cia,
                            status: "Not Started",
                          },
                        },
                      });

                      const doc = await apiGetAssetInventory(YEAR);
                      setRows(flattenInventoryToRows(doc));

                      setMessages((prev) => [
                        ...prev,
                        { role: "assistant", content: "Inventory table has been cleared." },
                      ]);
                    }
                  } catch (e) {
                    showPopup(e instanceof Error ? e.message : String(e));
                  } finally {
                    closeConfirm();
                  }
                }}
                autoFocus
              >
                Yes
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {popupOpen ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0b1020] p-5 shadow-2xl ring-1 ring-white/10">
            <div className="text-lg font-semibold text-slate-100">Notice</div>
            <div className="mt-2 whitespace-pre-wrap text-sm text-slate-300">{popupText}</div>
            <div className="mt-5 flex justify-end">
              <button
                className="rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-600"
                onClick={closePopup}
                autoFocus
              >
                OK
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}