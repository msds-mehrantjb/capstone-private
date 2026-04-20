import { lazy, Suspense, useEffect, useState } from "react";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const ScopeContext = lazy(() => import("./pages/ScopeContext"));
const AssetInventoryCIA = lazy(() => import("./pages/AssetInventoryCIA"));
const ThreatVulnerabilities = lazy(() => import("./pages/ThreatVulnerabilities"));
const ControlsPostures = lazy(() => import("./pages/ControlsPostures"));
const RiskAnalysis = lazy(() => import("./pages/RiskAnalysis"));
const RiskEvaluationTreatment = lazy(() => import("./pages/RiskEvaluationTreatment"));
const AnnexASoA = lazy(() => import("./pages/AnnexASoA"));
const ActionPlanImplementation = lazy(() => import("./pages/ActionPlanImplementation"));
const MonitoringImprovement = lazy(() => import("./pages/MonitoringImprovement"));
const FinalDeliverables = lazy(() => import("./pages/FinalDeliverables"));
const AIMLDashboard = lazy(() => import("./pages/AIMLDashboard"));

type RouteKey =
  | "dashboard"
  | "scope"
  | "assets"
  | "threats"
  | "controls"
  | "risk-analysis"
  | "risk-evaluation-treatment"
  | "annex-a-soa"
  | "action-plan-implementation"
  | "monitoring-improvement"
  | "final-deliveries"
  | "ai-ml"; // <-- add ai-ml route key

function getRouteFromHash(): RouteKey {
  const h = (window.location.hash || "").toLowerCase();

  if (h.startsWith("#/scope")) return "scope";
  if (h.startsWith("#/assets")) return "assets";
  if (h.startsWith("#/threats")) return "threats";
  if (h.startsWith("#/controls")) return "controls";
  if (h.startsWith("#/risk-analysis")) return "risk-analysis";
  if (h.startsWith("#/risk-evaluation-treatment")) return "risk-evaluation-treatment";
  if (h.startsWith("#/annex-a-soa")) return "annex-a-soa";
  if (h.startsWith("#/action-plan-implementation")) return "action-plan-implementation";
  if (h.startsWith("#/monitoring-improvement")) return "monitoring-improvement";
  if (h.startsWith("#/final-deliveries")) return "final-deliveries";
  if (h.startsWith("#/final-deliverables")) return "final-deliveries";
  if (h.startsWith("#/ai-ml")) return "ai-ml";

  return "dashboard";
}

export default function App() {
  const [route, setRoute] = useState<RouteKey>(() => {
    if (!window.location.hash) {
      window.location.hash = "#/dashboard";
    }
    return getRouteFromHash();
  });

  useEffect(() => {
    (window as any).downloadGuidePdf = async (guideId: string) => {
      try {
        const backendBase = "http://127.0.0.1:8000";
        const url = `${backendBase}/api/final-deliveries/action-plan-implementation/guide/${encodeURIComponent(guideId)}/pdf`;

        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`Failed to download PDF: ${response.status}`);
        }

        const blob = await response.blob();

        const link = document.createElement("a");
        const objectUrl = window.URL.createObjectURL(blob);

        link.href = objectUrl;
        link.download = `${guideId}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();

        window.URL.revokeObjectURL(objectUrl);
      } catch (err) {
        console.error(err);
        alert("Failed to download guide PDF");
      }
    };

    return () => {
      delete (window as any).downloadGuidePdf;
    };
  }, []);

  useEffect(() => {
    const onHashChange = () => setRoute(getRouteFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  let page: React.ReactNode;

  switch (route) {
    case "scope":
      page = <ScopeContext />;
      break;
    case "assets":
      page = <AssetInventoryCIA />;
      break;
    case "threats":
      page = <ThreatVulnerabilities />;
      break;
    case "controls":
      page = <ControlsPostures />;
      break;
    case "risk-analysis":
      page = <RiskAnalysis />;
      break;
    case "risk-evaluation-treatment":
      page = <RiskEvaluationTreatment />;
      break;
    case "annex-a-soa":
      page = <AnnexASoA />;
      break;
    case "action-plan-implementation":
      page = <ActionPlanImplementation />;
      break;
    case "monitoring-improvement":
      page = <MonitoringImprovement />;
      break;
    case "final-deliveries":
      page = <FinalDeliverables />;
      break;
    case "ai-ml":
      page = <AIMLDashboard />;
      break;
    case "dashboard":
    default:
      page = <Dashboard />;
      break;
  }

  return (
    <Suspense
      fallback={
        <div className="grid min-h-screen place-items-center bg-[#070A12] text-slate-100">
          Loading...
        </div>
      }
    >
      {page}
    </Suspense>
  );
}
