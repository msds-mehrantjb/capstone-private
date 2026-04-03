import { useEffect, useState } from "react";
import Dashboard from "./pages/Dashboard";
import ScopeContext from "./pages/ScopeContext";
import AssetInventoryCIA from "./pages/AssetInventoryCIA";
import ThreatVulnerabilities from "./pages/ThreatVulnerabilities";
import ControlsPostures from "./pages/ControlsPostures";
import RiskAnalysis from "./pages/RiskAnalysis";
import RiskEvaluationTreatment from "./pages/RiskEvaluationTreatment";
import AnnexASoA from "./pages/AnnexASoA";
import ActionPlanImplementation from "./pages/ActionPlanImplementation";
import MonitoringImprovement from "./pages/MonitoringImprovement";
/** import ActionPlan from "./pages/ActionPlan";
 import FinalDeliverables from "./pages/FinalDeliverables";
*/

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
  | "monitoring-improvement";

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
    const onHashChange = () => setRoute(getRouteFromHash());

    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  switch (route) {
    case "scope":
      return <ScopeContext />;

    case "assets":
      return <AssetInventoryCIA />;

    case "threats":
      return <ThreatVulnerabilities />;

    case "controls":
      return <ControlsPostures />;

    case "risk-analysis":
      return <RiskAnalysis />;

    case "risk-evaluation-treatment":
      return <RiskEvaluationTreatment />;

    case "annex-a-soa":
      return <AnnexASoA />;

    case "action-plan-implementation":
      return <ActionPlanImplementation />;

    case "monitoring-improvement":
      return <MonitoringImprovement />;

    case "dashboard":
    default:
      return <Dashboard />;
  }
}