from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_health import router as health_router
from app.api.routes_events import router as events_router
from app.api.routes_agent import router as agent_router
from app.api.routes_rag import router as rag_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_scope import router as scope_router
from app.api.routes_scope_agent import router as scope_agent_router
from app.api.routes_system_status import router as system_status_router
from app.api.routes_assets_inventory import router as assets_router
from app.api.routes_threat_vulnerabilities import router as threat_vulnerabilities_router
from app.api.routes_controls_postures import router as controls_postures_router
from app.api.routes_risk_analysis import router as risk_analysis_router
from app.api.routes_risk_evaluation_treatment import router as risk_evaluation_treatment_router
from app.api.routes_annex_a_soa import router as annex_a_soa_router
from app.api.routes_action_plan_implementation import router as action_plan_implementation_router
from app.api.routes_monitoring_improvement import router as monitoring_improvement_router
from app.api.routes_final_deliverables import router as final_deliverables_router
from app.api.routes_aiml_dashboard import router as aiml_dashboard_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agent-Based Risk Analysis API",
        description="Backend for Agent-based ISO 27001 risk assessment system",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:3000",
        ],
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(events_router)
    app.include_router(agent_router)
    app.include_router(rag_router)
    app.include_router(dashboard_router)
    app.include_router(scope_router)
    app.include_router(scope_agent_router)
    app.include_router(system_status_router)
    app.include_router(assets_router)
    app.include_router(threat_vulnerabilities_router)
    app.include_router(controls_postures_router)
    app.include_router(risk_analysis_router)
    app.include_router(risk_evaluation_treatment_router)
    app.include_router(annex_a_soa_router)
    app.include_router(action_plan_implementation_router)
    app.include_router(monitoring_improvement_router)
    app.include_router(final_deliverables_router)
    app.include_router(aiml_dashboard_router)

    return app


app = create_app()


@app.on_event("startup")
async def startup_event():
    print("Backend started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    print("Backend shutdown complete")
