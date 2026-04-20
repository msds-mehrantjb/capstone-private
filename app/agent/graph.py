from __future__ import annotations

from typing import TypedDict, Dict, Any

from langgraph.graph import StateGraph, END

from app.agent.events import hub, new_event


class AgentState(TypedDict):
    run_id: str
    input: str
    plan: Dict[str, Any]
    evidence: Dict[str, Any]
    report: Dict[str, Any]


async def plan_node(state: AgentState) -> AgentState:
    run_id = state["run_id"]

    await hub.publish(
        new_event(
            type="node_start",
            message="Planning started (LangGraph)",
            run_id=run_id,
        )
    )

    plan = {
        "objective": "Perform ISO 27001 risk assessment",
        "steps": [
            "Collect system metadata",
            "Retrieve control requirements",
            "Analyze risks",
            "Generate report",
        ],
    }

    await hub.publish(
        new_event(
            type="node_end",
            message="Planning complete",
            run_id=run_id,
            data=plan,
        )
    )

    state["plan"] = plan
    return state


async def execute_node(state: AgentState) -> AgentState:
    run_id = state["run_id"]

    await hub.publish(
        new_event(
            type="node_start",
            message="Execution started (LangGraph)",
            run_id=run_id,
        )
    )

    evidence = {
        "os": "Windows Server 2019",
        "domain_role": "Domain Controller",
        "risk": "Example risk placeholder",
    }

    await hub.publish(
        new_event(
            type="node_end",
            message="Execution complete",
            run_id=run_id,
            data=evidence,
        )
    )

    state["evidence"] = evidence
    return state


async def summarize_node(state: AgentState) -> AgentState:
    run_id = state["run_id"]

    await hub.publish(
        new_event(
            type="node_start",
            message="Report generation started",
            run_id=run_id,
        )
    )

    report = {
        "summary": "ISO 27001 risk analysis complete",
        "risk_level": "Medium",
        "recommendations": [
            "Apply latest security patches",
            "Enable advanced auditing",
        ],
    }

    await hub.publish(
        new_event(
            type="node_end",
            message="Report generation complete",
            run_id=run_id,
            data=report,
        )
    )

    state["report"] = report
    return state


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("planner", plan_node)
    graph.add_node("executor", execute_node)
    graph.add_node("summarizer", summarize_node)

    graph.set_entry_point("planner")

    graph.add_edge("planner", "executor")
    graph.add_edge("executor", "summarizer")
    graph.add_edge("summarizer", END)

    return graph.compile()


agent_graph = build_graph()