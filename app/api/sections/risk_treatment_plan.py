def build_risk_treatment_plan_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _extract_risk_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
        _risk_evaluation_treatment_file,
        _risk_treatment_row_to_markdown_row,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_risk_evaluation_treatment_file(year), {})
    rows = _extract_risk_rows(doc)

    table = _md_table(
        ["Hostname", "Risk", "Evaluation", "Treatment", "Owner", "Target Date"],
        [_risk_treatment_row_to_markdown_row(r) for r in rows],
    )

    lines = [
        "# Risk Treatment Plan",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Treatment Records:** {len(rows)}",
        "",
        "## Risk Treatment Plan",
        table,
        "",
    ]
    return "\n".join(lines)