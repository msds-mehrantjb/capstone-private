def build_action_plan_implementation_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _action_plan_implementation_file,
        _action_plan_row_to_markdown_row,
        _extract_controls_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_action_plan_implementation_file(year), {})
    rows = _extract_controls_rows(doc)

    table = _md_table(
        ["Control ID", "Control Name", "Implementation Status", "Owner", "Target Date"],
        [_action_plan_row_to_markdown_row(r) for r in rows],
    )

    lines = [
        "# Action Plan / Implementation",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Action Items:** {len(rows)}",
        "",
        "## Action Plan / Implementation",
        table,
        "",
    ]
    return "\n".join(lines)