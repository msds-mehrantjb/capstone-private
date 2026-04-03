def build_risk_register_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _extract_risk_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
        _risk_analysis_file,
        _risk_evaluation_treatment_file,
        _risk_register_row_to_markdown_row,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_risk_analysis_file(year), {})
    rows = _extract_risk_rows(doc)

    if not rows:
        doc = _read_json(_risk_evaluation_treatment_file(year), {})
        rows = _extract_risk_rows(doc)

    table = _md_table(
        ["Hostname", "Asset / Role", "Threat", "Vulnerability", "Likelihood", "Impact", "Risk"],
        [_risk_register_row_to_markdown_row(r) for r in rows],
    )

    lines = [
        "# Risk Register",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Total Risk Records:** {len(rows)}",
        "",
        "## Risk Register",
        table,
        "",
    ]
    return "\n".join(lines)