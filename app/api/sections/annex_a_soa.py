def build_annex_a_soa_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _annex_a_soa_file,
        _annex_row_to_markdown_row,
        _extract_controls_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_annex_a_soa_file(year), {})
    rows = _extract_controls_rows(doc)

    table = _md_table(
        ["Control ID", "Control Name", "Domain", "Applicable", "Implementation Status", "Justification"],
        [_annex_row_to_markdown_row(r) for r in rows],
    )

    lines = [
        "# Annex A & Statement of Applicability (SoA)",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Total Controls:** {len(rows)}",
        "",
        "## Annex A & SoA",
        table,
        "",
    ]
    return "\n".join(lines)