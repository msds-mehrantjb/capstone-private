def build_monitoring_improvement_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _load_dashboard_context,
        _md_table,
        _monitoring_improvement_file,
        _monitoring_row_to_markdown_row,
        _read_json,
        _safe_list,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_monitoring_improvement_file(year), {})
    cves = [r for r in _safe_list(doc.get("cves")) if isinstance(r, dict)]

    table = _md_table(
        ["Item", "Title", "Status", "Owner", "Review Date"],
        [_monitoring_row_to_markdown_row(r) for r in cves],
    )

    lines = [
        "# Monitoring Improvement",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Monitoring Items:** {len(cves)}",
        "",
        "## Monitoring / Improvement Register",
        table,
        "",
    ]
    return "\n".join(lines)