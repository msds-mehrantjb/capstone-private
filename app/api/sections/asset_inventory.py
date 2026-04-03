def build_asset_inventory_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _asset_inventory_file,
        _asset_row_to_markdown_row,
        _extract_asset_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
    )

    ctx = _load_dashboard_context(year)
    asset_doc = _read_json(_asset_inventory_file(year), {})
    rows = _extract_asset_rows(asset_doc)

    table = _md_table(
        ["Hostname", "IP Address", "Role", "CIA Rating", "Status", "Subnet"],
        [_asset_row_to_markdown_row(r) for r in rows],
    )

    lines = [
        "# Asset Inventory",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Total Assets:** {len(rows)}",
        "",
        "## Asset Inventory Table",
        table,
        "",
    ]
    return "\n".join(lines)