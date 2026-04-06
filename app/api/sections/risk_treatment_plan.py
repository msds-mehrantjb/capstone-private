def build_risk_treatment_plan_markdown(year: int) -> str:
    from collections import defaultdict

    from app.api.routes_final_deliverables import (
        _extract_risk_rows,
        _load_dashboard_context,
        _read_json,
        _risk_evaluation_treatment_file,
    )

    def _safe(value, default="-"):
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default

    def _shade_row(cells, bg_color):
        return (
            "<tr>"
            + "".join(
                f'<th style="background-color: {bg_color}; padding: 8px; border: 1px solid #999; text-align: left;">{c}</th>'
                for c in cells
            )
            + "</tr>"
        )

    def _data_row(cells, r):
        treatment = str(r.get("treatment", "")).lower()
        risk = str(r.get("risk", "")).lower()
        evaluation = str(r.get("evaluation", "")).lower()
    
        # 🎨 Determine row color
        if treatment == "mitigate":
            bg_color = "#fdecea"  # light red
        elif risk == "low" and evaluation == "accept":
            bg_color = "#e8f5e9"  # light green
        else:
            bg_color = "white"
    
        return (
            f'<tr style="background-color: {bg_color};">'
            + "".join(
                f'<td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{c}</td>'
                for c in cells
            )
            + "</tr>"
        )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_risk_evaluation_treatment_file(year), {})
    rows = _extract_risk_rows(doc)

    grouped = defaultdict(list)
    for r in rows:
        host = _safe(r.get("hostname"))
        grouped[host].append(r)

    lines = [
        "# Risk Treatment Plan",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Treatment Records:** {len(rows)}",
        f"- **Hosts:** {len(grouped)}",
        "",
        "## Risk Treatment Plan",
        "",
    ]

    if not rows:
        lines.append("_No risk treatment records found._")
        lines.append("")
        return "\n".join(lines)

    for host in sorted(grouped.keys()):
        host_rows = grouped[host]
        role = _safe(host_rows[0].get("role"))

        merged_header = (
            '<tr>'
            '<th colspan="5" '
            'style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; '
            'text-align: left; font-weight: bold;">'
            f'Host: {host} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; Role: {role}'
            '</th>'
            '</tr>'
        )

        table_html = [
            '<table style="border-collapse: collapse; width: 100%;">',
            "<thead>",
            merged_header,
            _shade_row(
                [
                    "Vulnerabilities",
                    "CVE ID",
                    "Risk",
                    "Evaluation",
                    "Treatment",
                ],
                "#eef5fb",
            ),
            "</thead>",
            "<tbody>",
        ]

        for r in host_rows:
            vulnerabilities = _safe(r.get("vulnerability_name"))
            cve_id = _safe(r.get("cve_id") or r.get("cve"))
            risk = _safe(r.get("risk"))
            evaluation = _safe(r.get("evaluation"))
            treatment = _safe(r.get("treatment"))

            table_html.append(
                _data_row(
                    [
                        vulnerabilities,
                        cve_id,
                        risk,
                        evaluation,
                        treatment,
                    ],
                    r
                )
            )
        table_html.extend(["</tbody>", "</table>", ""])
        lines.extend(table_html)

    return "\n".join(lines)