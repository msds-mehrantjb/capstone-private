import os
from urllib.parse import quote


def build_monitoring_improvement_markdown(
    year: int,
    include_guide_column: bool = True,
) -> str:
    from app.api.routes_final_deliverables import (
        _load_dashboard_context,
        _monitoring_improvement_file,
        _read_json,
    )

    def _safe(value, default="-"):
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default

    def _esc(value):
        text = "" if value is None else str(value).strip()
        text = (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return text if text else "-"

    def _text_to_html(value):
        text = _safe(value, "-")
        return _esc(text).replace("\n", "<br>")

    def _api_base_url() -> str:
        return (
            os.getenv("VITE_API_BASE_URL")
            or os.getenv("CAPSTONE_API_BASE_URL")
            or os.getenv("API_BASE_URL")
            or "http://127.0.0.1:8003"
        ).rstrip("/")

    def _normalize_text(value) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    def _extract_guide_records(guides_doc) -> list[dict]:
        if isinstance(guides_doc, list):
            return [g for g in guides_doc if isinstance(g, dict)]

        if isinstance(guides_doc, dict):
            for key in ["guides", "records", "items", "evidence_guides"]:
                value = guides_doc.get(key)
                if isinstance(value, list):
                    return [g for g in value if isinstance(g, dict)]

        return []

    def _find_matching_guide(
        guide_records: list[dict],
        item_row: dict,
        host: dict,
        evidence: dict,
    ) -> dict | None:
        control_id = _normalize_text(item_row.get("CVE") or item_row.get("cve"))
        hostname = _normalize_text(host.get("hostname"))
        vulnerability_name = _normalize_text(host.get("vulnerability_name") or item_row.get("vulnerability"))
        evidence_id = _normalize_text(evidence.get("evidence_id"))
        evidence_desc = _normalize_text(evidence.get("desc"))

        def _guide_matches_context(guide: dict) -> bool:
            guide_control = _normalize_text(guide.get("control_id") or guide.get("cve_id"))
            guide_host = _normalize_text(guide.get("hostname"))
            guide_vuln = _normalize_text(guide.get("vulnerability_name") or guide.get("control_name"))

            if guide_control and control_id and guide_control != control_id:
                return False
            if guide_host and hostname and guide_host != hostname:
                return False
            if guide_vuln and vulnerability_name and guide_vuln != vulnerability_name:
                return False

            return True

        if evidence_id:
            for guide in guide_records:
                if (
                    _normalize_text(guide.get("evidence_id")) == evidence_id
                    and _guide_matches_context(guide)
                ):
                    return guide

        for guide in guide_records:
            guide_control = _normalize_text(guide.get("control_id"))
            guide_host = _normalize_text(guide.get("hostname"))
            guide_vuln = _normalize_text(guide.get("vulnerability_name"))
            guide_desc = _normalize_text(guide.get("evidence_description"))

            if (
                guide_control == control_id
                and guide_host == hostname
                and guide_vuln == vulnerability_name
                and (
                    not evidence_desc
                    or evidence_desc == guide_desc
                    or evidence_desc in guide_desc
                    or guide_desc in evidence_desc
                )
            ):
                return guide

        return None

    def _has_meaningful_evidence(evidence: dict) -> bool:
        for key in ["responsible", "resources", "date", "url", "desc"]:
            if str(evidence.get(key, "")).strip():
                return True
        return False

    def _guide_icon_html(evidence: dict) -> str:
        if not _has_meaningful_evidence(evidence):
            return "-"

        evidence_id = str(evidence.get("evidence_id", "")).strip()
        if not evidence_id:
            return "-"

        pdf_url = (
            f"{_api_base_url()}"
            "/api/final-deliveries/monitoring-improvement/guide/"
            f"evidence/{quote(evidence_id, safe='')}/pdf"
        )

        return (
            f'<a href="{pdf_url}" '
            f'target="_blank" rel="noopener noreferrer" '
            f'style="text-decoration: none; font-size: 16px;" '
            f'title="Download Guide PDF">📄</a>'
        )

    def _main_monitoring_table(item_row: dict) -> str:
        cve_id = _safe(item_row.get("CVE") or item_row.get("cve"))
        vulnerability = _safe(item_row.get("vulnerability"))
        implementation_status = _safe(item_row.get("implementation_status"))
        justification = _safe(item_row.get("justification"))
        recommendation_action = _safe(
            item_row.get("recommendation_action") or item_row.get("recommended_action")
        )

        merged_header = (
            '<tr>'
            '<th colspan="2" '
            'style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; '
            'text-align: left; font-weight: bold;">'
            f'CVE ID: {_esc(cve_id)} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; '
            f'Vulnerability: {_esc(vulnerability)} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; '
            f'Status: {_esc(implementation_status)}'
            '</th>'
            '</tr>'
        )

        return "\n".join([
            '<table style="border-collapse: collapse; width: 100%; margin-bottom: 14px;">',
            '  <thead>',
            f'    {merged_header}',
            '    <tr>',
            '      <th style="width: 50%; background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Justification</th>',
            '      <th style="width: 50%; background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Recommendation Action</th>',
            '    </tr>',
            '  </thead>',
            '  <tbody>',
            '    <tr>',
            f'      <td style="width: 50%; padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(justification)}</td>',
            f'      <td style="width: 50%; padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(recommendation_action)}</td>',
            '    </tr>',
            '  </tbody>',
            '</table>',
        ])

    def _hosts_evidence_table(item_row: dict) -> str:
        hosts = item_row.get("hosts", [])

        if (
            (not isinstance(hosts, list) or not hosts)
            and any(item_row.get(key) for key in ("hostname", "ip_address", "role", "evidence"))
        ):
            hosts = [item_row]

        if not isinstance(hosts, list) or not hosts:
            return "_No host evidence available._"

        tables = []
        total_columns = 6 if include_guide_column else 5
        trailing_header_span = total_columns - 2
        colgroup = (
            "<colgroup>"
            "<col style=\"width: 18%;\">"
            "<col style=\"width: 16%;\">"
            "<col style=\"width: 10%;\">"
            "<col style=\"width: 16%;\">"
            + (
                "<col style=\"width: 35%;\">"
                "<col style=\"width: 5%;\">"
                if include_guide_column
                else "<col style=\"width: 40%;\">"
            )
            + "</colgroup>"
        )

        for host in hosts:
            if not isinstance(host, dict):
                continue

            hostname = _safe(host.get("hostname"))
            role = _safe(host.get("role"))
            ip_address = _safe(host.get("ip_address"))
            evidence_list = host.get("evidence", [])

            if not isinstance(evidence_list, list) or not evidence_list:
                evidence_list = [{}]

            lines = [
                '<table style="border-collapse: collapse; width: 100%; table-layout: fixed; margin-bottom: 20px;">',
                f'  {colgroup}',
                '  <thead>',
                '    <tr>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Host: {_esc(hostname)}</th>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Role: {_esc(role)}</th>',
                f'      <th colspan="{trailing_header_span}" style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">IP Address: {_esc(ip_address)}</th>',
                '    </tr>',
                '    <tr>',
                f'      <th colspan="{total_columns}" style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: center; font-weight: bold;">Evidence(s)</th>',
                '    </tr>',
                '    <tr>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Responsible</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Resources</th>',
                '      <th style="white-space: nowrap; background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Date</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">URL/PATH</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Desc</th>',
                '    </tr>',
                '  </thead>',
                '  <tbody>',
            ]

            if include_guide_column:
                lines.insert(
                    len(lines) - 3,
                    '      <th style="background-color: #eef5fb; padding: 4px 6px; border: 1px solid #999; text-align: center; width: 1%; white-space: nowrap;">Guide</th>',
                )

            for evidence in evidence_list:
                if not isinstance(evidence, dict):
                    evidence = {}

                responsible = _safe(evidence.get("responsible"))
                resources = _safe(evidence.get("resources"))
                date = _safe(evidence.get("date"))
                url = _safe(evidence.get("url"))
                desc = _safe(evidence.get("desc"))
                row_cells = [
                    '    <tr>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; overflow-wrap: anywhere; word-break: break-word;">{_text_to_html(responsible)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; overflow-wrap: anywhere; word-break: break-word;">{_text_to_html(resources)}</td>',
                    f'      <td style="white-space: nowrap; padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(date)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; overflow-wrap: anywhere; word-break: break-word;">{_text_to_html(url)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; overflow-wrap: anywhere; word-break: break-word;">{_text_to_html(desc)}</td>',
                ]

                if include_guide_column:
                    guide_cell = _guide_icon_html(evidence)
                    row_cells.append(
                        f'      <td style="padding: 4px 6px; border: 1px solid #999; vertical-align: middle; text-align: center; width: 1%; white-space: nowrap;">{guide_cell}</td>'
                    )

                row_cells.append('    </tr>')
                lines.extend(row_cells)

            lines.extend([
                '  </tbody>',
                '</table>',
            ])

            tables.append("\n".join(lines))

        return "\n\n".join(tables)

    ctx = _load_dashboard_context(year)
    doc = _read_json(_monitoring_improvement_file(year), {})
    if isinstance(doc, list):
        rows = [row for row in doc if isinstance(row, dict)]
    elif isinstance(doc, dict):
        rows = doc.get("cves", [])
        if not isinstance(rows, list):
            rows = doc.get("items", [])
        if not isinstance(rows, list):
            rows = doc.get("records", [])
        if not isinstance(rows, list):
            rows = doc.get("monitoring_items", [])
        rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    else:
        rows = []

    lines = [
        "# Monitoring Improvement",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Monitoring Items:** {len(rows)}",
        "",
        "## Monitoring / Improvement Register",
        "",
    ]

    if not rows:
        lines.append("_No monitoring items found._")
        lines.append("")
        return "\n".join(lines)

    methodology = """
## Recommended Action

### Overview
The Recommended Action represents a structured set of monitoring-focused activities designed to continuously track, detect, and respond to vulnerabilities identified within the organization’s environment. Unlike remediation-focused treatment plans, these actions emphasize ongoing visibility, validation, and control effectiveness.

---

### Objective

- Ensure continuous detection of abnormal or malicious behavior
- Validate effectiveness of remediation actions (patching, configuration changes)
- Provide early warning for exploitation attempts
- Support continuous improvement of security controls

---

### Methodology

#### Context-Aware Recommendation
Recommendations are generated using:
- CVE and vulnerability context
- Justification and risk reasoning
- Host and asset information
- Exposure and operational environment

---

#### Retrieval-Augmented Generation (RAG)
The system retrieves relevant ISO/IEC 27002 controls and combines:

- Semantic similarity (embedding-based)
- Keyword matching
- Control relevance boosting

This ensures alignment with ISO controls such as:
- Logging & monitoring (8.15, 8.16)
- Vulnerability management (8.8)
- Network monitoring (8.20)

---

#### Semantic Reasoning
Embedding models convert context into vectors and use cosine similarity to improve accuracy and relevance beyond keyword matching.

---

#### LLM-Based Action Generation
A local LLM served through Ollama generates structured monitoring actions:

- Output starts with **"Recommended monitoring actions:"**
- Bullet-point format only
- No explanations or narrative
- Focus on detection, alerting, validation, and tracking

---

#### Monitoring-Oriented Design
All actions focus on:

- Detection (logs, alerts, anomalies)
- Validation (patch and fix verification)
- Visibility (exposure tracking)
- Response readiness (incident detection)
- Continuous improvement

---

### Benefits

- Continuous risk visibility
- Audit-ready structured output
- Faster detection and response
- Context-aware recommendations
- Standardized monitoring practices

---

### Conclusion

The Recommended Action process combines AI reasoning, RAG, and ISO-aligned knowledge to generate effective monitoring strategies that ensure vulnerabilities are continuously tracked, validated, and controlled over time.
"""

    for row in rows:
        lines.extend([
            _main_monitoring_table(row),
            "",
            _hosts_evidence_table(row),
            "",
        ])

    lines.extend([
        "",
        methodology,
        "",
    ])

    return "\n".join(lines)
