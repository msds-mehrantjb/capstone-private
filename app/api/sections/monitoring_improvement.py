def build_monitoring_improvement_markdown(year: int) -> str:
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
        if not isinstance(hosts, list) or not hosts:
            return "_No host evidence available._"

        tables = []

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
                '<table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">',
                '  <thead>',
                '    <tr>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Host: {_esc(hostname)}</th>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Role: {_esc(role)}</th>',
                f'      <th colspan="3" style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">IP Address: {_esc(ip_address)}</th>',
                '    </tr>',
                '    <tr>',
                '      <th colspan="5" style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: center; font-weight: bold;">Evidence(s)</th>',
                '    </tr>',
                '    <tr>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Responsible</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Resources</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Date</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">URL/PATH</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Desc</th>',
                '    </tr>',
                '  </thead>',
                '  <tbody>',
            ]

            for evidence in evidence_list:
                if not isinstance(evidence, dict):
                    evidence = {}

                responsible = _safe(evidence.get("responsible"))
                resources = _safe(evidence.get("resources"))
                date = _safe(evidence.get("date"))
                url = _safe(evidence.get("url"))
                desc = _safe(evidence.get("desc"))

                lines.extend([
                    '    <tr>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(responsible)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(resources)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(date)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(url)}</td>',
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(desc)}</td>',
                    '    </tr>',
                ])

            lines.extend([
                '  </tbody>',
                '</table>',
            ])

            tables.append("\n".join(lines))

        return "\n\n".join(tables)

    ctx = _load_dashboard_context(year)
    doc = _read_json(_monitoring_improvement_file(year), {})
    rows = doc.get("cves", [])

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
A local LLM (Llama 3 via Ollama) generates structured monitoring actions:

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