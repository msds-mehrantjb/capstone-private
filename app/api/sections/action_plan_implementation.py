def build_action_plan_implementation_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _action_plan_implementation_file,
        _load_dashboard_context,
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

    def _main_control_table(control_row: dict) -> str:
        control_id = _safe(control_row.get("control"))
        control_name = _safe(control_row.get("control_name"))
        implementation_status = _safe(control_row.get("implementation_status"))
        justification = _safe(control_row.get("justification"))
        treatment_plan = _safe(
            control_row.get("treatment_plan") or control_row.get("treatment_action")
        )

        merged_header = (
            '<tr>'
            '<th colspan="3" '
            'style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; '
            'text-align: left; font-weight: bold;">'
            f'Control ID: {_esc(control_id)} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; '
            f'Control Name: {_esc(control_name)} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; '
            f'Status: {_esc(implementation_status)}'
            '</th>'
            '</tr>'
        )

        return "\n".join([
            '<table style="border-collapse: collapse; width: 100%; margin-bottom: 14px;">',
            '  <thead>',
            f'    {merged_header}',
            '    <tr>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Justification</th>',
            '      <th colspan="2" style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Treatment Plan</th>',
            '    </tr>',
            '  </thead>',
            '  <tbody>',
            '    <tr>',
            f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(justification)}</td>',
            f'      <td colspan="2" style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_text_to_html(treatment_plan)}</td>',
            '    </tr>',
            '  </tbody>',
            '</table>',
        ])

    def _hosts_evidence_table(control_row: dict) -> str:
        hosts = control_row.get("hosts", [])
        if not isinstance(hosts, list) or not hosts:
            return "_No host evidence available._"

        tables = []

        for host in hosts:
            if not isinstance(host, dict):
                continue

            hostname = _safe(host.get("hostname"))
            role = _safe(host.get("role"))
            vulnerability = _safe(host.get("vulnerability_name"))
            evidence_list = host.get("evidence", [])

            if not isinstance(evidence_list, list) or not evidence_list:
                evidence_list = [{}]

            lines = [
                '<table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">',
                '  <thead>',
                '    <tr>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Host: {_esc(hostname)}</th>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Role: {_esc(role)}</th>',
                f'      <th colspan="3" style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Vulnerability: {_esc(vulnerability)}</th>',
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
    doc = _read_json(_action_plan_implementation_file(year), {})
    rows = doc.get("controls", [])

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
        "",
    ]

    if not rows:
        lines.append("_No action plan records found._")
        lines.append("")
        return "\n".join(lines)

    methodology = """
## Treatment Plan Recommendation

### Overview
The Treatment Plan Recommendation process generates structured and actionable remediation strategies aligned with ISO/IEC 27001:2022. Each treatment plan is derived from identified risks, vulnerabilities, and asset context to ensure effective and targeted risk mitigation.

---

### Methodology

#### Context-Aware Analysis
Recommendations are generated based on:
- Control ID and Control Name  
- Justification (risk reasoning and business impact)  
- Asset context (host, role, exposure)  
- Vulnerability details (CVE, risk level)  

This ensures that all treatment actions are environment-specific and not generic.

---

#### Retrieval-Augmented Generation (RAG)
The system uses a Retrieval-Augmented Generation approach to ground recommendations in ISO standards:

- Relevant controls are retrieved from ISO/IEC 27002 dataset  
- Semantic similarity and keyword matching identify the best control references  
- A hybrid scoring model combines semantic relevance, keyword matching, and control alignment  

---

#### Semantic Reasoning with Embeddings
Embedding models are used to:
- Convert risk and control context into vector representations  
- Measure similarity using cosine similarity  
- Improve contextual matching beyond keyword-based search  

---

#### LLM-Based Treatment Generation
A local Large Language Model (Llama 3 via Ollama) is used to generate treatment actions.

The model:
- Receives structured context  
- Produces actionable bullet points  
- Ensures implementation-focused steps  

---

#### Practical Implementation Focus
All treatment actions:
- Focus on real implementation steps  
- Include technical and administrative controls  
- Avoid generic recommendations  

---

### Benefits

- Consistency  
- Audit readiness  
- Traceability  
- Context-aware recommendations  

---

### Conclusion

This process ensures that all treatment actions are relevant, practical, and aligned with ISO 27001 requirements.
"""

    for row in rows:
        lines.extend([
            _main_control_table(row),
            "",
            _hosts_evidence_table(row),
            "",
        ])
    
    # ✅ NOW SAFE
    lines.extend([
        "",
        methodology,
        "",
    ])
    return "\n".join(lines)