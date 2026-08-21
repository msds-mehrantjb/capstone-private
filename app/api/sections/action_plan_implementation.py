import os
from urllib.parse import quote


def build_action_plan_implementation_markdown(
    year: int,
    include_guide_column: bool = True,
) -> str:
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
        control_row: dict,
        host: dict,
        evidence: dict,
        evidence_index: int,
    ) -> dict | None:
        control_id = _normalize_text(
            control_row.get("control_id") or control_row.get("control")
        )
        hostname = _normalize_text(host.get("hostname"))
        vulnerability_name = _normalize_text(host.get("vulnerability_name"))
        evidence_id = _normalize_text(evidence.get("evidence_id"))
        evidence_desc = _normalize_text(evidence.get("desc"))

        def _guide_matches_context(guide: dict) -> bool:
            guide_control = _normalize_text(guide.get("control_id"))
            guide_host = _normalize_text(guide.get("hostname"))
            guide_vuln = _normalize_text(guide.get("vulnerability_name"))

            if guide_control and control_id and guide_control != control_id:
                return False
            if guide_host and hostname and guide_host != hostname:
                return False
            if guide_vuln and vulnerability_name and guide_vuln != vulnerability_name:
                return False

            return True
    
        # Best match: evidence_id
        if evidence_id:
            for guide in guide_records:
                if (
                    _normalize_text(guide.get("evidence_id")) == evidence_id
                    and _guide_matches_context(guide)
                ):
                    return guide
    
        # Fallback match for older evidence rows if evidence_id is missing
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
            "/api/final-deliveries/action-plan-implementation/guide/"
            f"evidence/{quote(evidence_id, safe='')}/pdf"
        )
    
        return (
            f'<a href="{pdf_url}" '
            f'target="_blank" rel="noopener noreferrer" '
            f'style="display: inline-block; color: #000; text-decoration: none; font-size: 16px; '
            f'line-height: 1;" '
            f'title="Create or download Guide PDF">📄</a>'
        )
    
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
        total_columns = 6 if include_guide_column else 5
        trailing_header_span = total_columns - 2
        colgroup = (
            "<colgroup>"
            "<col style=\"width: 16%;\">"
            "<col style=\"width: 16%;\">"
            "<col style=\"width: 10%;\">"
            "<col style=\"width: 16%;\">"
            + (
                "<col style=\"width: 37%;\">"
                "<col style=\"width: 5%;\">"
                if include_guide_column
                else "<col style=\"width: 42%;\">"
            )
            + "</colgroup>"
        )

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
                '<table style="border-collapse: collapse; width: 100%; table-layout: fixed; margin-bottom: 20px;">',
                f'  {colgroup}',
                '  <thead>',
                '    <tr>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Host: {_esc(hostname)}</th>',
                f'      <th style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Role: {_esc(role)}</th>',
                f'      <th colspan="{trailing_header_span}" style="background-color: #e8f1e8; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Vulnerability: {_esc(vulnerability)}</th>',
                '    </tr>',
                '    <tr>',
                f'      <th colspan="{total_columns}" style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: center; font-weight: bold;">Evidence(s)</th>',
                '    </tr>',
                '    <tr>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Responsible</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Resources</th>',
                '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left; white-space: nowrap;">Date</th>',
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

            for evidence_index, evidence in enumerate(evidence_list):
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
                    f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; white-space: nowrap;">{_text_to_html(date)}</td>',
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
A local Large Language Model served through Ollama is used to generate treatment actions.

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

    lines.extend([
        "",
        methodology,
        "",
    ])

    return "\n".join(lines)
