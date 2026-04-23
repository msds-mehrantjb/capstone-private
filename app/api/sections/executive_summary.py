def build_executive_summary_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _action_plan_implementation_file,
        _annex_a_soa_file,
        _extract_controls_rows,
        _extract_risk_rows,
        _extract_scope_summary,
        _get_section,
        _load_dashboard_context,
        _load_scope_file_payload,
        _md_table,
        _read_json,
        _render_section,
        _risk_evaluation_treatment_file,
        _safe_md,
    )

    ctx = _load_dashboard_context(year)
    scope_doc = _load_scope_file_payload(year)
    scope_summary = _extract_scope_summary(scope_doc, ctx, year)

    risk_eval_doc = _read_json(_risk_evaluation_treatment_file(year), {})
    annex_doc = _read_json(_annex_a_soa_file(year), {})
    action_doc = _read_json(_action_plan_implementation_file(year), {})

    risk_rows = _extract_risk_rows(risk_eval_doc)
    annex_rows = _extract_controls_rows(annex_doc)
    action_rows = _extract_controls_rows(action_doc)

    high_risks = 0
    medium_risks = 0
    low_risks = 0

    for row in risk_rows:
        risk = str(row.get("risk", row.get("risk_level", ""))).strip().lower()
        if risk == "high":
            high_risks += 1
        elif risk == "medium":
            medium_risks += 1
        elif risk == "low":
            low_risks += 1

    sec_boundaries = _get_section(scope_doc, "organizational_boundaries")
    sec_geo = _get_section(scope_doc, "geographic_boundaries")
    sec_tech = _get_section(scope_doc, "technical_boundaries")
    sec_exclusions = _get_section(scope_doc, "exclusions")
    sec_stakeholders = _get_section(scope_doc, "stakeholders")

    boundaries_md = _safe_md(
        _render_section(sec_boundaries),
        "_Not defined in the scope document._"
    )

    included_md = _safe_md(
        "\n\n".join([
            _render_section(sec_geo),
            _render_section(sec_tech)
        ]),
        "_Not defined in the scope document._"
    )

    excluded_md = _safe_md(
        _render_section(sec_exclusions),
        "_Not defined in the scope document._"
    )

    interested_parties_md = _safe_md(
        _render_section(sec_stakeholders),
        "_Not defined in the scope document._"
    )

    rows = [
        ["**Assessment Year**", scope_summary["assessment_year"]],
        ["**Scope Name**", scope_summary["scope_name"]],
        ["**Environment**", scope_summary["environment"]],
        ["**Included Assets**", scope_summary["included_assets"]],
        ["**Assessment Standard**", scope_summary["assessment_standard"]],
        ["**Scope Status**", scope_summary["scope_status"]],
    ]

    if scope_summary["organization_name"] != "NA":
        rows.insert(0, ["**Organization**", scope_summary["organization_name"]])

    if scope_summary["scope_statement"] != "NA":
        rows.insert(
            3 if scope_summary["organization_name"] != "NA" else 2,
            ["**Scope Statement**", scope_summary["scope_statement"]],
        )

    org_scope_table = _md_table(["Attribute", "Value"], rows)
    risk_position_table = _md_table(
        ["Risk Level", "Count"],
        [
            ["**High**", high_risks],
            ["**Medium**", medium_risks],
            ["**Low**", low_risks],
        ],
    )

    lines = [
        "# Executive Summary",
        "",
        "---",
        "",
        "## 1. Overview",
        "",
        "This report presents the results of the **ISO/IEC 27001:2022 assessment** conducted for the defined audit scope.",
        "",
        "It provides a consolidated and management-focused view of the organization’s **information security posture**, including:",
        "",
        "- Identified risks and exposure levels",
        "- Risk treatment priorities",
        "- Control applicability and effectiveness",
        "- Implementation status",
        "- Monitoring and continual improvement requirements",
        "",
        "---",
        "",
        "## 2. Organization & Scope",
        "",
        org_scope_table,
        "",
        "---",
        "",
        "## 3. Scope Definition",
        "",
        "### Organizational Boundaries",
        boundaries_md,
        "",
        "### Included in Scope",
        included_md,
        "",
        "### Excluded from Scope",
        excluded_md,
        "",
        "### Interested Parties",
        interested_parties_md,
        "",
        "---",
        "",
        "## Assessment Methodology",
        "",
        "The assessment was conducted across the full ISO 27001 lifecycle, including:",
        "",
        "- Asset identification and classification",
        "- Threat and vulnerability assessment",
        "- Existing control evaluation",
        "- Risk analysis and evaluation",
        "- Risk treatment planning",
        "- Annex A control selection and justification (SoA)",
        "- Action planning and implementation tracking",
        "- Monitoring and continual improvement",
        "",
        "The objective of this assessment is to provide management with a **clear, decision-ready understanding** of current risks and required remediation actions.",
        "",
        "---",
        "",
        "## Key Findings",
        "",
        f"- **Assets assessed:** {scope_summary['included_assets']}",
        f"- **High risks identified:** {high_risks}",
        f"- **Medium risks identified:** {medium_risks}",
        f"- **Low risks identified:** {low_risks}",
        f"- **Annex A / SoA controls defined:** {len(annex_rows)}",
        f"- **Action plan items defined:** {len(action_rows)}",
        "",
        "### Key Observations",
        "",
        "- A number of **high-risk conditions** require immediate remediation",
        "- Control implementation is **partially effective** and requires strengthening",
        "- Risk treatment activities are defined but require **execution and tracking**",
        "- Scope definition elements require further formalization",
        "",
        "---",
        "",
        "## Risk Position",
        "",
        risk_position_table,
        "",
        "**Summary:**  ",
        "The organization currently maintains a **moderate to elevated risk posture**, with priority focus required on high-risk items.",
        "",
        "---",
        "",
        "## Annex A & Statement of Applicability (SoA)",
        "",
        "Annex A controls have been evaluated against identified risks and organizational context:",
        "",
        "- Applicable controls have been selected and documented",
        "- Justifications have been defined within the Statement of Applicability",
        "- The SoA serves as the **baseline for control implementation and audit validation**",
        "",
        "---",
        "",
        "## Priority Recommendations",
        "",
        "- Address all **high-risk findings** through approved treatment actions",
        "- Strengthen controls in **critical infrastructure and security domains**",
        "- Ensure **formal tracking of remediation activities** via the Action Plan",
        "- Validate treatment effectiveness through **ongoing monitoring**",
        "- Maintain sufficient documentation and evidence to support **audit readiness**",
        "",
        "---",
        "",
        "## Management Conclusion",
        "",
        "The organization has established a **structured foundation for ISO/IEC 27001 alignment** within the defined scope.",
        "",
        "However, further effort is required in the following areas:",
        "",
        "- Execution of risk treatment plans",
        "- Improvement of control maturity and effectiveness",
        "- Formalization of scope definition and governance elements",
        "- Continuous monitoring and improvement",
        "",
        "These actions are necessary to ensure that risks remain within acceptable tolerance and that the **Information Security Management System (ISMS) continues to mature over time**.",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)
