def build_asset_inventory_markdown(year: int) -> str:
    from collections import defaultdict

    from app.api.routes_final_deliverables import (
        _asset_inventory_file,
        _extract_asset_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
    )

    def _safe_str(value, default: str = "NA") -> str:
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default

    def _get_hostname(row: dict) -> str:
        return _safe_str(row.get("hostname") or row.get("host") or row.get("name"))

    def _get_ip_address(row: dict) -> str:
        location = row.get("location", {})
        if isinstance(location, dict):
            ip = location.get("ip_address")
            if ip:
                return _safe_str(ip)
        return _safe_str(row.get("ip") or row.get("ip_address"))

    def _get_operating_system(row: dict) -> str:
        return _safe_str(row.get("operating_system"))

    def _get_role(row: dict) -> str:
        return _safe_str(row.get("role") or row.get("predicted_role"))

    def _get_criticality(row: dict) -> str:
        cia = row.get("cia_rating", {})
        if isinstance(cia, dict):
            return _safe_str(cia.get("criticality"))
        return _safe_str(row.get("cia_rating"))

    def _get_business_context(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        business_context = detail.get("business_context", {})
        if not isinstance(business_context, dict):
            return "NA"

        department = str(business_context.get("department", "")).strip()
        business_function = str(business_context.get("business_function", "")).strip()

        if department and business_function:
            return f"{department} / {business_function}"
        if department:
            return department
        if business_function:
            return business_function
        return "NA"

    def _get_subnet_name(row: dict) -> str:
        subnet = str(row.get("subnet", "")).strip()
        if subnet:
            return subnet

        location = row.get("location", {})
        if isinstance(location, dict):
            subnet_name = str(location.get("name", "")).strip()
            if subnet_name:
                return subnet_name

        return "Uncategorized"

    def _get_indicator_role(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        indicator = detail.get("indicator_based_role_detection", {})
        if not isinstance(indicator, dict):
            return "NA"

        detected_roles = indicator.get("detected_roles", [])
        if isinstance(detected_roles, list) and detected_roles:
            return _safe_str(detected_roles[0])

        return "NA"

    def _get_indicator_confidence(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        indicator = detail.get("indicator_based_role_detection", {})
        if not isinstance(indicator, dict):
            return "NA"

        return _safe_str(indicator.get("confidence"))

    def _get_ml_role(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        ml = detail.get("ml_role_prediction", {})
        if not isinstance(ml, dict):
            return "NA"

        predicted_roles = ml.get("predicted_roles", [])
        if isinstance(predicted_roles, list) and predicted_roles:
            return _safe_str(predicted_roles[0])

        return "NA"

    def _get_ml_confidence(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        ml = detail.get("ml_role_prediction", {})
        if not isinstance(ml, dict):
            return "NA"

        return _safe_str(ml.get("confidence"))

    def _get_selected_role(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        selected = detail.get("selected_role", {})
        if not isinstance(selected, dict):
            return "NA"

        return _safe_str(selected.get("role"))

    def _get_selected_method(row: dict) -> str:
        detail = row.get("detail", {})
        if not isinstance(detail, dict):
            return "NA"

        selected = detail.get("selected_role", {})
        if not isinstance(selected, dict):
            return "NA"

        return _safe_str(selected.get("method"))

    def _build_grouped_header_table(rows_data: list[list[object]]) -> str:
        if not rows_data:
            return "_No data available._"
    
        def esc(value: object) -> str:
            text = "" if value is None else str(value).strip()
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
    
        lines = [
            '<table style="border-collapse: collapse; width: 100%; text-align: left;">',
            '  <thead>',
            '    <tr>',
            '      <th rowspan="2" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Hostname</th>',
            '      <th colspan="2" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Indicator Based</th>',
            '      <th colspan="2" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">ML-Based</th>',
            '      <th colspan="2" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">Selected</th>',
            '    </tr>',
            '    <tr>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Role</th>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Confidence</th>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Role</th>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Confidence</th>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Role</th>',
            '      <th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">Method</th>',
            '    </tr>',
            '  </thead>',
            '  <tbody>',
        ]
    
        for row in rows_data:
            normalized = list(row) + [""] * (7 - len(row))
            lines.extend([
                '    <tr>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[0])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[1])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[2])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[3])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[4])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[5])}</td>',
                f'      <td style="padding: 8px; border: 1px solid #999; vertical-align: top; text-align: left;">{esc(normalized[6])}</td>',
                '    </tr>',
            ])
    
        lines.extend([
            '  </tbody>',
            '</table>',
        ])
    
        return "\n".join(lines)

    ctx = _load_dashboard_context(year)
    asset_doc = _read_json(_asset_inventory_file(year), {})
    rows = _extract_asset_rows(asset_doc)

    grouped_rows: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped_rows[_get_subnet_name(row)].append(row)

    lines = [
        "# Asset Inventory",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Total Assets:** {len(rows)}",
        f"- **Total Subnets:** {len(grouped_rows)}",
        "",
        "## Asset Inventory Table",
        "",
    ]

    for subnet_name in sorted(grouped_rows.keys()):
        subnet_rows = grouped_rows[subnet_name]

        table_rows = []
        for row in subnet_rows:
            table_rows.append([
                _get_hostname(row),
                _get_ip_address(row),
                _get_role(row),
                _get_operating_system(row),
                _get_criticality(row),
                _safe_str(row.get("status")),
                _get_business_context(row),
            ])

        table = _md_table(
            [
                "Hostname",
                "IP Address",
                "Role",
                "Operating System",
                "CIA Rating",
                "Status",
                "Business Context",
            ],
            table_rows,
        )

        lines.extend([
            f"### Subnet: {subnet_name}",
            "",
            table,
            "",
        ])

    ml_detection_rows = []
    for row in rows:
        ml_detection_rows.append([
            _get_hostname(row),
            _get_indicator_role(row),
            _get_indicator_confidence(row),
            _get_ml_role(row),
            _get_ml_confidence(row),
            _get_selected_role(row),
            _get_selected_method(row),
        ])

    ml_detection_table = _build_grouped_header_table(ml_detection_rows)

    lines.extend([
        "## Asset Inventory ML-based Role Detection",
        "",
        ml_detection_table,
        "",
    
        "## Role Detection Methodology and Selection Approach",
        "",
        "### Overview",
        "The Asset Inventory system applies a hybrid role detection approach combining indicator-based analysis and machine learning (ML) prediction. This ensures both explainability and predictive capability, supporting consistent and auditable asset classification.",
        "",
    
        "### Indicator-Based Role Detection",
        "Indicator-based detection uses deterministic analysis of asset technical characteristics, including:",
        "- Open ports",
        "- Running services",
        "- Installed roles and software",
        "- Hostname patterns",
        "- Operating system attributes",
        "",
        "These indicators are matched against a predefined knowledge base of role signatures. The system normalizes and tokenizes these attributes, then calculates a matching score based on overlap between observed indicators and known role patterns.",
        "",
        "This method provides high interpretability and strong accuracy when clear technical indicators exist. Confidence is expressed using qualitative levels such as High and Very High.",
        "",
    
        "### ML-Based Role Detection",
        "The ML-based role detection approach uses supervised machine learning models trained on structured datasets representing enterprise asset roles.",
        "",
        "#### Role Taxonomy and Standards Alignment",
        "The system uses a role taxonomy aligned with industry standards, particularly NIST-based role definitions for enterprise infrastructure. Standard server roles such as Domain Controller, DNS Server, Web Server, and Database Server are derived from a NIST-aligned dataset.",
        "",
        "While the role definitions are based on NIST guidance, the training datasets themselves are not directly sourced from NIST. Instead, they are constructed using a combination of synthetic data and real operational data collected from the environment.",
        "",
        "#### Training Datasets",
        "The system maintains two separate training datasets:",
        "",
        "- **Server Role Dataset**: Contains labeled records of server assets based on NIST-aligned role taxonomy.",
        "- **Workstation Role Dataset**: Contains labeled records for endpoint systems, including user workstations and specialized endpoints.",
        "",
        "Each dataset includes features derived from:",
        "- Device profile (OS type, OS version, domain membership)",
        "- Technical indicators (open ports, running services, installed roles, installed software)",
        "- Business context (department, business function, business criticality)",
        "",
        "These datasets are stored in structured format and continuously updated as new validated assets are submitted into the system.",
        "",
        "#### Synthetic Data Initialization",
        "At the initial stage, the ML models are trained using synthetic data. This synthetic dataset is generated based on predefined mappings between:",
        "- Services and roles",
        "- Open ports and infrastructure functions",
        "- Installed software and system responsibilities",
        "",
        "The synthetic data is informed by industry best practices and standard role definitions (including NIST-aligned roles), but is generated within the system to bootstrap the learning process.",
        "",
        "The purpose of synthetic data is to:",
        "- Enable initial model training before real data is available",
        "- Provide baseline coverage of common enterprise roles",
        "- Ensure early-stage functionality of the system",
        "",
        "Synthetic records are explicitly tagged within the dataset to maintain traceability and separation from real data.",
        "",
        "#### Transition to Real Data",
        "As the system operates, real asset data is collected through the Asset Inventory process and validated prior to inclusion in the training datasets.",
        "",
        "Only assets that meet validation criteria (e.g., active status, valid role assignment) are converted into structured training records and appended to the datasets.",
        "",
        "Each record is tagged with its origin (synthetic or real), ensuring full traceability of data sources.",
        "",
        "#### Dataset Evolution and Data Source Management",
        "The training datasets evolve over time from synthetic-dominant to real-data-dominant:",
        "",
        "- Initial phase: Primarily synthetic data",
        "- Intermediate phase: Combination of synthetic and real data",
        "- Mature phase: Predominantly real data",
        "",
        "As real data accumulates, the influence of synthetic data decreases. Synthetic data can be reduced or removed entirely once sufficient real data is available, allowing the model to better reflect the actual enterprise environment.",
        "",
        "#### Model Training and Prediction",
        "The system uses a Random Forest classifier within a preprocessing pipeline that includes:",
        "- Feature transformation and encoding",
        "- Handling of categorical variables",
        "- Missing data imputation",
        "",
        "The model produces:",
        "- Predicted role",
        "- Confidence score (probability-based)",
        "",
        "This enables accurate role classification even when some indicators are incomplete or ambiguous.",
        "",
        "#### Continuous Learning",
        "The system supports continuous improvement through:",
        "- Incremental addition of real asset data",
        "- Periodic model retraining",
        "- Adaptation to changes in the enterprise environment",
        "",
        "This ensures that the ML-based role detection remains accurate, adaptive, and aligned with operational reality.",
        "",
    
        "### Role Selection Strategy",
        "The final role assigned to each asset is determined through a structured selection process:",
        "",
        "1. Confidence comparison between indicator-based and ML-based results",
        "2. Consideration of data completeness and indicator richness",
        "3. Consistency check between both methods",
        "",
        "If both methods agree, the role is accepted with high confidence. In case of disagreement:",
        "- The method with higher confidence is selected",
        "- Indicator-based results are preferred when strong deterministic evidence exists",
        "",
        "The selected role is stored along with the detection method (indicator or ml) to ensure traceability.",
        "",
    
        "### Compliance and Audit Considerations",
        "This hybrid approach ensures:",
        "- Traceability of decisions",
        "- Repeatable and consistent classification logic",
        "- Evidence-based role assignment",
        "- Auditability of intermediate and final results",
        "",
        "All detection results (indicator-based, ML-based, and selected role) are retained, enabling full transparency during audit review.",
        "",
    
        "### Conclusion",
        "The combination of deterministic and ML-based role detection provides a robust and scalable mechanism for asset classification. This supports accurate risk assessment and aligns with ISO/IEC 27001 requirements for asset management and control implementation.",
        "",
    ])

    return "\n".join(lines)