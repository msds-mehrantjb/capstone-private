def build_risk_register_markdown(year: int) -> str:
    from collections import OrderedDict

    from app.api.routes_final_deliverables import (
        _extract_risk_rows,
        _escape_md,
        _load_dashboard_context,
        _read_json,
        _risk_analysis_file,
        _risk_evaluation_treatment_file,
    )

    def _as_list(value):
        if isinstance(value, list):
            return value
        if value in (None, "", "NA"):
            return []
        return [value]

    def _to_text(value, default="NA"):
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default

    def _yes_no(value):
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, str):
            v = value.strip().lower()
            if v in {"true", "yes", "y", "1"}:
                return "Yes"
            if v in {"false", "no", "n", "0"}:
                return "No"
        return "NA"

    def _make_html_table(headers, rows):
        if not rows:
            return "<p><em>No data available.</em></p>"

        header_cells = "".join(
            f'<th style="text-align:left; border:1px solid #cbd5e1; padding:8px; background-color:#f3f4f6;">{_escape_md(h)}</th>'
            for h in headers
        )

        body_rows = []
        for row in rows:
            normalized = list(row) + [""] * (len(headers) - len(row))
            cells = "".join(
                f'<td style="text-align:left; border:1px solid #cbd5e1; padding:8px;">{_escape_md(v)}</td>'
                for v in normalized[: len(headers)]
            )
            body_rows.append(f"<tr>{cells}</tr>")

        return f"""
<table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px; margin-bottom:20px;">
    <thead>
        <tr>{header_cells}</tr>
    </thead>
    <tbody>
        {''.join(body_rows)}
    </tbody>
</table>
"""

    def _make_group_table_html(hostname, role, rows, headers, host_span=1):
        def td(v):
            return f'<td style="padding: 8px; border: 1px solid #999; vertical-align: top;">{_escape_md(v)}</td>'
    
        header_cells = "".join(
            f'<th style="background-color: #eef5fb; padding: 8px; border: 1px solid #999; text-align: left;">{_escape_md(h)}</th>'
            for h in headers
        )
    
        body_rows = "".join(
            "<tr>" + "".join(td(v) for v in row) + "</tr>"
            for row in rows
        )
    
        col_count = len(headers)
        host_span = max(1, min(host_span, col_count))
        role_span = max(1, col_count - host_span)
    
        return f"""
<table style="border-collapse: collapse; width: 100%;">
    <thead>
        <tr>
            <th colspan="{host_span}" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">
                Host: {_escape_md(hostname)}
            </th>
            <th colspan="{role_span}" style="background-color: #d9eaf7; padding: 8px; border: 1px solid #999; text-align: left; font-weight: bold;">
                Role: {_escape_md(role)}
            </th>
        </tr>
        <tr>
            {header_cells}
        </tr>
    </thead>
    <tbody>
        {body_rows}
    </tbody>
</table>
"""

    ctx = _load_dashboard_context(year)
    doc = _read_json(_risk_analysis_file(year), {})
    rows = _extract_risk_rows(doc)

    if not rows:
        doc = _read_json(_risk_evaluation_treatment_file(year), {})
        rows = _extract_risk_rows(doc)

    register_headers = ["Vulnerabilities", "CVE ID", "Exploit", "Likelihood", "Impact", "Risk"]
    analysis_headers = [
        "Vulnerability",
        "CVE ID",
        "CVSS Score",
        "Likelihood Score",
        "Risk Score",
        "Exposure",
        "ML Probability",
    ]

    register_grouped = OrderedDict()
    analysis_grouped = OrderedDict()

    for row in rows:
        hostname = row.get("hostname", row.get("host", row.get("name", "NA")))
        role = row.get("role", row.get("predicted_role", row.get("asset", "NA")))
        key = (_to_text(hostname), _to_text(role))

        if key not in register_grouped:
            register_grouped[key] = []
        if key not in analysis_grouped:
            analysis_grouped[key] = []

        vulnerabilities = _as_list(row.get("vulnerability_name"))
        if not vulnerabilities:
            vulnerabilities = _as_list(row.get("vulnerability"))
        if not vulnerabilities:
            vulnerabilities = ["NA"]

        cves = _as_list(row.get("cve"))
        if not cves:
            cves = ["NA"]

        exploit_value = _yes_no(row.get("exploit_available"))
        likelihood = _to_text(row.get("likelihood", row.get("Likelihood", "NA")))
        impact = _to_text(row.get("impact", row.get("CIA rating", "NA")))
        risk = _to_text(row.get("risk", row.get("risk_level", "NA")))

        cvss_score = _to_text(row.get("cvss_score"))
        likelihood_score = _to_text(row.get("likelihood_score"))
        risk_score = _to_text(row.get("risk_score"))
        exposure = _to_text(row.get("exposure"))
        ml_probability = _to_text(row.get("ml_probability"))

        max_len = max(len(vulnerabilities), len(cves))
        vulnerabilities = vulnerabilities + [""] * (max_len - len(vulnerabilities))
        cves = cves + [""] * (max_len - len(cves))

        for vuln, cve in zip(vulnerabilities, cves):
            vuln_text = _to_text(vuln, "NA")
            cve_text = _to_text(cve, "NA")

            register_grouped[key].append([
                vuln_text,
                cve_text,
                exploit_value,
                likelihood,
                impact,
                risk,
            ])

            analysis_grouped[key].append([
                vuln_text,
                cve_text,
                cvss_score,
                likelihood_score,
                risk_score,
                exposure,
                ml_probability,
            ])

    register_sections = []
    analysis_sections = []
    total_records = 0

    # Host spans only first column so Role starts above CVE ID
    for (hostname, role), group_rows in register_grouped.items():
        total_records += len(group_rows)
        register_sections.append(
            _make_group_table_html(
                hostname,
                role,
                group_rows,
                register_headers,
                host_span=1,
            )
        )

    # Keep same style for risk analysis
    for (hostname, role), group_rows in analysis_grouped.items():
        analysis_sections.append(
            _make_group_table_html(
                hostname,
                role,
                group_rows,
                analysis_headers,
                host_span=1,
            )
        )

    methodology_html = """
<div class="methodology-section">

<style>
.methodology-section table th,
.methodology-section table td {
    text-align: left !important;
    vertical-align: top !important;
}
</style>

<h2>Risk Computation Methodology</h2>

<h3>1. Overview</h3>
<p>
The risk computation model implemented in this system follows the principles of NIST SP 800-30,
where risk is determined as a function of:
</p>

<ul>
    <li><strong>Likelihood</strong> – probability of a threat exploiting a vulnerability</li>
    <li><strong>Impact</strong> – consequence of the event based on asset criticality</li>
</ul>

<p>
The system enhances the traditional model by integrating contextual factors and
machine learning–based probability:
</p>

<p><strong>Risk = (Likelihood × Impact) × (1 + ML Probability)</strong></p>

<h3>2. Likelihood Computation</h3>

<h4>2.1 Likelihood Formula</h4>
<pre style="white-space:pre-wrap; font-family:Arial, sans-serif;">
Likelihood Score =
    (0.20 × CVSS)
  + (0.35 × Exploit Availability)
  + (0.15 × Patch Status)
  + (0.15 × Exposure)
  + (0.10 × Asset Role)
  + (0.05 × CIA Rating)

Final Likelihood = Likelihood Score × (1 + ML Probability)
</pre>

<p>The likelihood score is normalized to the range:</p>
<p><strong>0.0 → 1.0</strong></p>

<h4>2.2 Sources of Likelihood Components</h4>

<p><strong>CVSS Score</strong></p>
<ul>
    <li>Source: Vulnerability data</li>
    <li>Normalized from 0–10 to 0–1</li>
    <li>Represents intrinsic technical severity</li>
</ul>

<p><strong>Exploit Availability</strong></p>
<ul>
    <li>Indicates whether a public exploit exists</li>
    <li>Values:
        <ul>
            <li>Yes → 0.60</li>
            <li>No → 0.10</li>
        </ul>
    </li>
</ul>

<p><strong>Patch Status</strong></p>
<ul>
    <li>Derived from patch management controls</li>
    <li>Reflects how exposed the vulnerability is</li>
</ul>

<p><strong>Exposure</strong></p>
<p>Exposure is dynamically inferred using:</p>
<ul>
    <li>IP address type (internal vs external)</li>
    <li>Number of open ports</li>
    <li>Presence of critical ports (e.g., 445, 3389, 80, 443)</li>
    <li>Asset role (e.g., web server, domain controller)</li>
    <li>ML probability (minor influence)</li>
</ul>

<p>Output levels:</p>
<p><strong>Very Low / Low / Medium / High / Critical</strong></p>

<p>Mapped to normalized values:</p>
<ul>
    <li>Very Low = 0.05</li>
    <li>Low = 0.25</li>
    <li>Medium = 0.50</li>
    <li>High = 0.70</li>
    <li>Critical = 1.00</li>
</ul>

<p><strong>Asset Role</strong></p>
<p>Examples:</p>
<ul>
    <li>Domain Controller → 0.90</li>
    <li>Web Server → 0.60</li>
    <li>Workstation → 0.35</li>
</ul>

<p>Represents asset attractiveness and importance to attackers.</p>

<p><strong>CIA Rating</strong></p>
<p>Derived from the Asset Inventory &amp; CIA module:</p>
<ul>
    <li>Critical → 1.00</li>
    <li>High → 0.80</li>
    <li>Medium → 0.50</li>
    <li>Low → 0.20</li>
</ul>

<h3>3. Likelihood Classification</h3>
<table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px; margin-bottom:20px;">
    <thead>
        <tr style="background-color:#f3f4f6; font-weight:bold;">
            <th style="border:1px solid #cbd5e1; padding:8px;">Score</th>
            <th style="border:1px solid #cbd5e1; padding:8px;">Level</th>
        </tr>
    </thead>
    <tbody>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 0.90</td><td style="border:1px solid #cbd5e1; padding:8px;">Critical</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 0.80</td><td style="border:1px solid #cbd5e1; padding:8px;">High</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 0.55</td><td style="border:1px solid #cbd5e1; padding:8px;">Medium</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">&lt; 0.55</td><td style="border:1px solid #cbd5e1; padding:8px;">Low</td></tr>
    </tbody>
</table>

<h3>4. Risk Score Computation</h3>

<h4>4.1 Formula</h4>
<p><strong>Risk Score = CIA Weight × Likelihood Score × (1 + ML Probability)</strong></p>

<p>Where:</p>
<p><strong>CIA Weight:</strong></p>
<ul>
    <li>Critical → 9</li>
    <li>High → 8</li>
    <li>Medium → 6</li>
    <li>Low → 3</li>
</ul>

<h4>4.2 Risk Classification</h4>
<table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px; margin-bottom:20px;">
    <thead>
        <tr style="background-color:#f3f4f6; font-weight:bold;">
            <th style="border:1px solid #cbd5e1; padding:8px;">Score</th>
            <th style="border:1px solid #cbd5e1; padding:8px;">Level</th>
        </tr>
    </thead>
    <tbody>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 15</td><td style="border:1px solid #cbd5e1; padding:8px;">Critical</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 10</td><td style="border:1px solid #cbd5e1; padding:8px;">High</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">≥ 6</td><td style="border:1px solid #cbd5e1; padding:8px;">Medium</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">&lt; 6</td><td style="border:1px solid #cbd5e1; padding:8px;">Low</td></tr>
    </tbody>
</table>

<h3>5. Exposure Definition</h3>
<p>Exposure represents how accessible an asset is to attackers.</p>

<p>It is computed using:</p>
<ul>
    <li>Network exposure (internal vs external IP)</li>
    <li>Open ports and critical services</li>
    <li>Asset role</li>
    <li>Behavioral indicators</li>
</ul>

<p>This value directly influences likelihood.</p>

<h2>Machine Learning–Based Risk Enhancement</h2>

<h3>6. ML Model Overview</h3>
<p>
The system incorporates a machine learning component to dynamically adjust risk.
</p>

<p><strong>Model Used:</strong><br>
Random Forest Classifier</p>

<p>This model is chosen for:</p>
<ul>
    <li>High accuracy on structured data</li>
    <li>Robustness to noise</li>
    <li>Ability to model non-linear relationships</li>
    <li>Feature importance interpretability</li>
</ul>

<h3>7. Training Dataset</h3>
<p>The model is trained using:</p>
<p><strong>user_behavior_training_dataset.parquet</strong></p>

<p><strong>Features:</strong></p>
<ul>
    <li>failedLoginAttempts</li>
    <li>accessFrequency</li>
    <li>loginConsistency</li>
    <li>passwordResets</li>
    <li>sessionDuration</li>
</ul>

<p><strong>Target:</strong></p>
<p>risk_level (Low / Medium / High / Critical)</p>

<h3>8. ML Pipeline</h3>
<p>The ML pipeline includes:</p>
<ul>
    <li>Data preprocessing (missing value imputation)</li>
    <li>Label encoding of risk levels</li>
    <li>Train/test split (80/20, stratified)</li>
    <li>Model training using Random Forest</li>
    <li>Probability prediction using class probabilities</li>
</ul>

<h3>9. ML Probability Definition</h3>
<p><strong>ML Probability = Maximum predicted class probability</strong></p>

<p>Range:</p>
<p><strong>0.0 → 1.0</strong></p>

<table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px; margin-bottom:20px;">
    <thead>
        <tr style="background-color:#f3f4f6; font-weight:bold;">
            <th style="border:1px solid #cbd5e1; padding:8px;">ML Probability</th>
            <th style="border:1px solid #cbd5e1; padding:8px;">Interpretation</th>
        </tr>
    </thead>
    <tbody>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">0.20</td><td style="border:1px solid #cbd5e1; padding:8px;">Low confidence</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">0.50</td><td style="border:1px solid #cbd5e1; padding:8px;">Moderate confidence</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">0.90</td><td style="border:1px solid #cbd5e1; padding:8px;">High confidence</td></tr>
    </tbody>
</table>

<h3>10. Role of ML in Risk Computation</h3>

<p><strong>Likelihood Adjustment</strong></p>
<p>Likelihood = Base Likelihood × (1 + ML Probability)</p>

<p><strong>Risk Adjustment</strong></p>
<p>Risk Score = Base Risk × (1 + ML Probability)</p>

<p><strong>Default Behavior</strong></p>
<p>If ML output is not available:</p>
<p><strong>ML Probability = 0.30</strong></p>

<p>This ensures moderate influence without biasing results.</p>

<h3>11. Alignment with NIST Risk Model</h3>
<table style="border-collapse:collapse; width:100%; font-family:Arial, sans-serif; font-size:13px; margin-bottom:20px;">
    <thead>
        <tr style="background-color:#f3f4f6; font-weight:bold;">
            <th style="border:1px solid #cbd5e1; padding:8px;">NIST Concept</th>
            <th style="border:1px solid #cbd5e1; padding:8px;">Implementation</th>
        </tr>
    </thead>
    <tbody>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Threat Likelihood</td><td style="border:1px solid #cbd5e1; padding:8px;">CVSS + Exploit + Exposure</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Vulnerability</td><td style="border:1px solid #cbd5e1; padding:8px;">Patch Status</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Predisposing Conditions</td><td style="border:1px solid #cbd5e1; padding:8px;">Role + Open Ports</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Impact</td><td style="border:1px solid #cbd5e1; padding:8px;">CIA Rating</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Risk Determination</td><td style="border:1px solid #cbd5e1; padding:8px;">Likelihood × Impact</td></tr>
        <tr><td style="border:1px solid #cbd5e1; padding:8px;">Threat Intelligence</td><td style="border:1px solid #cbd5e1; padding:8px;">ML Probability</td></tr>
    </tbody>
</table>

<h3>12. Summary</h3>
<p>
This risk computation approach extends traditional risk assessment by integrating:
</p>
<ul>
    <li>Technical severity (CVSS)</li>
    <li>Real-world exploitability</li>
    <li>Environmental exposure</li>
    <li>Asset criticality (CIA)</li>
    <li>Control effectiveness (patching)</li>
    <li>Machine learning–driven probability</li>
</ul>

<p>Result:</p>
<p><strong>A dynamic, adaptive, and context-aware risk scoring model</strong></p>

</div>
"""
    html = f"""
<h1>Risk Register</h1>

<p><strong>Assessment Year:</strong> {year}<br>
<strong>Scope:</strong> {_escape_md(ctx['scope']['name'])}</p>

<h2>Summary</h2>
<ul>
    <li><strong>Total Risk Records:</strong> {total_records}</li>
    <li><strong>Total Hosts:</strong> {len(register_grouped)}</li>
</ul>

<h2>Risk Register</h2>
{''.join(register_sections)}

<h2>Risk Analysis</h2>
{''.join(analysis_sections) if analysis_sections else "<p><em>No data available.</em></p>"}

{methodology_html}
"""

    return html