def build_annex_a_soa_markdown(year: int) -> str:
    from app.api.routes_final_deliverables import (
        _annex_a_soa_file,
        _annex_row_to_markdown_row,
        _extract_controls_rows,
        _load_dashboard_context,
        _md_table,
        _read_json,
    )

    ctx = _load_dashboard_context(year)
    doc = _read_json(_annex_a_soa_file(year), {})
    rows = _extract_controls_rows(doc)

    table = _md_table(
        ["Control ID", "Control Name", "Domain", "Applicable", "Implementation Status", "Justification"],
        [_annex_row_to_markdown_row(r) for r in rows],
    )

    methodology = """
## Justification and Control Recommendation Methodology

### 1. Overview
The Annex A & Statement of Applicability (SoA) is developed based on the results of the risk assessment process. Each control included in the SoA is supported by a clear justification that explains why the control is necessary in the context of identified risks, vulnerabilities, and business impact.

The methodology ensures that:
- All selected controls are risk-driven
- Justifications are evidence-based and auditable
- Recommendations are consistent with ISO/IEC 27001:2022 requirements

---

### 2. Justification Approach

The justification for each control is derived from:
- Identified vulnerabilities
- Associated risks
- Asset CIA ratings (Confidentiality, Integrity, Availability)
- Observed technical and operational weaknesses

Each justification:
- Explains why the control is required
- Describes the security weakness or gap
- Links the control to real risk conditions
- Focuses on exposure rather than generic statements

Typical weaknesses addressed include:
- Unpatched systems
- Weak authentication mechanisms
- Misconfigurations
- Excessive privileges
- Exposed services

---

### 3. Control Recommendation Approach

Controls are selected using a structured risk-based approach:

- Mapping vulnerabilities to appropriate control categories
- Evaluating applicability to asset roles and environments
- Prioritizing controls that reduce likelihood or impact

Examples:
- Authentication weaknesses → Authentication controls
- Privilege escalation risks → Privileged access controls
- Unpatched vulnerabilities → Vulnerability management controls
- Misconfigurations → Secure configuration controls
- Network exposure → Network security controls

---

### 4. Technologies Used

#### 4.1 Retrieval-Augmented Generation (RAG)
The system uses a Retrieval-Augmented Generation approach to ensure that control selection is grounded in ISO/IEC 27002 control knowledge.

Relevant controls are retrieved based on:
- Risk context
- Vulnerability characteristics
- Asset information

This ensures recommendations are accurate, explainable, and standards-aligned.

---

#### 4.2 Semantic Search and Embeddings
Risk and vulnerability descriptions are transformed into vector representations.

These are used to:
- Identify semantically similar controls
- Capture contextual meaning beyond keywords
- Improve matching accuracy

---

#### 4.3 Reasoning-Based Decision Layer
A reasoning layer evaluates retrieved controls and determines:

- Relevance to the risk context
- Applicability to the environment
- Strength of mitigation capability

This ensures that selected controls are logically aligned with identified risks.

---

#### 4.4 Machine Learning–Assisted Context
Machine learning enhances decision quality by providing:

- Asset role prediction
- CIA classification
- Risk probability estimation
- Exposure analysis

This allows more precise mapping between risks and controls.

---

#### 4.5 Hybrid Scoring Model
Control selection is based on:

- Semantic similarity
- Keyword relevance
- Domain-specific rules

This hybrid approach improves accuracy and consistency.

---

### 5. Auditability and Traceability

The process ensures:
- Traceability from risk to control
- Consistent justification across all controls
- Alignment with ISO/IEC 27001:2022
- Clear and structured outputs suitable for audit review

---

### 6. Outcome

The resulting Annex A & SoA:

- Reflects actual risk conditions
- Provides clear and defensible justifications
- Demonstrates a structured and repeatable methodology
- Supports audit and compliance requirements
"""

    lines = [
        "# Annex A & Statement of Applicability (SoA)",
        "",
        f"**Assessment Year:** {year}",
        f"**Scope:** {ctx['scope']['name']}",
        "",
        "## Summary",
        f"- **Total Controls:** {len(rows)}",
        "",
        "## Annex A & SoA",
        table,
        "",
        methodology,
        "",
    ]

    return "\n".join(lines)