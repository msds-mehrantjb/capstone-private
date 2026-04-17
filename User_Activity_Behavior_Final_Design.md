# User Activity Behavior Risk Type – Final Design Specification

## 1. Overview
User Activity Behavior is introduced as a standalone vulnerability type that applies to all workstation assets. It influences likelihood only, while CIA ratings determine impact.

---

## 2. Scope
- Applies to: ALL workstation assets
- Servers: user_behavior = {}

---

## 3. Risk Model
- Behavior → Likelihood
- CIA → Impact
- Risk = Likelihood × Impact

---

## 4. Indicators (Core Only)
- failedLoginAttempts
- accessFrequency
- loginConsistency
- passwordResets
- sessionDuration

---

## 5. Weighted Scoring Formula

BehaviorRiskScore =
(0.15 × failedLoginScore) +
(0.30 × accessAnomalyScore) +
(0.10 × loginVarianceScore) +
(0.20 × passwordResetScore) +
(0.25 × sessionAnomalyScore)

---

## 6. Likelihood Mapping (Use Existing System)
Use current likelihood scoring system.

---

## 7. JSON Schema

### Workstation Entry
{
  "hostname": "",
  "ip_address": "",
  "role": "",
  "CIA rating": "",
  "vulnerability_name": "User Activity Behavior",
  "severity": "",
  "cvss_score": 0.0,
  "exploit_available": "",
  "patch_status": 0,
  cve": "",
  "open_ports": [],
  "override": 0,
  "likelihood": "",
  "risk": "",
  "likelihood_score": 0.0,
  "risk_score": 0.0,
  "exposure": "",
  "user_behavior": {
    "failedLoginAttempts": 0,
    "accessFrequency": 0.0,
    "loginConsistency": 0.0,
    "passwordResets": 0,
    "sessionDuration": 0.0,
    "behaviorRiskScore": 0.0,
    "rule_score": 0.0,
    "ml_score": 0.0,
    "likelihood": ""
  }
}

### Server Entry
"user_behavior": {}

---

## 8. Source of Truth

- UserBehaviorActivity.json → raw observations
- RiskAnalysis.json → computed risk results

---

## 9. ML Model

Model:
- Random Forest (based on existing system)

Features:
- failedLoginAttempts
- accessFrequency
- loginConsistency
- passwordResets
- sessionDuration

Target:
- risk_level

Final (future):
FinalBehaviorScore =
(0.60 × RuleScore) +
(0.40 × MLScore)

---

## 10. Constraints

- Always create behavior vulnerability for workstations
- No threat/control mapping in Risk Analysis
- No impact modification by behavior

---

## 11. Final Architecture Flow

1. Collect behavior → UserBehaviorActivity.json
2. Compute behavior score
3. Map to likelihood
4. Inject into RiskAnalysis.json
5. Compute final risk

---

## 12. Final Notes

- Standalone vulnerability
- Fully auditable
- Expandable with ML later
