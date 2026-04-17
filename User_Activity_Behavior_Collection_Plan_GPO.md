# User Activity Behavior Collection Plan for Workstations

## 1. Purpose

This document finalizes the **collection-layer plan** for the new **User Activity Behavior** risk type.

This plan covers only:

- daily behavior evidence collection on workstations
- local storage of summarized daily behavior
- central aggregation during the Risk Analysis process
- deployment of the collection agent by **GPO**
- creation of a **scheduled task** to gather evidence every day for the previous day

This document does **not** implement anything. It finalizes the design before implementation.

---

## 2. Scope

This collection design applies to:

- **all workstation assets**
- all workstation types in scope of the current system

This collection design does **not** apply to servers in Phase 1.

For servers:

```json
"user_behavior": {}
```

---

## 3. Final Collection Model

The collection process will use a **two-layer design**:

### Layer 1 — Local collection on each workstation
Each workstation runs a local behavior collection agent that:

- reads approved Windows evidence sources locally
- summarizes the previous day's activity
- writes one daily summarized record

### Layer 2 — Central aggregation during Risk Analysis
During the Risk Analysis process, the backend gathers the summarized workstation records and merges them into the central project file:

```text
data/work/2026/UserBehaviorActivity.json
```

This keeps:

- raw evidence collection local to the workstation
- summarized behavior data centralized for analysis
- risk processing separated from event parsing logic

---

## 4. Approved Windows Data Sources for WS-01 and Other Workstations

The local workstation collector should gather evidence from these Windows sources:

- Windows Security Event Log
- System Event Log
- PowerShell Operational Log
- Task Scheduler logs
- local group membership checks
- login and logout events
- account lockout events
- password change/reset events
- RDP logon events if used
- process creation logs if enabled
- removable media events if needed

### High-value event categories
The collector should be designed to derive evidence related to:

- successful logon
- failed logon
- account lockout
- password change
- privilege assignment
- process execution
- remote login events
- administrative group membership changes

---

## 5. Final Required Daily JSON Record

Only the approved Phase 1 fields are required.

### Required schema

```json
{
  "hostname": "WS-01",
  "date": "2026-04-11",
  "user": "CORP\\jdoe",
  "dailyBehaviorSummary": {
    "failedLoginAttempts": 0,
    "successfulLoginCount": 0,
    "accessFrequency": 0.0,
    "loginConsistency": 0.0,
    "passwordResets": 0,
    "sessionDuration": 0.0
  },
  "observations": []
}
```

### Explicit exclusion from Phase 1
The following fields are **not included** in the required schema:

- `offHoursLoginRate`
- `privilegeUseFrequency`
- `newSystemAccessCount`

---

## 6. Final Central JSON File Design

The central file should contain an array of daily records.

### Recommended central structure

```json
{
  "records": [
    {
      "hostname": "WS-01",
      "date": "2026-04-11",
      "user": "CORP\\jdoe",
      "dailyBehaviorSummary": {
        "failedLoginAttempts": 8,
        "successfulLoginCount": 14,
        "accessFrequency": 0.74,
        "loginConsistency": 0.42,
        "passwordResets": 2,
        "sessionDuration": 0.81
      },
      "observations": [
        "Multiple failed logons before successful access"
      ]
    }
  ]
}
```

### Record uniqueness rule

There must be only **one record per workstation per day**.

Natural key:

```text
hostname + date
```

If a record for the same workstation and date already exists, it must be updated rather than duplicated.

---

## 7. Best Storage Path Recommendation

### A. Local path on every workstation
The best local machine-level path is:

```text
C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json
```

### Why this is the best local path
- machine-wide location
- not tied to a user profile
- stable across logins
- appropriate for service or scheduled task output
- suitable for GPO-based deployment

### B. Central project path
The central aggregated file should be stored in the existing project working path:

```text
data/work/2026/UserBehaviorActivity.json
```

### Why this is the best central path
- consistent with the existing `data/work/<year>` model
- close to `RiskAnalysis.json`
- easy for the backend to access
- keeps behavior input and risk output in the same workspace

---

## 8. Final Deployment Method

The local workstation collection agent should be deployed to every workstation by **Group Policy Object (GPO)**.

### Final deployment design
Use GPO to:

- deploy the collector code to each workstation
- create the local working directory if missing
- create the scheduled task
- ensure the collector runs automatically every day

### Why GPO is the best deployment path
- centralized administration
- suitable for domain-joined Windows workstations
- consistent rollout to all workstations
- easy update and replacement of the agent code later
- easy auditability of deployment scope

---

## 9. Recommended GPO-Based Agent Distribution Design

The planned GPO deployment should do the following on every workstation:

### Step 1 — Copy agent files
Copy the collector package from a central network location to a local path such as:

```text
C:\ProgramData\BehaviorAgent\
```

Recommended contents:

```text
C:\ProgramData\BehaviorAgent\
    collect_behavior.ps1
    config.json
    logs\
    UserBehaviorActivity.json
```

### Step 2 — Ensure folder structure exists
The GPO deployment should create:

- `C:\ProgramData\BehaviorAgent\`
- `C:\ProgramData\BehaviorAgent\logs\`

### Step 3 — Register a scheduled task
The GPO deployment should create a scheduled task that runs daily.

### Step 4 — Run under an appropriate security context
The scheduled task should run under a controlled account with enough permissions to read the required local event logs and write the output file.

---

## 10. Final Scheduled Task Plan

A scheduled task must be created on every workstation to gather the evidence **every day for the previous day**.

### Final scheduling rule
The task runs once per day and summarizes evidence for:

```text
the last completed day
```

Example:
- task runs on `2026-04-12`
- collector summarizes activity for `2026-04-11`

### Why this is the best rule
- avoids partial-day collection noise
- gives a complete daily record
- produces stable and comparable daily summaries
- simplifies later scoring and validation

### Recommended task timing
Run the task during off-hours, such as early morning, after the previous day has fully completed.

Example planning choice:
- run daily at **01:00 AM** local time

This time is only a design recommendation and can be changed during implementation.

---

## 11. Final Information Gathering Flow on Each Workstation

The local agent on each workstation should follow this logic:

### Step 1
Determine the target collection date:

```text
yesterday
```

### Step 2
Read the approved Windows data sources for that date range only.

### Step 3
Calculate the Phase 1 daily summary fields:

- `failedLoginAttempts`
- `successfulLoginCount`
- `accessFrequency`
- `loginConsistency`
- `passwordResets`
- `sessionDuration`

### Step 4
Generate analyst-friendly observations.

### Step 5
Write or update the local JSON file at:

```text
C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json
```

### Step 6
Ensure only one record exists for:

```text
hostname + date
```

---

## 12. Final Meaning of Each Core Indicator

These meanings are locked for the design:

### `failedLoginAttempts`
Count of failed logon-related events for the target date.

Risk direction:
- higher = worse

### `successfulLoginCount`
Count of successful logon events for the target date.

Role in Phase 1:
- contextual support for analysis
- not one of the five behavior-scoring indicators, but retained in the daily summary

### `accessFrequency`
Daily access activity measure derived from successful access behavior.

Risk direction:
- stronger deviation from baseline = worse

### `loginConsistency`
Measure of stability and regularity of the user's logon pattern.

Risk direction:
- lower consistency = worse

### `passwordResets`
Count of password change or reset related events for the target date.

Risk direction:
- higher = worse

### `sessionDuration`
Measure of session behavior for the target date.

Risk direction:
- stronger deviation from expected behavior = worse

---

## 13. Final Local File Behavior

The workstation-local JSON file may contain multiple records over time, but only one per day per workstation.

### Recommended local structure

```json
{
  "records": [
    {
      "hostname": "WS-01",
      "date": "2026-04-11",
      "user": "CORP\\jdoe",
      "dailyBehaviorSummary": {
        "failedLoginAttempts": 8,
        "successfulLoginCount": 14,
        "accessFrequency": 0.74,
        "loginConsistency": 0.42,
        "passwordResets": 2,
        "sessionDuration": 0.81
      },
      "observations": [
        "Multiple failed logons before successful access"
      ]
    }
  ]
}
```

### Final local record rule
- append if the date does not exist
- update if the same `hostname + date` already exists
- never duplicate the same day for the same workstation

---

## 14. Final Central Aggregation During Risk Analysis

During Risk Analysis, the system should gather the summarized local workstation records and merge them into the central project file.

### Final Risk Analysis gathering flow

#### Step 1
Risk Analysis starts.

#### Step 2
For each workstation asset, the process checks whether the required daily summary record already exists in the central behavior file.

#### Step 3
If missing or outdated, the process collects the summarized local record from:

```text
C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json
```

#### Step 4
The process merges the record into the central file:

```text
data/work/2026/UserBehaviorActivity.json
```

#### Step 5
Risk Analysis then consumes the central behavior file and uses it to create the standalone **User Activity Behavior** vulnerability entry in `RiskAnalysis.json`.

### Important design rule
Risk Analysis gathers **summarized daily workstation records**, not raw Windows logs.

This keeps the Risk Analysis stage lightweight and clean.

---

## 15. Why This Architecture Is the Best Path

This design is the best path because it provides:

- local evidence collection where the logs actually exist
- centralized aggregation for analysis and history
- a clean separation between telemetry gathering and risk interpretation
- a domain-friendly deployment model through GPO
- repeatable daily evidence collection through a scheduled task
- future compatibility with weighted scoring first and ML later

---

## 16. Final Constraints

The following rules are now locked:

- deploy the workstation behavior collector by **GPO**
- create a **scheduled task** on every workstation
- the scheduled task gathers evidence **every day for the previous day**
- local workstation output path is:

```text
C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json
```

- central project aggregation path is:

```text
data/work/2026/UserBehaviorActivity.json
```

- only one record per workstation per date
- only the Phase 1 approved fields are required
- Risk Analysis gathers summarized records, not raw event logs
- servers remain:

```json
"user_behavior": {}
```

---

## 17. Final Locked Plan Summary

### Collection
- local behavior evidence gathered on each workstation
- summarized daily record only
- previous-day collection window

### Deployment
- deploy agent code by GPO
- create local directory by GPO
- register scheduled task by GPO

### Local storage
- `C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json`

### Central storage
- `data/work/2026/UserBehaviorActivity.json`

### Aggregation
- Risk Analysis gathers summarized workstation records
- merges records centrally
- then computes the standalone behavior vulnerability later

---

## 18. Final Recommendation

The best final design is:

- use **GPO** to deploy the local collection agent to all workstations
- use **Scheduled Task** via GPO to run once daily
- collect evidence for **the previous day**
- store local summaries in `C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json`
- aggregate all workstation summaries into `data/work/2026/UserBehaviorActivity.json` during Risk Analysis
- keep the collection layer strictly observational and separate from scoring and treatment

---

## 19. Scheduled Task Resilience (UPDATED - MANDATORY)

### Handling Workstations That Are Powered OFF

The scheduled task must be configured to handle cases where the workstation is OFF at the scheduled execution time.

### Required Behavior

If the workstation is OFF at the scheduled time (e.g., 01:00 AM):

- The task does NOT run at that time
- When the workstation powers ON later, the task MUST run automatically
- The task MUST still process the **previous day**

### Example Scenario

- Task scheduled: 01:00 AM (April 12)
- Workstation OFF at that time
- User logs in at 09:00 AM
- The task runs automatically at 09:00 AM
- The task processes data for: **April 11**

### Mandatory Configuration

The scheduled task MUST include:

- **Run task as soon as possible after a scheduled start is missed** → ENABLED

### Additional Required Trigger

Add a secondary trigger:

- **Run at system startup**

### Final Required Scheduled Task Configuration

Triggers:
- Daily at 01:00 AM
- At system startup

Settings:
- Run as soon as possible after missed start → ENABLED
- Do not run multiple instances in parallel
- Allow manual execution for testing

### Critical Design Rule

The collector MUST always process:

```text
the previous completed day
```

This ensures:
- no partial-day data
- consistent daily records
- correct behavior even with delayed execution

---

