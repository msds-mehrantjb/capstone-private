# BehaviorAgent Technical Document

## Overview

`BehaviorAgent` is a Windows workstation-side PowerShell agent that collects a daily summary of user logon behavior from the local Security event log and stores the result as a JSON record on the workstation.

The agent writes to the configured local behavior JSON file and is intended to be deployed from the organization’s shared deployment location.

The central project-side aggregator later reads those workstation files over an admin share by combining:

- the workstation host
- the local system drive share
- the configured local behavior JSON path

---

## Files

The agent package currently contains:

- `collect_behavior.ps1`
- `config.json`
- `install_behavior_agent.ps1`
- `register_behavior_task.ps1`

---

## Installation

### Installation model

The installer script uses:

- a shared deployment source
- a configured local agent root
- a configured local log folder

### Installation flow

The installation is performed by `install_behavior_agent.ps1`.

It does the following:

1. Creates the local agent root if it does not exist.
2. Creates the local log folder if it does not exist.
3. Copies these files from the shared deployment source into the local target folder:
   - `collect_behavior.ps1`
   - `config.json`
   - `register_behavior_task.ps1`
4. Runs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <local agent root>\register_behavior_task.ps1
```

### Practical deployment model

This script is intended to be distributed through GPO so every workstation receives the same collector package from the shared deployment source and registers the same scheduled task locally.

---

## Scheduling

Scheduling is handled by `register_behavior_task.ps1`.

### Task name

`BehaviorAgent-DailyCollection`

### Execution command

The scheduled task runs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<local agent root>\collect_behavior.ps1"
```

### Triggers

The task has two triggers:

1. Daily at `01:00 AM`
2. At system startup

### Security context

The task runs as:

- user: `SYSTEM`
- logon type: `ServiceAccount`
- privilege level: `Highest`

### Task settings

The scheduled task is configured with:

- `StartWhenAvailable`
- `AllowStartIfOnBatteries`
- `DontStopIfGoingOnBatteries`
- `MultipleInstances IgnoreNew`
- execution time limit: `1 hour`

This means the agent is designed to:

- run every day on schedule
- run after startup if the workstation was offline during the scheduled time
- avoid parallel duplicate runs

---

## What the agent collects

The collection logic is implemented in `collect_behavior.ps1`.

The agent reads the local Windows Security log for the **previous day** only.

### Time window

The collector computes:

- target date = yesterday
- start = yesterday `00:00:00`
- end = today `00:00:00`

So each run summarizes one complete previous day.

### Event IDs used

The script collects these Security log event IDs:

- `4624` -> successful logon
- `4625` -> failed logon
- `4723` -> attempt to change password
- `4724` -> attempt to reset password
- `4634` -> logoff
- `4647` -> user-initiated logoff

### Output fields

For each workstation and target day, the agent writes one record with:

- `hostname`
- `date`
- `user`
- `dailyBehaviorSummary`
  - `failedLoginAttempts`
  - `successfulLoginCount`
  - `accessFrequency`
  - `loginConsistency`
  - `passwordResets`
  - `sessionDuration`
- `observations`

### Output location

The local workstation output file is defined in `config.json` through the `LocalJsonPath` setting.

---

## How each metric is computed

### 1. Failed login attempts

Source:

- count of Security events `4625`

Method:

- direct event count for the previous day

### 2. Successful login count

Source:

- Security events `4624`

Method:

- counts filtered successful logon events after excluding system/service-style users such as:
  - `NT AUTHORITY\SYSTEM`
  - `WINDOW MANAGER\DWM-*`
  - `FONT DRIVER HOST\UMFD-*`

### 3. User

Method:

- from the filtered successful logons, the script groups by `domain\username`
- the most frequent user becomes the record’s `user`
- if there are no successful logons, fallback is:

`<COMPUTERNAME>\<USERNAME>`

### 4. Access frequency

Method:

- `successfulLoginCount / SuccessfulLoginDailyCap`
- rounded to 4 decimals
- capped at `1.0`

Configured cap:

- `SuccessfulLoginDailyCap = 20`

Interpretation:

- this is a normalized login-frequency score, not a raw login count

### 5. Login consistency

Method:

- extracts the hour-of-day from each successful logon
- computes variance and standard deviation of login hours
- computes:

`1.0 - (stddev / 12.0)`

- clamps result to `0.0..1.0`
- rounds to 4 decimals

Interpretation:

- higher value means more consistent login timing
- lower value means more variable login timing

### 6. Password resets

Method:

- count of Security events `4723` and `4724`

### 7. Session duration

Method:

1. Build successful logon sessions from `4624`
2. Build logout events from `4634` and `4647`
3. Match login and logout by `LogonId`
4. Compute session duration in minutes
5. Ignore durations outside `0..1440` minutes
6. Average the matched session durations
7. Normalize by `SessionDurationCapMinutes`
8. Cap at `1.0`

Configured cap:

- `SessionDurationCapMinutes = 480`

Interpretation:

- this is a normalized session-duration score, not raw minutes

---

## JSON update behavior

The collector updates the local JSON through `Update-BehaviorJsonRecord`.

### Record uniqueness

Only one record is kept per:

- `hostname`
- `date`

If a record for the same host and date already exists, it is updated in place.

### Retention

Old records are removed using:

- `RetentionDays = 30`

Only records newer than the retention cutoff are kept.

### Final JSON structure

The file format is:

```json
{
  "records": [
    {
      "hostname": "WS-01",
      "date": "2026-04-13",
      "user": "CORP\\Administrator",
      "dailyBehaviorSummary": {
        "failedLoginAttempts": 1,
        "successfulLoginCount": 67,
        "accessFrequency": 1.0,
        "loginConsistency": 0.8013,
        "passwordResets": 0,
        "sessionDuration": 0.0012
      },
      "observations": []
    }
  ]
}
```

---

## Logging and error handling

The agent writes to the configured collector log path defined in `config.json`.

The collector logs:

- start of collection
- target date
- Security log read errors
- successful record write
- fatal exceptions

If the config file is missing or invalid, or if the collector encounters a fatal error, the script throws and the scheduled task run should fail visibly in Task Scheduler history.

---

## Configurable settings

Current settings in `config.json`:

- `AgentRoot`
- `LocalJsonPath`
- `LogPath`
- `RetentionDays = 30`
- `SuccessfulLoginDailyCap = 20`
- `SessionDurationCapMinutes = 480`
- `TaskName = BehaviorAgent-DailyCollection`
- `TaskTime = 01:00`
- `Domain`
- `OutputDateMode = PreviousDay`

---

## Central integration with the Capstone app

After workstation-side collection:

1. Each workstation stores its local behavior summary in the configured local behavior JSON file.
2. The project-side aggregator in `aggregate_user_behavior.py` reads those files over admin shares.
3. The aggregator merges them into the central user behavior activity dataset.
4. Risk Analysis reads that central file and converts the latest record per workstation into the `User Activity Behavior` risk row.

---

## Operational summary

In plain technical terms, this agent:

- is deployed from a shared central source
- installs to the configured local agent root
- registers a scheduled task running as `SYSTEM`
- runs daily and at startup
- summarizes the previous day’s Security log activity
- writes one workstation/day JSON record
- retains 30 days of local history
- feeds the central Risk Analysis workflow through the aggregation step
