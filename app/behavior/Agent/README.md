# Workstation Behavior Agent

`BehaviorAgent` is a Windows workstation-side PowerShell package that collects a
daily summary of user logon behavior from the local Security event log and
writes one JSON record per workstation day.

The central project-side behavior aggregator later reads those workstation files
over the admin share path built from the workstation hostname, the local system
drive share, and the configured local JSON output path.

## Package Files

- `collect_behavior.ps1` - Collects the previous day's Security log activity and writes the behavior summary JSON.
- `config.json` - Stores the local agent root, output file path, log path, task name, and collection settings.
- `install_behavior_agent.ps1` - Creates the local folders, copies the package files, and registers the scheduled task.
- `register_behavior_task.ps1` - Creates the scheduled task that runs the collector automatically.

## Installation Model

This package is intended to be distributed from a shared deployment source,
typically through GPO, so each workstation receives the same collector package
and registers the same scheduled task locally.

`install_behavior_agent.ps1` performs this flow:

1. Create the local agent root if it does not already exist.
2. Create the local log folder if it does not already exist.
3. Copy `collect_behavior.ps1`, `config.json`, and `register_behavior_task.ps1`
   into the local agent folder.
4. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <local agent root>\register_behavior_task.ps1
```

## Scheduled Task

Scheduling is handled by `register_behavior_task.ps1`.

- Task name: `BehaviorAgent-DailyCollection`
- Command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<local agent root>\collect_behavior.ps1"
```

- Triggers:
  - Daily at `01:00 AM`
  - At system startup
- Security context:
  - User: `SYSTEM`
  - Logon type: `ServiceAccount`
  - Privilege level: `Highest`

The task is configured to start when available, tolerate battery power, ignore
parallel duplicate runs, and allow up to one hour for execution.

## What The Agent Collects

`collect_behavior.ps1` reads the local Windows Security log for the previous
day only, using this time window:

- Start: yesterday `00:00:00`
- End: today `00:00:00`

It summarizes these event IDs:

- `4624` - successful logon
- `4625` - failed logon
- `4723` - attempt to change password
- `4724` - attempt to reset password
- `4634` - logoff
- `4647` - user-initiated logoff

For each workstation-day, the agent writes a record with:

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

## Configuration Defaults

The current `config.json` defaults are:

- Agent root: `C:\ProgramData\BehaviorAgent`
- Output JSON: `C:\ProgramData\BehaviorAgent\UserBehaviorActivity.json`
- Log path: `C:\ProgramData\BehaviorAgent\logs\collect_behavior.log`
- Retention days: `30`
- Task name: `BehaviorAgent-DailyCollection`
- Task time: `01:00`
- Output date mode: `PreviousDay`

Review configuration, task permissions, and endpoint deployment policy before
installing this package on any Windows workstation.
