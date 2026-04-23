    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    $taskName = "BehaviorAgent-DailyCollection"
    $agentRoot = "C:\ProgramData\BehaviorAgent"
    $scriptPath = Join-Path $agentRoot "collect_behavior.ps1"

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Collector script not found at $scriptPath"
    }

    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    $dailyTrigger = New-ScheduledTaskTrigger -Daily -At 1:00AM
    $startupTrigger = New-ScheduledTaskTrigger -AtStartup

    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Trigger @($dailyTrigger, $startupTrigger) `
        -Settings $settings

    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
