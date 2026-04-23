    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    $sourceRoot = "\\SRV-01\SYSVOL\corp.local\scripts\BehaviorAgent"
    $targetRoot = "C:\ProgramData\BehaviorAgent"
    $targetLogRoot = Join-Path $targetRoot "logs"

    if (-not (Test-Path -LiteralPath $targetRoot)) {
        New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $targetLogRoot)) {
        New-Item -ItemType Directory -Path $targetLogRoot -Force | Out-Null
    }

    Copy-Item -Path (Join-Path $sourceRoot "collect_behavior.ps1") -Destination (Join-Path $targetRoot "collect_behavior.ps1") -Force
    Copy-Item -Path (Join-Path $sourceRoot "config.json") -Destination (Join-Path $targetRoot "config.json") -Force
    Copy-Item -Path (Join-Path $sourceRoot "register_behavior_task.ps1") -Destination (Join-Path $targetRoot "register_behavior_task.ps1") -Force

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $targetRoot "register_behavior_task.ps1")
