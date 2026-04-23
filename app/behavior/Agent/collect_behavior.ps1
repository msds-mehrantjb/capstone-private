    [CmdletBinding()]
    param(
        [string]$ConfigPath = "C:\ProgramData\BehaviorAgent\config.json"
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    function Write-Log {
        param([string]$Message)
        try {
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $line = "$timestamp $Message"
            Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
        } catch {
        }
    }

    function Ensure-Directory {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

function Read-JsonFile {
    param([string]$Path, $DefaultValue)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "DEBUG: Config file not found at $Path"
        return $DefaultValue
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        Write-Host "DEBUG: Raw JSON loaded successfully"

        $obj = $raw | ConvertFrom-Json
        Write-Host "DEBUG: JSON parsed successfully"

        return $obj
    } catch {
        Write-Host "DEBUG ERROR: $($_.Exception.Message)"
        throw   # 🔥 IMPORTANT: DO NOT SILENTLY RETURN
    }
}

    function Write-JsonFile {
        param(
            [string]$Path,
            [Parameter(Mandatory=$true)]$Object
        )
        $json = $Object | ConvertTo-Json -Depth 10
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    }

    function Get-PreviousDayWindow {
        $today = Get-Date
        $targetDate = $today.Date.AddDays(-1)
        $start = $targetDate
        $end = $targetDate.AddDays(1)
        return [PSCustomObject]@{
            TargetDate = $targetDate.ToString("yyyy-MM-dd")
            Start      = $start
            End        = $end
        }
    }

    function Convert-HexLogonIdToCanonical {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $v = $Value.Trim().ToLower()
        if ($v -notmatch "^0x") {
            try {
                $num = [UInt64]$v
                return ("0x{0:x}" -f $num)
            } catch {
                return $v
            }
        }
        return $v
    }

    function Get-EventDataMap {
        param($EventRecord)
        $map = @{}
        try {
            $xml = [xml]$EventRecord.ToXml()
            foreach ($d in $xml.Event.EventData.Data) {
                $name = [string]$d.Name
                $value = [string]$d.'#text'
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $map[$name] = $value
                }
            }
        } catch {
        }
        return $map
    }

    function Get-UserValueFrom4624 {
        param($DataMap)
        $domain = $DataMap["TargetDomainName"]
        $user = $DataMap["TargetUserName"]

        if ([string]::IsNullOrWhiteSpace($user)) {
            return $null
        }

        if ([string]::IsNullOrWhiteSpace($domain)) {
            return $user
        }

        return "$domain\$user"
    }

    function Get-SecurityEvents {
        param(
            [DateTime]$Start,
            [DateTime]$End,
            [int[]]$Ids
        )
        $filter = @{
            LogName   = 'Security'
            StartTime = $Start
            EndTime   = $End
            Id        = $Ids
        }
        try {
            return Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        } catch {
            Write-Log "ERROR reading Security log: $($_.Exception.Message)"
            return @()
        }
    }

    function Get-FailedLoginCount {
        param($Events4625)
        return @($Events4625).Count
    }

    function Get-SuccessfulLoginsDetailed {
        param($Events4624)

        $items = @()

        foreach ($e in $Events4624) {
            $data = Get-EventDataMap -EventRecord $e
            $logonType = $data["LogonType"]
            $targetUser = Get-UserValueFrom4624 -DataMap $data
            $logonId = Convert-HexLogonIdToCanonical -Value $data["TargetLogonId"]

            if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }

            $excludeUsers = @(
                "NT AUTHORITY\SYSTEM",
                "WINDOW MANAGER\DWM-1",
                "WINDOW MANAGER\DWM-2",
                "FONT DRIVER HOST\UMFD-0",
                "FONT DRIVER HOST\UMFD-1"
            )

            if ($excludeUsers -contains $targetUser.ToUpper()) { continue }

            $items += [PSCustomObject]@{
                TimeCreated = [DateTime]$e.TimeCreated
                User        = $targetUser
                LogonType   = [string]$logonType
                LogonId     = $logonId
                EventId     = 4624
            }
        }

        return $items
    }

    function Get-LogoutEventsDetailed {
        param($LogoutEvents)

        $items = @()

        foreach ($e in $LogoutEvents) {
            $data = Get-EventDataMap -EventRecord $e

            $possibleLogonId = $null
            foreach ($key in @("TargetLogonId","SubjectLogonId","LogonId")) {
                if ($data.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($data[$key])) {
                    $possibleLogonId = $data[$key]
                    break
                }
            }

            $items += [PSCustomObject]@{
                TimeCreated = [DateTime]$e.TimeCreated
                LogonId     = Convert-HexLogonIdToCanonical -Value $possibleLogonId
                EventId     = [int]$e.Id
            }
        }

        return $items
    }

    function Get-ModeUser {
        param($SuccessfulLogins)

        if (-not $SuccessfulLogins -or $SuccessfulLogins.Count -eq 0) {
            return "$env:COMPUTERNAME\$env:USERNAME"
        }

        $groups = $SuccessfulLogins | Group-Object User | Sort-Object Count -Descending
        return $groups[0].Name
    }

    function Get-AccessFrequency {
        param(
            [int]$SuccessfulLoginCount,
            [int]$Cap
        )
        if ($Cap -le 0) { return 0.0 }
        $v = [double]$SuccessfulLoginCount / [double]$Cap
        if ($v -gt 1.0) { $v = 1.0 }
        return [Math]::Round($v, 4)
    }

    function Get-LoginConsistency {
        param($SuccessfulLogins)

        if (-not $SuccessfulLogins -or $SuccessfulLogins.Count -eq 0) {
            return 0.0
        }

        if ($SuccessfulLogins.Count -eq 1) {
            return 1.0
        }

        $hours = @()
        foreach ($i in $SuccessfulLogins) {
            $hours += [double]$i.TimeCreated.Hour
        }

        $avg = ($hours | Measure-Object -Average).Average
        $sumSq = 0.0
        foreach ($h in $hours) {
            $sumSq += [Math]::Pow(($h - $avg), 2)
        }

        $variance = $sumSq / $hours.Count
        $stddev = [Math]::Sqrt($variance)

        $score = 1.0 - ($stddev / 12.0)
        if ($score -lt 0.0) { $score = 0.0 }
        if ($score -gt 1.0) { $score = 1.0 }

        return [Math]::Round($score, 4)
    }

    function Get-SessionDuration {
        param(
            $SuccessfulLogins,
            $LogoutEvents,
            [int]$CapMinutes
        )

        if (-not $SuccessfulLogins -or $SuccessfulLogins.Count -eq 0) {
            return 0.0
        }

        $logoutIndex = @{}
        foreach ($lo in $LogoutEvents | Sort-Object TimeCreated) {
            if ([string]::IsNullOrWhiteSpace($lo.LogonId)) { continue }
            if (-not $logoutIndex.ContainsKey($lo.LogonId)) {
                $logoutIndex[$lo.LogonId] = New-Object System.Collections.ArrayList
            }
            [void]$logoutIndex[$lo.LogonId].Add($lo)
        }

        $durations = @()

        foreach ($login in ($SuccessfulLogins | Sort-Object TimeCreated)) {
            if ([string]::IsNullOrWhiteSpace($login.LogonId)) { continue }
            if (-not $logoutIndex.ContainsKey($login.LogonId)) { continue }

            $candidateList = $logoutIndex[$login.LogonId]
            $matched = $null

            foreach ($lo in @($candidateList)) {
                if ($lo.TimeCreated -gt $login.TimeCreated) {
                    $matched = $lo
                    break
                }
            }

            if ($null -ne $matched) {
                $minutes = ($matched.TimeCreated - $login.TimeCreated).TotalMinutes
                if ($minutes -ge 0 -and $minutes -le 1440) {
                    $durations += [double]$minutes
                }
                [void]$candidateList.Remove($matched)
            }
        }

        if (-not $durations -or $durations.Count -eq 0) {
            return 0.0
        }

        $avgMinutes = ($durations | Measure-Object -Average).Average
        if ($CapMinutes -le 0) { return 0.0 }

        $score = [double]$avgMinutes / [double]$CapMinutes
        if ($score -gt 1.0) { $score = 1.0 }

        return [Math]::Round($score, 4)
    }

    function Update-BehaviorJsonRecord {
        param(
            [string]$JsonPath,
            [string]$Hostname,
            [string]$DateString,
            [string]$User,
            [hashtable]$DailyBehaviorSummary,
            [array]$Observations,
            [int]$RetentionDays
        )

        $defaultDoc = [PSCustomObject]@{
            records = @()
        }

        $doc = Read-JsonFile -Path $JsonPath -DefaultValue $defaultDoc
        if ($null -eq $doc.records) {
            $doc = [PSCustomObject]@{
                records = @()
            }
        }

	if ($doc.records -isnot [System.Collections.IEnumerable] -or $doc.records -is [string]) {
	    $doc.records = @($doc.records)
	}

        $records = @($doc.records)

        $existing = $records | Where-Object {
            $_.hostname -eq $Hostname -and $_.date -eq $DateString
        } | Select-Object -First 1

        if ($null -ne $existing) {
            $existing.user = $User
            $existing.dailyBehaviorSummary = [PSCustomObject]$DailyBehaviorSummary
            $existing.observations = @($Observations)
        } else {
            $records += [PSCustomObject]@{
                hostname = $Hostname
                date = $DateString
                user = $User
                dailyBehaviorSummary = [PSCustomObject]$DailyBehaviorSummary
                observations = @($Observations)
            }
        }

        $cutoff = (Get-Date).Date.AddDays(-1 * [Math]::Abs($RetentionDays))

        $filtered = @()
        foreach ($r in $records) {
            try {
                $recordDate = [DateTime]::ParseExact($r.date, "yyyy-MM-dd", $null)
                if ($recordDate -ge $cutoff) {
                    $filtered += $r
                }
            } catch {
            }
        }

	$finalDoc = [PSCustomObject]@{
	    records = @($filtered | Sort-Object hostname, date)
	}
        Write-JsonFile -Path $JsonPath -Object $finalDoc
    }

    try {
        $cfg = Read-JsonFile -Path $ConfigPath -DefaultValue $null
        if ($null -eq $cfg) {
            throw "Config file not found or invalid at $ConfigPath"
        }

        $agentRoot = $cfg.AgentRoot
        $jsonPath = $cfg.LocalJsonPath
        $script:LogPath = $cfg.LogPath
        $retentionDays = [int]$cfg.RetentionDays
        $successCap = [int]$cfg.SuccessfulLoginDailyCap
        $sessionCap = [int]$cfg.SessionDurationCapMinutes

        Ensure-Directory -Path $agentRoot
        Ensure-Directory -Path (Split-Path -Parent $script:LogPath)

        Write-Log "START collection"

        $window = Get-PreviousDayWindow
        $targetDate = $window.TargetDate
        $start = $window.Start
        $end = $window.End

        Write-Log "Collecting for target date $targetDate"

        $events4624 = Get-SecurityEvents -Start $start -End $end -Ids @(4624)
        $events4625 = Get-SecurityEvents -Start $start -End $end -Ids @(4625)
        $eventsPw = Get-SecurityEvents -Start $start -End $end -Ids @(4723,4724)
        $eventsLogout = Get-SecurityEvents -Start $start -End $end -Ids @(4634,4647)

        $successfulLogins = Get-SuccessfulLoginsDetailed -Events4624 $events4624
        $logoutEvents = Get-LogoutEventsDetailed -LogoutEvents $eventsLogout

        $failedLoginAttempts = Get-FailedLoginCount -Events4625 $events4625
        $successfulLoginCount = @($successfulLogins).Count
        $passwordResets = @($eventsPw).Count
        $user = Get-ModeUser -SuccessfulLogins $successfulLogins
        $accessFrequency = Get-AccessFrequency -SuccessfulLoginCount $successfulLoginCount -Cap $successCap
        $loginConsistency = Get-LoginConsistency -SuccessfulLogins $successfulLogins
        $sessionDuration = Get-SessionDuration -SuccessfulLogins $successfulLogins -LogoutEvents $logoutEvents -CapMinutes $sessionCap

        $summary = @{
            failedLoginAttempts = [int]$failedLoginAttempts
            successfulLoginCount = [int]$successfulLoginCount
            accessFrequency = [double]$accessFrequency
            loginConsistency = [double]$loginConsistency
            passwordResets = [int]$passwordResets
            sessionDuration = [double]$sessionDuration
        }

        $observations = @()

        Update-BehaviorJsonRecord `
            -JsonPath $jsonPath `
            -Hostname $env:COMPUTERNAME `
            -DateString $targetDate `
            -User $user `
            -DailyBehaviorSummary $summary `
            -Observations $observations `
            -RetentionDays $retentionDays

        Write-Log "SUCCESS wrote record for $($env:COMPUTERNAME) $targetDate"
    } catch {
        Write-Log "FATAL $($_.Exception.Message)"
        throw
    }
