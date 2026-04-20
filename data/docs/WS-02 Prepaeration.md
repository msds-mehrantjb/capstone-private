## 1. Enable Remote Desktop (Port 3389)

``` powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Start-Service TermService
```

## 2. Validate Open Ports

``` cmd
netstat -ano | findstr :3389
netstat -ano | findstr :135
```

Expected: - 3389 → LISTENING - 135 → LISTENING

## 3. Verify Required Services

``` powershell
Get-Service RpcEptMapper, msiserver, TermService | Select Name, Status, StartType
```

Expected: - RpcEptMapper → Running / Automatic - TermService → Running /
Manual - msiserver → Stopped / Manual

## 4. Create Fake Installed Software Entries

``` powershell
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Workday" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Workday" -Name "DisplayName" -Value "Workday" -PropertyType String -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MicrosoftOffice" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MicrosoftOffice" -Name "DisplayName" -Value "Microsoft Office" -PropertyType String -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\JavaRuntimeEnvironment" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\JavaRuntimeEnvironment" -Name "DisplayName" -Value "Java Runtime Environment" -PropertyType String -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Browser" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Browser" -Name "DisplayName" -Value "Browser" -PropertyType String -Force
```

## 5. Verify Installed Software

``` powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName | Where-Object { $_.DisplayName -ne $null }
```

Expected: - Workday - Microsoft Office - Java Runtime Environment -
Browser

## 6. Validate Security Controls

### Antivirus

``` powershell
Get-MpComputerStatus | Select AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
```

Expected: - All values = True

### 7.Firewall

``` powershell
Get-NetFirewallProfile | Select Name, Enabled
```

Expected: - Domain = True - Private = True - Public = True

### 8.Event Logging

``` powershell
Get-Service EventLog
```

Expected: - Status = Running

## 9. Validate Domain Membership

``` cmd
systeminfo | findstr /B /C:"Domain"
```

Expected: Domain: corp.local

## 10. Final Validation Commands

``` cmd
hostname
whoami
echo %logonserver%
ipconfig /all
```
