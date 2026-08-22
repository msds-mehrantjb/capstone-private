[CmdletBinding()]
param(
    [switch]$IncludeMissing
)

$ErrorActionPreference = "Stop"

$labContainers = @(
    "gateway",
    "srv_01",
    "srv_02",
    "srv_03",
    "srv_04",
    "ws_01",
    "ws_02",
    "ws_03",
    "ws_04",
    "ws_05",
    "ws_06"
)

$labNetworks = @(
    [PSCustomObject]@{
        Name = "docker_lab_subnet_a_net"
        Label = "Main Enterprise Network"
        Subnet = "10.0.0.0/28"
        DockerBridgeGateway = "10.0.0.14"
        LabRouterInterface = "gateway: 10.0.0.1"
    },
    [PSCustomObject]@{
        Name = "docker_lab_subnet_b_net"
        Label = "Secondary Enterprise Network"
        Subnet = "10.0.0.16/28"
        DockerBridgeGateway = "10.0.0.30"
        LabRouterInterface = "gateway: 10.0.0.17"
    }
)

function Test-DockerAvailable {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker CLI was not found in PATH. Install or start Docker Desktop, then try again."
    }

    $null = docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not reachable. Start Docker Desktop, or run this terminal as Administrator if Docker pipe access is denied."
    }
}

function Get-LabContainerRows {
    foreach ($name in $labContainers) {
        $raw = docker inspect $name 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
            if ($IncludeMissing) {
                [PSCustomObject]@{
                    Container = $name
                    Status    = "missing"
                    Network   = "-"
                    IPAddress = "-"
                }
            }
            continue
        }

        $inspect = $raw | ConvertFrom-Json
        $status = $inspect.State.Status
        $networks = $inspect.NetworkSettings.Networks

        if ($null -eq $networks -or $networks.PSObject.Properties.Count -eq 0) {
            [PSCustomObject]@{
                Container = $name
                Status    = $status
                Network   = "-"
                IPAddress = "-"
            }
            continue
        }

        foreach ($network in $networks.PSObject.Properties) {
            [PSCustomObject]@{
                Container = $name
                Status    = $status
                Network   = $network.Name
                IPAddress = $network.Value.IPAddress
            }
        }
    }
}

try {
    Test-DockerAvailable
    Write-Host ""
    Write-Host "Docker Lab Networks"
    Write-Host "-------------------"
    $labNetworks | Format-Table -AutoSize

    Write-Host ""
    Write-Host "Docker Lab Containers"
    Write-Host "---------------------"
    Get-LabContainerRows | Sort-Object Network, IPAddress, Container | Format-Table -AutoSize
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
