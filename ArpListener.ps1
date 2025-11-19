<#
.SYNOPSIS
    Simple listener for the ARP/neighbor table that shows newly discovered devices.

.DESCRIPTION
    Periodically queries the neighbor table and reports IP/MAC pairs that have
    not been seen before. Uses Get-NetNeighbor instead of parsing arp.exe output.

.PARAMETER IntervalMs
    Polling interval in milliseconds (default: 1000 ms).

.EXAMPLE
    .\Start-ArpListener.ps1 -IntervalMs 2000
#>

[CmdletBinding()]
param(
    [int]
    [ValidateRange(100, 60000)]
    $IntervalMs = 1000,

    [Parameter(Mandatory = $false)]
    [string]
    $LogFile,

    [Parameter(Mandatory = $false)]
    [string[]]
    $InterfaceAlias,

    [Parameter(Mandatory = $false)]
    [switch]
    $Scan,

    [Parameter(Mandatory = $false)]
    [int]
    $ScanIntervalSec = 60
)

Write-Host "=== ARP / Neighbor listener (near real time) ==="
Write-Host "Press CTRL+C to stop.`n"

if ($LogFile) {
    $LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)
    Write-Host "Logging to: $LogFile"
    if (-not (Test-Path $LogFile)) {
        "Timestamp,IP,MAC,Interface,Hostname,Vendor" | Out-File -FilePath $LogFile -Encoding UTF8
    }
}

# Hashtable: key = "ip-mac", value = [datetime] first detection
$known = @{}
$lastScan = [DateTime]::MinValue

function Get-MacVendor {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Mac
    )

    $clean = $Mac -replace '[:-]', '' -replace '\.', ''
    if ($clean.Length -lt 6) { return $null }
    $prefix6 = $clean.Substring(0, 6).ToUpper()
    $prefix7 = if ($clean.Length -ge 7) { $clean.Substring(0, 7).ToUpper() } else { $null }

    # Resolve a base directory for optional OUI files; fall back to current location if needed
    $dir = $PSScriptRoot
    if (-not $dir -and $MyInvocation.MyCommand.Path) {
        $dir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if (-not $dir) { $dir = (Get-Location).Path }

    $candidateNames = @('manuf', 'oui.txt', 'nmap-mac-prefixes')
    $candidates = $candidateNames | ForEach-Object { Join-Path -Path $dir -ChildPath $_ }
    $file = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $file) { return $null }

    if (-not $script:Ouis) {
        $script:Ouis = @{}
        $lines = Get-Content -LiteralPath $file -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match '^([0-9A-Fa-f]{6,7})[\s\t]+(.+)$') {
                $script:Ouis[$Matches[1].ToUpper()] = $Matches[2].Trim()
            }
            elseif ($line -match '^([0-9A-Fa-f]{6})\s*\(hex\)\s*(.+)$') {
                $script:Ouis[$Matches[1].ToUpper()] = $Matches[2].Trim()
            }
        }
    }

    if ($prefix7 -and $script:Ouis.ContainsKey($prefix7)) {
        return $script:Ouis[$prefix7]
    }
    if ($script:Ouis.ContainsKey($prefix6)) {
        return $script:Ouis[$prefix6]
    }
    return $null
}

function Get-NeighborName {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Ip
    )

    try {
        $entry = [System.Net.Dns]::GetHostEntry($Ip)
        if ($entry.HostName) { return $entry.HostName }
    }
    catch { }

    try {
        $dns = Resolve-DnsName -Name $Ip -ErrorAction Stop
        $nameHost = $dns | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1 -ExpandProperty NameHost
        if ($nameHost) { return $nameHost }
    }
    catch { }

    return $null
}

while ($true) {
    try {
        # Query neighbor table and keep Reachable/Stale entries
        $params = @{
            ErrorAction = 'SilentlyContinue' # Don't stop if no neighbors found at all
        }
        if ($InterfaceAlias) {
            $params['InterfaceAlias'] = $InterfaceAlias
        }

        $neighbors = Get-NetNeighbor @params |
        Where-Object {
            $_.State -in @('Reachable', 'Stale') -and
            $_.IPAddress -ne $null -and
            $_.LinkLayerAddress -and
            $_.LinkLayerAddress -ne 'ff-ff-ff-ff-ff-ff'
        }

        foreach ($n in $neighbors) {
            $ip = $n.IPAddress
            $mac = $n.LinkLayerAddress.ToLower()
            # Explicit format to avoid double quotes in concatenation
            $id = '{0}-{1}' -f $ip, $mac

            if (-not $known.ContainsKey($id)) {
                $firstSeen = Get-Date
                $known[$id] = $firstSeen

                $hostname = Get-NeighborName -Ip $ip
                $vendor = Get-MacVendor -Mac $mac
                $nameSuffix = if ($hostname) { " ; name: $hostname" } else { "" }
                $vendorSuffix = if ($vendor) { " ; vendor: $vendor" } else { "" }

                $msg = '[{0:HH:mm:ss}] [+] NEW DEVICE: {1} -> {2} (interface: {3}{4}{5})' -f `
                    $firstSeen, $ip, $mac, $n.InterfaceAlias, $nameSuffix, $vendorSuffix

                Write-Host $msg -ForegroundColor Green

                if ($LogFile) {
                    $csvLine = '"{0}","{1}","{2}","{3}","{4}","{5}"' -f `
                        $firstSeen.ToString('yyyy-MM-dd HH:mm:ss'), $ip, $mac, $n.InterfaceAlias, $hostname, $vendor
                    $csvLine | Out-File -FilePath $LogFile -Append -Encoding UTF8
                }
            }
        }

        # Active Scanning Logic
        if ($Scan -and ((Get-Date) - $lastScan).TotalSeconds -ge $ScanIntervalSec) {
            $lastScan = Get-Date
            Write-Host "[Scanning] Sending ping sweep to refresh ARP table..." -ForegroundColor DarkGray
            
            # Get subnets from relevant interfaces
            $ifParams = @{ AddressFamily = 'IPv4' }
            if ($InterfaceAlias) { $ifParams['InterfaceAlias'] = $InterfaceAlias }
            
            $ips = Get-NetIPAddress @ifParams | Where-Object { $_.PrefixOrigin -ne 'WellKnown' }
            
            foreach ($ipConfig in $ips) {
                # Calculate subnet range (simplified: just ping the /24 neighbor)
                # For a robust solution, we'd parse PrefixLength. Here we assume /24 for simplicity or just ping neighbors.
                # Actually, a better way is to just ping the broadcast or use a range.
                # Let's try to ping the first 10 and last 10 or just random ones? 
                # No, to be effective we need to ping existing neighbors to refresh them or scan the subnet.
                # A full subnet scan in PS is slow. Let's just ping the broadcast address if possible, or rely on the user knowing this is a "noisy" scan.
                # Better approach for "Active": Ping all *known* neighbors to keep them alive, AND try to ping a few randoms?
                # Let's stick to a simple implementation: Ping the broadcast address? Windows doesn't always like that.
                # Let's iterate 1..254 for the current subnet.
                
                $base = $ipConfig.IPAddress.Substring(0, $ipConfig.IPAddress.LastIndexOf('.'))
                1..254 | ForEach-Object {
                    $target = "$base.$_"
                    # Fire and forget
                    Test-Connection -ComputerName $target -Count 1 -Quiet -AsJob | Out-Null
                }
            }
        }
    }
    catch {
        Write-Warning ('Failed to query the neighbor table: {0}' -f $_.Exception.Message)
    }

    Start-Sleep -Milliseconds $IntervalMs
}
