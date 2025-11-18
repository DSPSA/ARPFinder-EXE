<#
.SYNOPSIS
    Écouteur simple de la table ARP/voisins qui affiche les nouveaux appareils découverts.

.DESCRIPTION
    Interroge périodiquement la table des voisins et signale les paires IP/MAC
    qui n'ont pas encore été vues. Utilise Get-NetNeighbor au lieu d'analyser
    la sortie de arp.exe.

.PARAMETER IntervalMs
    Intervalle d’interrogation en millisecondes (par défaut : 1000 ms).

.EXAMPLE
    .\Start-ArpListener.ps1 -IntervalMs 2000
#>

[CmdletBinding()]
param(
    [int]
    [ValidateRange(100, 60000)]
    $IntervalMs = 1000
)

Write-Host '=== Écouteur ARP / Voisins (quasi temps réel) ==='
Write-Host 'Appuyez sur CTRL+C pour arrêter.`n'

# Hashtable : clé = "ip-mac", valeur = [datetime] première détection
$known = @{}

function Get-MacVendor {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Mac
    )

    $clean = $Mac -replace '[:-]', '' -replace '\.', ''
    if ($clean.Length -lt 6) { return $null }
    $prefix6 = $clean.Substring(0, 6).ToUpper()
    $prefix7 = if ($clean.Length -ge 7) { $clean.Substring(0, 7).ToUpper() } else { $null }

    $dir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        Join-Path $dir 'manuf',
        Join-Path $dir 'oui.txt',
        Join-Path $dir 'nmap-mac-prefixes'
    )
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
        # Interroge la table des voisins : Reachable et Stale sont intéressants
        $neighbors = Get-NetNeighbor -ErrorAction Stop |
            Where-Object {
                $_.State -in @('Reachable', 'Stale') -and
                $_.IPAddress -ne $null -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -ne 'ff-ff-ff-ff-ff-ff'
            }

        foreach ($n in $neighbors) {
            $ip  = $n.IPAddress
            $mac = $n.LinkLayerAddress.ToLower()
            # Format explicit pour éviter les guillemets doubles
            $id  = '{0}-{1}' -f $ip, $mac

            if (-not $known.ContainsKey($id)) {
                $firstSeen = Get-Date
                $known[$id] = $firstSeen

                $hostname = Get-NeighborName -Ip $ip
                $vendor   = Get-MacVendor -Mac $mac
                $nameSuffix = if ($hostname) { " ; nom : $hostname" } else { "" }
                $vendorSuffix = if ($vendor) { " ; constructeur : $vendor" } else { "" }

                $msg = '[{0:HH:mm:ss}] [+] NOUVEL APPAREIL : {1} -> {2} (interface : {3}{4}{5})' -f `
                    $firstSeen, $ip, $mac, $n.InterfaceAlias, $nameSuffix, $vendorSuffix

                Write-Host $msg -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning ('Échec de l''interrogation de la table des voisins : {0}' -f $_.Exception.Message)
    }

    Start-Sleep -Milliseconds $IntervalMs
}
