<#
.SYNOPSIS
    GUI version of ArpListener using WinForms and Runspaces.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ==========================================
# 1. Shared State (Thread-Safe)
# ==========================================
$SyncHash = [hashtable]::Synchronized(@{})
$SyncHash.LogQueue = [System.Collections.Queue]::Synchronized([System.Collections.Queue]::new())
$SyncHash.Command = "Stop" # Start / Stop
$SyncHash.Params = @{
    Scan           = $false
    LogFile        = ""
    InterfaceAlias = ""
}

# ==========================================
# 2. Background Worker Script
# ==========================================
$WorkerScript = {
    param($SyncHash)

    # Helper Functions (Copied from original)
    function Get-MacVendor {
        param([string]$Mac)
        $clean = $Mac -replace '[:-]', '' -replace '\.', ''
        if ($clean.Length -lt 6) { return $null }
        # $prefix6 = $clean.Substring(0, 6).ToUpper()
        # Simplified OUI lookup for the GUI version (embedded or file based?)
        # For now, let's skip complex file loading or assume files are in PSScriptRoot if passed.
        # To keep it simple and robust in the runspace, we'll skip OUI file loading for this iteration 
        # or we need to pass the path in.
        return $null 
    }

    function Get-NeighborName {
        param([string]$Ip)
        try {
            $entry = [System.Net.Dns]::GetHostEntry($Ip)
            if ($entry.HostName) { return $entry.HostName }
        }
        catch {}
        return $null
    }

    $known = @{}
    $lastScan = [DateTime]::MinValue

    while ($true) {
        if ($SyncHash.Command -eq "Stop") {
            Start-Sleep -Milliseconds 500
            continue
        }

        try {
            # 1. Query Neighbors
            $params = @{ ErrorAction = 'SilentlyContinue' }
            if ($SyncHash.Params.InterfaceAlias) {
                $params['InterfaceAlias'] = $SyncHash.Params.InterfaceAlias
            }

            $neighbors = Get-NetNeighbor @params | Where-Object {
                $_.State -in @('Reachable', 'Stale') -and
                $_.IPAddress -ne $null -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -ne 'ff-ff-ff-ff-ff-ff'
            }

            foreach ($n in $neighbors) {
                $ip = $n.IPAddress
                $mac = $n.LinkLayerAddress.ToLower()
                $id = "$ip-$mac"

                if (-not $known.ContainsKey($id)) {
                    $firstSeen = Get-Date
                    $known[$id] = $firstSeen
                    
                    # Resolve details
                    $hostname = Get-NeighborName -Ip $ip
                    # $vendor = Get-MacVendor -Mac $mac # Skip for now to avoid complexity in runspace

                    # Add to Queue for UI
                    $obj = [PSCustomObject]@{
                        Timestamp = $firstSeen.ToString("HH:mm:ss")
                        IP        = $ip
                        MAC       = $mac
                        Interface = $n.InterfaceAlias
                        Hostname  = $hostname
                        Vendor    = ""
                    }
                    $SyncHash.LogQueue.Enqueue($obj)

                    # File Logging
                    if ($SyncHash.Params.LogFile) {
                        try {
                            $line = '"{0}","{1}","{2}","{3}","{4}"' -f $obj.Timestamp, $ip, $mac, $obj.Interface, $obj.Hostname
                            $line | Out-File -FilePath $SyncHash.Params.LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
                        }
                        catch {}
                    }
                }
            }

            # 2. Active Scan
            if ($SyncHash.Params.Scan -and ((Get-Date) - $lastScan).TotalSeconds -ge 60) {
                $lastScan = Get-Date
                # Simple ping sweep logic
                $ifParams = @{ AddressFamily = 'IPv4' }
                if ($SyncHash.Params.InterfaceAlias) { $ifParams['InterfaceAlias'] = $SyncHash.Params.InterfaceAlias }
                $ips = Get-NetIPAddress @ifParams | Where-Object { $_.PrefixOrigin -ne 'WellKnown' }
                
                foreach ($ipConfig in $ips) {
                    $base = $ipConfig.IPAddress.Substring(0, $ipConfig.IPAddress.LastIndexOf('.'))
                    1..254 | ForEach-Object {
                        $target = "$base.$_"
                        Test-Connection -ComputerName $target -Count 1 -Quiet -AsJob | Out-Null
                    }
                }
            }

        }
        catch {
            # Ignore errors in loop
        }

        Start-Sleep -Milliseconds 1000
    }
}

# ==========================================
# 3. Start Background Thread
# ==========================================
$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
try {
    $PSInstance = [powershell]::Create().AddScript($WorkerScript).AddArgument($SyncHash)
    $PSInstance.Runspace = $Runspace
    $PSInstance.BeginInvoke() | Out-Null
} catch {}

# ==========================================
# 4. GUI Construction
# ==========================================
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "ARP Listener v2.1.1"
$Form.Size = New-Object System.Drawing.Size(800, 500)
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "Sizable"

# --- Top Panel (FlowLayout) ---
$PanelTop = New-Object System.Windows.Forms.FlowLayoutPanel
$PanelTop.Dock = "Top"
$PanelTop.Height = 50
$PanelTop.Padding = New-Object System.Windows.Forms.Padding(10)
$PanelTop.AutoSize = $true
$Form.Controls.Add($PanelTop)

$BtnStart = New-Object System.Windows.Forms.Button
$BtnStart.Text = "Start"
$BtnStart.Size = New-Object System.Drawing.Size(80, 30)
$BtnStart.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
$PanelTop.Controls.Add($BtnStart)

$ChkScan = New-Object System.Windows.Forms.CheckBox
$ChkScan.Text = "Active Scan"
$ChkScan.AutoSize = $true
$ChkScan.Margin = New-Object System.Windows.Forms.Padding(0, 5, 10, 0)
$PanelTop.Controls.Add($ChkScan)

$ChkLog = New-Object System.Windows.Forms.CheckBox
$ChkLog.Text = "Log to File"
$ChkLog.AutoSize = $true
$ChkLog.Margin = New-Object System.Windows.Forms.Padding(0, 5, 10, 0)
$PanelTop.Controls.Add($ChkLog)

$LblIf = New-Object System.Windows.Forms.Label
$LblIf.Text = "Interface:"
$LblIf.AutoSize = $true
$LblIf.Margin = New-Object System.Windows.Forms.Padding(0, 5, 5, 0)
$PanelTop.Controls.Add($LblIf)

$CmbIf = New-Object System.Windows.Forms.ComboBox
$CmbIf.Width = 250
$CmbIf.DropDownStyle = "DropDownList"
# Populate Interfaces with IP
try {
    $ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' }
    $CmbIf.Items.Add("") | Out-Null # Empty option
    
    $selectedIndex = 0
    foreach ($ip in $ips) {
        $alias = $ip.InterfaceAlias
        $addr = $ip.IPAddress
        $str = "$alias ($addr)"
        $index = $CmbIf.Items.Add($str)
        
        # Auto-select if Up
        if ($ip.InterfaceIndex -eq (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex -First 1)) {
            $selectedIndex = $index
        }
    }
    if ($CmbIf.Items.Count -gt 1) {
        $CmbIf.SelectedIndex = $selectedIndex
    }
}
catch {}
$PanelTop.Controls.Add($CmbIf)

# --- Status Strip ---
$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$StatusLabel.Text = "v2.1.1 | Digital Swiss Partners DSPSA"
$StatusStrip.Items.Add($StatusLabel) | Out-Null
$Form.Controls.Add($StatusStrip)

# --- Tooltips ---
$ToolTip = New-Object System.Windows.Forms.ToolTip
$ToolTip.AutoPopDelay = 5000
$ToolTip.InitialDelay = 1000
$ToolTip.ReshowDelay = 500
$ToolTip.ShowAlways = $true

$ToolTip.SetToolTip($ChkScan, "Active Scan: Pings all IPs in the subnet every 60s to find silent devices.`nUseful for finding devices that don't talk often.")
$ToolTip.SetToolTip($ChkLog, "Log to File: Saves all discovered devices to a CSV file.`nUseful for long-term monitoring.")
$ToolTip.SetToolTip($BtnStart, "Start/Stop: Begins or ends the network monitoring session.`nPassive mode by default (stealthy).")
$ToolTip.SetToolTip($CmbIf, "Interface: Select the network adapter to monitor.`nAuto-selects your active internet connection.")

# --- Grid ---
$Grid = New-Object System.Windows.Forms.DataGridView
$Grid.Dock = "Fill"
$Grid.AllowUserToAddRows = $false
$Grid.ReadOnly = $true
$Grid.SelectionMode = "FullRowSelect"
$Grid.AutoGenerateColumns = $false
$Grid.ColumnHeadersVisible = $false # Hide native headers
$Grid.RowHeadersVisible = $false # Hide row headers (the little triangle selector)

$Grid.Columns.Add("Timestamp", "Timestamp") | Out-Null
$Grid.Columns.Add("IP", "IP Address") | Out-Null
$Grid.Columns.Add("MAC", "MAC Address") | Out-Null
$Grid.Columns.Add("Interface", "Interface") | Out-Null
$Grid.Columns.Add("Hostname", "Hostname") | Out-Null
$Grid.Columns[4].AutoSizeMode = "Fill" # Use index 4 instead of Name

# --- Fake Header Row (User Hack) ---
try {
    $hIdx = $Grid.Rows.Add("TIMESTAMP", "IP ADDRESS", "MAC ADDRESS", "INTERFACE", "HOSTNAME")
    $headerRow = $Grid.Rows[$hIdx]
    $headerRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    $headerRow.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    if ($Grid.Font) {
        $headerRow.DefaultCellStyle.Font = New-Object System.Drawing.Font($Grid.Font, [System.Drawing.FontStyle]::Bold)
    }
    $headerRow.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    $headerRow.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $headerRow.Frozen = $true
}
catch {}

$Form.Controls.Add($Grid)
try { $Grid.ClearSelection() } catch {}

# --- Logic ---
$BtnStart.Add_Click({
        if ($BtnStart.Text -eq "Start") {
            # Update Params
            $SyncHash.Params.Scan = $ChkScan.Checked
        
            # Parse Interface Alias from "Alias (IP)" string
            $selected = $CmbIf.SelectedItem
            if ($selected -match '^(.+) \(') {
                $SyncHash.Params.InterfaceAlias = $Matches[1]
            }
            else {
                $SyncHash.Params.InterfaceAlias = $selected
            }
        
            if ($ChkLog.Checked) {
                $sfd = New-Object System.Windows.Forms.SaveFileDialog
                $sfd.Filter = "CSV Files (*.csv)|*.csv"
                if ($sfd.ShowDialog() -eq "OK") {
                    $SyncHash.Params.LogFile = $sfd.FileName
                }
                else {
                    $ChkLog.Checked = $false # Cancelled
                }
            }
            else {
                $SyncHash.Params.LogFile = ""
            }

            $SyncHash.Command = "Start"
            $BtnStart.Text = "Stop"
            $ChkScan.Enabled = $false
            $ChkLog.Enabled = $false
            $CmbIf.Enabled = $false
        }
        else {
            $SyncHash.Command = "Stop"
            $BtnStart.Text = "Start"
            $ChkScan.Enabled = $true
            $ChkLog.Enabled = $true
            $CmbIf.Enabled = $true
        }
    })

# --- Timer for Updates ---
$Timer = New-Object System.Windows.Forms.Timer
$Timer.Interval = 500 # 500ms
$Timer.Add_Tick({
        try {
            if ($null -ne $SyncHash -and $null -ne $SyncHash.LogQueue) {
                while ($SyncHash.LogQueue.Count -gt 0) {
                    $item = $SyncHash.LogQueue.Dequeue()
                    if ($null -ne $Grid -and $null -ne $Grid.Rows) {
                        $Grid.Rows.Add($item.Timestamp, $item.IP, $item.MAC, $item.Interface, $item.Hostname) | Out-Null
                        # Auto scroll
                        if ($Grid.Rows.Count -gt 0) {
                            $Grid.FirstDisplayedScrollingRowIndex = $Grid.Rows.Count - 1
                        }
                    }
                }
            }
        }
        catch {
            # Suppress timer errors to prevent popups
        }
    })
$Timer.Start()

# --- Cleanup ---
$Form.Add_FormClosing({
        $SyncHash.Command = "Stop"
        $PSInstance.Stop()
        $Runspace.Close()
        $Runspace.Dispose()
    })

[void]$Form.ShowDialog()
