# ARP Listener

Small Windows helper that watches the ARP/neighbor table and prints any newly seen IP/MAC pairs, optionally enriched with reverse DNS and OUI vendor lookup. Useful for spotting devices that just appeared on your LAN in near real time.

## What this repository contains
- `ArpListener.ps1` – core PowerShell script that polls `Get-NetNeighbor` and announces newly discovered neighbors.
- `ArpListener.cmd` – convenience wrapper that regenerates `ArpListener.ps1` in the current folder and launches it with execution policy bypassed for that process only.
- `ArpListener.exe` – compiled launcher (optional; not rebuilt here).

## Requirements
- Windows with PowerShell 5.1+ (or PowerShell 7+) and the `NetTCPIP` module providing `Get-NetNeighbor`.
- Normal user privileges are typically enough to read the neighbor table; use an elevated prompt if you see access errors.

## Quick start
1) PowerShell:  
   ```powershell
   .\ArpListener.ps1 -IntervalMs 1000
   ```
2) Command Prompt: run `ArpListener.cmd` (creates/refreshes the `.ps1` locally and starts it).
3) Stop with `Ctrl + C`.

Notes:
- The `-IntervalMs` parameter controls the polling frequency (bounds: 100–60000 ms; default 1000).
- The script tracks first-seen timestamps in memory only; restarting clears the cache.

## Optional OUI/vendor lookup
Place one of these files next to the script to resolve the MAC vendor prefix:
- `manuf` (Wireshark format)
- `oui.txt` (older IEEE format)
- `nmap-mac-prefixes` (Nmap format)

The first available file is loaded lazily on first lookup.

## How it works
- Polls `Get-NetNeighbor` for `Reachable` and `Stale` entries and ignores broadcasts.
- Keeps a hashtable keyed by `ip-mac`; when a new entry appears, prints the timestamp, IP, MAC, interface alias, optional reverse DNS hostname, and optional vendor.
- Reverse DNS uses `[System.Net.Dns]::GetHostEntry()` first, then `Resolve-DnsName` for PTRs.

## Operational tips
- Run from a stable wired interface for more complete discovery; Wi-Fi may expire entries faster.
- If execution policy blocks scripts, use the provided `.cmd` wrapper or run PowerShell with `-ExecutionPolicy Bypass` for that session only.
- For continuous monitoring, schedule the script with Task Scheduler and configure logging (e.g., redirect output to a file).

## Contributing
The repository is small; please keep edits minimal and include a short rationale in pull requests. If you add features (e.g., output to file, filtering by interface), document flags and defaults in this README.

## License
MIT License (see `LICENSE`).
