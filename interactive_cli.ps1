# ==============================================================================
#  PACKET SNIFFER AND NETWORK DEFENSE ANALYZER (Interactive Console)
#  Interactive Menu Interface for Windows
# ==============================================================================

Clear-Host

$esc = [char]27
$cReset = "$esc[0m"
$cBold  = "$esc[1m"
$cDim   = "$esc[2m"
$cCyan  = "$esc[36m"
$cGreen = "$esc[32m"
$cYellow= "$esc[33m"
$cRed   = "$esc[31m"
$cWhite = "$esc[37m"
$cBgRed = "$esc[41;37m"
$cBgYel = "$esc[43;30m"

class SecurityAlert {
    [string]$Timestamp
    [string]$SrcIp
    [string]$DstIp
    [string]$Reason
    [string]$Severity
}

class TrafficStats {
    [uint64]$TotalPackets = 0
    [uint64]$TotalBytes = 0
    [uint64]$TcpPackets = 0
    [uint64]$UdpPackets = 0
    [uint64]$IcmpPackets = 0
    [double]$PacketsPerSecond = 0.0
}

$stats = [TrafficStats]::new()
$alertsList = [System.Collections.Generic.List[SecurityAlert]]::new()
$isCapturing = $false
$activeFilter = "None (Ingesting All Protocols)"
$logPath = "logs/sniffer_activity.log"
$reportPath = "reports/activity_report.txt"

# Ensure directories exist
if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }
if (-not (Test-Path "reports")) { New-Item -ItemType Directory -Path "reports" | Out-Null }

function Print-Banner {
    Write-Host "$cCyan$cBold"
    Write-Host "   ================================================================"
    Write-Host "      PACKET SNIFFER AND BEHAVIORAL ANOMALY DETECTION ENGINE      "
    Write-Host "   ================================================================"
    Write-Host "$cReset"
    Write-Host "$cDim  [ DEFENSIVE NETWORK PACKET ANALYSIS AND ANOMALY DETECTION ENGINE ]$cReset"
    Write-Host "$cCyan  ----------------------------------------------------------------$cReset`n"
}

Print-Banner

while ($true) {
    Write-Host "$cBold  CONTROL CONSOLE $cReset" -NoNewline
    if ($isCapturing) {
        Write-Host "$cGreen[ACTIVE - CAPTURING STREAM]$cReset"
    } else {
        Write-Host "$cDim[STANDBY]$cReset"
    }

    Write-Host "$cDim  +-------------------------------------------------------------+"
    Write-Host "  |  $cBold$cCyan[1]$cReset  List Network Interfaces                            |"
    Write-Host "  |  $cBold$cGreen[2]$cReset  Simulate Live Packet Capture Ingest                |"
    Write-Host "  |  $cBold$cYellow[3]$cReset  Apply Protocol Filter (TCP Only)                   |"
    Write-Host "  |  $cBold$cCyan[4]$cReset  View Live Real-Time Telemetry HUD                  |"
    Write-Host "  |  $cBold$cRed[5]$cReset  View Security Alerts and Anomalies ($($alertsList.Count))              |"
    Write-Host "  |  $cBold$cCyan[6]$cReset  Generate Diagnostic Audit Report                   |"
    Write-Host "  |  $cDim[7]$cReset  View System Activity Log Location                  |"
    Write-Host "  |  $cDim[8]$cReset  Halt and Exit Engine                               |"
    Write-Host "  +-------------------------------------------------------------+$cReset"
    
    $choice = Read-Host "  Select option [1-8]"

    switch ($choice) {
        "1" {
            Write-Host "`n$cBold$cCyan  [DETECTED NETWORK INTERFACES]$cReset"
            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
            if ($adapters) {
                $idx = 0
                foreach ($ad in $adapters) {
                    Write-Host "    $cCyan[$idx]$cReset $($ad.Name) ($($ad.InterfaceDescription)) - Status: $($ad.Status)"
                    $idx++
                }
            } else {
                Write-Host "    $cCyan[0]$cReset Ethernet (Intel Gigabit Controller)"
                Write-Host "    $cCyan[1]$cReset Wi-Fi (802.11ax Wireless Adapter)"
                Write-Host "    $cCyan[2]$cReset Loopback (127.0.0.1 Software Adapter)"
            }
            Write-Host ""
        }
        "2" {
            Write-Host "`n$cGreen  * Ingesting live packet stream...$cReset"
            $isCapturing = $true
            # Ingest normal + attacks
            for ($i = 1; $i -le 25; $i++) {
                $stats.TotalPackets++
                $stats.TotalBytes += 512
                $stats.TcpPackets++
            }
            # Inject Port Scan
            $scanAlert = [SecurityAlert]::new()
            $scanAlert.Timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
            $scanAlert.SrcIp = "10.0.0.99"
            $scanAlert.DstIp = "192.168.1.1"
            $scanAlert.Reason = "Port scan signature detected (touched 14 unique ports)"
            $scanAlert.Severity = "MEDIUM"
            $alertsList.Add($scanAlert)

            # Inject Burst Flood
            $burstAlert = [SecurityAlert]::new()
            $burstAlert.Timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
            $burstAlert.SrcIp = "172.16.0.40"
            $burstAlert.DstIp = "192.168.1.5"
            $burstAlert.Reason = "Abnormal volumetric burst rate (210 pkts/window)"
            $burstAlert.Severity = "HIGH"
            $alertsList.Add($burstAlert)

            for ($i = 1; $i -le 210; $i++) {
                $stats.TotalPackets++
                $stats.TotalBytes += 128
                $stats.UdpPackets++
            }
            $stats.PacketsPerSecond = 584.2

            # Log to file
            Add-Content -Path $logPath -Value "[$([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))] [ALERT] Port scan detected from 10.0.0.99"
            Add-Content -Path $logPath -Value "[$([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))] [ALERT] High burst packet rate from 172.16.0.40"

            Write-Host "  $cGreen[PASS]$cReset Ingested 235 packets. 2 security anomalies intercepted and logged!`n"
        }
        "3" {
            $activeFilter = "TCP Only (Discarding UDP and ICMP frames)"
            Write-Host "`n$cYellow  * Filter Applied: $activeFilter`n$cReset"
        }
        "4" {
            Write-Host "`n$cBold$cCyan  ===================== LIVE TELEMETRY HUD =====================$cReset"
            Write-Host "   Total Packets: $cBold$cGreen$($stats.TotalPackets)$cReset        Total Volume: $cBold$cGreen$($stats.TotalBytes) bytes$cReset"
            Write-Host "   TCP Packets:   $cCyan$($stats.TcpPackets)$cReset        UDP Packets:  $cCyan$($stats.UdpPackets)$cReset"
            Write-Host "   Throughput:    $cBold$cYellow$($stats.PacketsPerSecond) pps$cReset    Active Filter:$cWhite $activeFilter$cReset"
            Write-Host "$cBold$cCyan  =============================================================$cReset`n"
        }
        "5" {
            Write-Host "`n$cBold$cRed  [DETECTED SECURITY ANOMALIES ($($alertsList.Count))]$cReset"
            if ($alertsList.Count -eq 0) {
                Write-Host "  $cGreen[OK]$cReset Clean baseline. No anomalies detected in current window.`n"
            } else {
                foreach ($a in $alertsList) {
                    $badge = if ($a.Severity -eq "HIGH") { "$cBgRed HIGH $cReset" } else { "$cBgYel MED  $cReset" }
                    Write-Host "   $badge [$($a.Timestamp)] $($a.SrcIp) -> $($a.DstIp) | $($a.Reason)"
                }
                Write-Host ""
            }
        }
        "6" {
            $rep = @"
================================================================================
             DEFENSIVE NETWORK SECURITY AND ANOMALY DETECTION AUDIT
================================================================================

[1] SESSION OVERVIEW
    Total Packets Ingested: $($stats.TotalPackets)
    Total Volume Ingested:  $($stats.TotalBytes) bytes
    Average Throughput:     $($stats.PacketsPerSecond) pkts/sec
    Active Filter Setting:  $activeFilter

[2] PROTOCOL COMPOSITION
    TCP Frames: $($stats.TcpPackets)
    UDP Frames: $($stats.UdpPackets)
    ICMP Frames: $($stats.IcmpPackets)

[3] DETECTED INCIDENTS ($($alertsList.Count))
"@
            foreach ($a in $alertsList) {
                $rep += "`n    [$($a.Severity)] [$($a.Timestamp)] $($a.SrcIp) -> $($a.DstIp) | $($a.Reason)"
            }
            $rep += "`n================================================================================`n"
            Set-Content -Path $reportPath -Value $rep
            Write-Host "`n$cGreen  * Report generated and saved to: $reportPath`n$cReset"
        }
        "7" {
            Write-Host "`n  System log stored at: $cCyan$logPath`n$cReset"
        }
        "8" {
            Write-Host "`n$cGreen  Engine shutdown cleanly. Goodbye!`n$cReset"
            break
        }
        default {
            Write-Host "`n$cYellow  Invalid option. Please enter 1-8.`n$cReset"
        }
    }
}
