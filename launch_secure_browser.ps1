# CyberSentinel Built-in Secure Browser Launcher
$htmlPath = "$PSScriptRoot\secure_browser\index.html"
$fileUri = "file:///" + $htmlPath.Replace("\", "/")

Write-Host "Launching CyberSentinel Built-in Secure Browser..." -ForegroundColor Cyan

$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

if (Test-Path $chrome) {
    Start-Process $chrome -ArgumentList "--app=$fileUri"
} elseif (Test-Path $edge) {
    Start-Process $edge -ArgumentList "--app=$fileUri"
} else {
    Start-Process $htmlPath
}
