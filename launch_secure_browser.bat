@echo off
title CyberSentinel Secure Browser
echo Launching CyberSentinel Built-in Secure Browser...

set HTML_PATH=%~dp0secure_browser\index.html

if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --app="file:///%HTML_PATH:\=/%"
    exit
)

if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --app="file:///%HTML_PATH:\=/%"
    exit
)

start "" "%HTML_PATH%"
exit
