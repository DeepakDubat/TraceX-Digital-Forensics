@echo off
title Stop Forensics Workbench
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_workbench.ps1"

