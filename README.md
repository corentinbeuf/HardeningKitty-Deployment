# HardeningKitty-Deployment

This project has for target to imprement HardeningKitty on a Windows Server using PowerShell script or using GPO.

## Install HardeningKitty
- Download lastest release of HardeningKitty project.
```ps1
$version = "v.0.9.3"
Invoke-WebRequest -Uri "https://github.com/scipag/HardeningKitty/archive/refs/tags/$version.zip" -Output "$env:userprofile\Downloads\HardeningKitty-$version.zip"
```
- Unzip downloaded archive.
- Open a PowerShell instance in administrator mode.
- Go to the following path :
```ps1
cd $env:userprofile\Downloads\HardeningKitty-$version
```
- Import HardeningKitty module.
```ps1
Import-Module .\HardeningKitty.psm1
```
- Start audit.
```ps1
Invoke-HardeningKitty -Mode Audit -Log -Report
```