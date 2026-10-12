# Removes the MeshTransit client. Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\MeshTransit\uninstall.ps1" [-Purge]
#
# Keeps C:\ProgramData\MeshTransit (identity key, state, logs) unless -Purge
# is given; run meshctl logout first to remove this machine from its Network.
param([switch]$Purge)
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (Run as administrator).'
}

$installDir = Join-Path $env:ProgramFiles 'MeshTransit'
$serviceName = 'MeshTransit'

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$kept = ($machinePath -split ';') | Where-Object { $_ -and $_ -ne $installDir }
[Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')

# The script may run from the install directory; remove it last.
Get-ChildItem -Path $installDir -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne 'uninstall.ps1' } | Remove-Item -Force -Recurse
if ($Purge) {
    Remove-Item -Force -Recurse -Path (Join-Path $env:ProgramData 'MeshTransit') -ErrorAction SilentlyContinue
    if (Get-LocalGroup -Name 'MeshTransit Users' -ErrorAction SilentlyContinue) {
        Remove-LocalGroup -Name 'MeshTransit Users'
    }
}
Write-Host 'MeshTransit is removed.'
if (-not $Purge) { Write-Host 'State is kept in C:\ProgramData\MeshTransit; use -Purge to remove it.' }
