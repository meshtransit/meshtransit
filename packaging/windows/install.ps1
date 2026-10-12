# Installs the MeshTransit client on Windows from an extracted release zip.
# Run from an elevated PowerShell in the extracted folder:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
#   C:\Program Files\MeshTransit\        meshd.exe, meshctl.exe, wintun.dll
#   C:\ProgramData\MeshTransit\          identity key, state, logs
#   MeshTransit service (LocalSystem, automatic start, restarts on failure)
#
# The installing user joins the local group "MeshTransit Users", whose
# members can use meshctl without elevation after signing in again.
# Reinstalling keeps the identity key and state.
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (Run as administrator).'
}

$source = $PSScriptRoot
$installDir = Join-Path $env:ProgramFiles 'MeshTransit'
$serviceName = 'MeshTransit'
$groupName = 'MeshTransit Users'
$pipe = '\\.\pipe\ProtectedPrefix\Administrators\MeshTransit\meshd'

foreach ($file in 'meshd.exe', 'meshctl.exe', 'wintun.dll') {
    if (-not (Test-Path (Join-Path $source $file))) { throw "$file is missing next to install.ps1" }
}
$sums = Join-Path $source 'SHA256SUMS'
if (Test-Path $sums) {
    foreach ($line in Get-Content $sums) {
        $hash, $file = $line -split '\s+', 2
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $source $file)).Hash.ToLowerInvariant()
        if ($actual -ne $hash) { throw "checksum mismatch for $file" }
    }
}

if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $groupName -Description 'May use meshctl without elevation' | Out-Null
}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not (Get-LocalGroupMember -Group $groupName -Member $user -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group $groupName -Member $user
}

# Stop a running install before replacing its files.
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
foreach ($file in 'meshd.exe', 'meshctl.exe', 'wintun.dll', 'wintun-LICENSE.txt', 'uninstall.ps1') {
    $path = Join-Path $source $file
    if (Test-Path $path) { Copy-Item -Force $path $installDir }
}

$binary = '"' + (Join-Path $installDir 'meshd.exe') + '" --enable-data-plane --wireguard-listen-port=41641'
if ($existing) {
    & sc.exe config $serviceName binPath= $binary start= auto | Out-Null
} else {
    New-Service -Name $serviceName -DisplayName 'MeshTransit' -BinaryPathName $binary `
        -StartupType Automatic -Description 'MeshTransit mesh networking' | Out-Null
}
# Restart after 5 s on failure; reset the failure count after a day.
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($machinePath -split ';') -notcontains $installDir) {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$installDir", 'Machine')
}

Start-Service -Name $serviceName
$deadline = (Get-Date).AddSeconds(20)
while (-not (Test-Path $pipe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $pipe)) {
    throw 'The MeshTransit service did not start; see C:\ProgramData\MeshTransit\logs\meshd.log'
}
Write-Host 'MeshTransit is installed and running.'
Write-Host 'Connect this machine with: meshctl up   (open a new terminal first; sign in again to use it without elevation)'
