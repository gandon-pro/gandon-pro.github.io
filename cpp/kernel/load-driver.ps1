param([string]$Image = (Join-Path $PSScriptRoot 'out\GandonMemory.sys'), [switch]$Unload)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script in an elevated PowerShell session. No changes were made.' }
$Image = (Resolve-Path -LiteralPath $Image).Path
$name = 'GandonMemory'
$existing = Get-CimInstance Win32_SystemDriver -Filter "Name='$name'" -ErrorAction SilentlyContinue
if ($existing -and $existing.PathName.Trim('"') -ne $Image) { throw 'A different driver already uses this service name; refusing to replace it.' }
if ($Unload) {
    if ($existing) {
        & sc.exe stop $name
        if ($LASTEXITCODE -notin @(0,1062)) { throw 'Driver could not be stopped; service was not deleted.' }
        & sc.exe delete $name
        if ($LASTEXITCODE -ne 0) { throw 'Could not delete driver service.' }
    }
    return
}
$signature = Get-AuthenticodeSignature -LiteralPath $Image
if ($signature.Status -ne 'Valid') { throw "Driver signature is $($signature.Status). Provide a properly signed driver. This script never changes Secure Boot or signature enforcement." }
$created = $false
if (!$existing) {
    & sc.exe create $name type= kernel start= demand binPath= $Image
    if ($LASTEXITCODE -ne 0) { throw 'Could not create kernel service.' }
    $created = $true
}
& sc.exe start $name
if ($LASTEXITCODE -notin @(0,1056)) {
    if ($created) { & sc.exe delete $name | Out-Null }
    throw 'Windows rejected the driver load. Consult CodeIntegrity/Operational. Ordinary Authenticode validity alone does not guarantee kernel policy acceptance.'
}
& sc.exe query $name
