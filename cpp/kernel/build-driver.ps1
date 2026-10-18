param(
    [Parameter(Mandatory=$true)][string]$WdkRoot,
    [string]$SdkRoot = 'C:\Program Files (x86)\Windows Kits\10',
    [string]$Version = '10.0.26100.0',
    [string]$OutDir = (Join-Path $PSScriptRoot 'out')
)
$ErrorActionPreference = 'Stop'
$vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$visualStudio) { throw 'MSVC x64 build tools not found' }
$msvcRoot = (Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
$compiler = Join-Path $msvcRoot 'bin\Hostx64\x64\cl.exe'
$linker = Join-Path $msvcRoot 'bin\Hostx64\x64\link.exe'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$kernelInclude = Join-Path $WdkRoot "Include\$Version\km"
$sharedInclude = Join-Path $SdkRoot "Include\$Version\shared"
$kernelLibrary = Join-Path $WdkRoot "Lib\$Version\km\x64"
if (!(Test-Path -LiteralPath (Join-Path $kernelInclude 'ntifs.h'))) { throw 'WDK km headers not found' }
$source = Join-Path $PSScriptRoot 'gandon_memory.c'
$object = Join-Path $OutDir 'gandon_memory.obj'
$image = Join-Path $OutDir 'GandonMemory.sys'
& $compiler /nologo /c /W4 /WX /kernel /guard:cf /GS /Zl /utf-8 /O2 /Oi /D_AMD64_ /DAMD64 /D_WIN64 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000008 "/I$kernelInclude" "/I$(Join-Path $kernelInclude 'crt')" "/I$sharedInclude" "/I$(Join-Path $msvcRoot 'include')" "/Fo$object" $source
if ($LASTEXITCODE -ne 0) { throw "Driver compilation failed: $LASTEXITCODE" }
& $linker /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO /MACHINE:X64 /RELEASE /GUARD:CF "/OUT:$image" $object (Join-Path $kernelLibrary 'ntoskrnl.lib') (Join-Path $kernelLibrary 'wdmsec.lib') (Join-Path $kernelLibrary 'BufferOverflowK.lib')
if ($LASTEXITCODE -ne 0) { throw "Driver link failed: $LASTEXITCODE" }
Get-FileHash -LiteralPath $image -Algorithm SHA256
Write-Output 'Built driver only. This script does not build the disassembler, sign, install, or load the driver.'


