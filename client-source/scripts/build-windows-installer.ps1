param(
    [Parameter(Mandatory=$true)][string]$ApplicationExe,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Root 'dist-client-production' }
$IExpress = Join-Path $env:SystemRoot 'System32\iexpress.exe'
if (-not (Test-Path -LiteralPath $IExpress -PathType Leaf)) { throw 'Windows IExpress is unavailable.' }
if (-not (Test-Path -LiteralPath $ApplicationExe -PathType Leaf)) { throw "Application executable is missing: $ApplicationExe" }
$toolchainSource = Join-Path $Root 'client\src-tauri\resources\arduino-toolchain'
if (-not (Test-Path -LiteralPath (Join-Path $toolchainSource 'READY') -PathType Leaf)) { throw 'The offline Arduino toolchain has not been prepared.' }

$stage = Join-Path $env:TEMP ("akfes-installer-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Copy-Item -LiteralPath $ApplicationExe -Destination (Join-Path $stage 'AKFES-Secure-Messenger.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'installer-assets\install.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'installer-assets\uninstall.ps1') -Destination $stage
$toolchainArchive = Join-Path $stage 'arduino-toolchain.tar.gz'
& tar.exe -czf $toolchainArchive -C (Split-Path -Parent $toolchainSource) (Split-Path -Leaf $toolchainSource)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $toolchainArchive -PathType Leaf)) { throw 'Offline Arduino toolchain packaging failed.' }

$target = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'AKFES-Secure-Messenger-Setup.exe'
if (Test-Path -LiteralPath $target) {
    $existing = Get-Item -LiteralPath $target -Force
    if ($existing.PSIsContainer -or $existing.LinkType) { throw "Refusing unsafe installer target: $target" }
    Remove-Item -LiteralPath $target -Force
}
# IExpress is a legacy component and fails silently when its destination path is
# deeply nested.  Build in a deliberately short directory, then move the result
# to the caller's requested output path after IExpress has completed.
$shortOutput = Join-Path $env:TEMP ('akfes-i-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $shortOutput | Out-Null
$iexpressTarget = Join-Path $shortOutput 'AKFES-Setup.exe'
$sed = Join-Path $stage 'akfes-installer.sed'
$stageWithSlash = ([IO.Path]::GetFullPath($stage)).TrimEnd('\') + '\'
$sedText = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$iexpressTarget
FriendlyName=AKFES Secure Messenger Setup
AppLaunched=powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=SourceFiles
[SourceFiles]
SourceFiles0=$stageWithSlash
[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
[Strings]
FILE0=AKFES-Secure-Messenger.exe
FILE1=install.ps1
FILE2=uninstall.ps1
FILE3=arduino-toolchain.tar.gz
"@
Set-Content -LiteralPath $sed -Value $sedText -Encoding ascii
$builder = Start-Process -FilePath $IExpress -ArgumentList @('/N','/Q',$sed) -Wait -PassThru
if ($builder.ExitCode -ne 0) { throw "IExpress failed (exit $($builder.ExitCode))." }
if (-not (Test-Path -LiteralPath $iexpressTarget -PathType Leaf)) { throw 'Windows installer was not produced.' }
Move-Item -LiteralPath $iexpressTarget -Destination $target -Force
Write-Output $target
