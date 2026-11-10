param(
    [string]$IdentityFile = (Join-Path $env:USERPROFILE '.ssh\akfes-vultr'),
    [string]$Server = 'api.akfes.kro.kr',
    [string]$User = 'akfesadmin',
    [switch]$ServerOnly,
    [switch]$BuildOnly,
    [ValidateRange(1, 20)]
    [int]$KeepReleaseCount = 3
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$fullRelease = Join-Path $root 'BUILD_AND_DEPLOY_AKFES_VULTR.ps1'

if ($ServerOnly -and $BuildOnly) { throw 'Choose either -ServerOnly or -BuildOnly, not both.' }
foreach ($path in @($fullRelease)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}

if (-not $BuildOnly -and -not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "SSH private key is missing: $IdentityFile" }
$releaseArgs=@{Server=$Server;User=$User;IdentityFile=$IdentityFile;KeepReleaseCount=$KeepReleaseCount}
if($ServerOnly){$releaseArgs.ServerOnly=$true}
if($BuildOnly){$releaseArgs.BuildOnly=$true}
& $fullRelease @releaseArgs
if ($LASTEXITCODE -ne 0) { throw "AKFES release failed (exit $LASTEXITCODE)." }
