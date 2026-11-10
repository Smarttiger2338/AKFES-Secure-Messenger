[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $PSScriptRoot
$composeFile = Join-Path $root 'server-source\deploy\windows-local\compose.yaml'
$environmentFile = Join-Path $root '.local-test\compose.env'
if (-not (Test-Path -LiteralPath $environmentFile -PathType Leaf)) {
    throw 'Local test state was not found. START_LOCAL_TEST.ps1 must be run first.'
}

& docker compose --env-file $environmentFile -f $composeFile down
if ($LASTEXITCODE -ne 0) { throw "docker compose down failed (exit $LASTEXITCODE)." }
Write-Host 'AKFES local test containers stopped. Database and encrypted files were preserved.' -ForegroundColor Green
