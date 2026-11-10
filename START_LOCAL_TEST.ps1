[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $PSScriptRoot
$clientDirectory = Join-Path $root 'client-source\client'
$composeFile = Join-Path $root 'server-source\deploy\windows-local\compose.yaml'
$stateDirectory = Join-Path $root '.local-test'
$environmentFile = Join-Path $stateDirectory 'compose.env'
$inviteFile = Join-Path $stateDirectory 'invite-code.txt'
$infoFile = Join-Path $stateDirectory 'TEST-INFO.txt'

function New-RandomHex([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant()
}

function Get-Sha256Hex([string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash($bytes) } finally { $hasher.Dispose() }
    return ([BitConverter]::ToString($digest)).Replace('-','').ToLowerInvariant()
}

function Test-DockerEngine {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Start-DockerDesktop {
    Write-Host 'Starting Docker Desktop...'
    $dockerCli = (Get-Command docker -ErrorAction Stop).Source
    Start-Process -FilePath $dockerCli -ArgumentList @('desktop', 'start') -WindowStyle Hidden

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
        'C:\Program Files\Docker\Docker\Docker Desktop.exe',
        'C:\Program Files\Docker\Docker\frontend\Docker Desktop.exe'
    )
    $executable = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $executable) {
        throw 'Docker Desktop is installed incompletely or cannot be found. Start Docker Desktop manually and run this script again.'
    }
    if (-not (Get-Process | Where-Object { $_.ProcessName -match '^(Docker Desktop|com\.docker\.backend)$' })) {
        Start-Process -FilePath $executable -WindowStyle Hidden
    }
    for ($attempt = 1; $attempt -le 90; $attempt++) {
        Start-Sleep -Seconds 2
        if (Test-DockerEngine) { return }
        if (($attempt % 10) -eq 0) { Write-Host "Waiting for Docker engine... $($attempt * 2)s" }
    }
    throw 'Docker Desktop did not become ready within 3 minutes.'
}

foreach ($command in @('docker', 'node', 'npm')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is required but was not found in PATH."
    }
}
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) { throw "Missing compose file: $composeFile" }
if (-not (Test-Path -LiteralPath $clientDirectory -PathType Container)) { throw "Missing client source: $clientDirectory" }

if (-not (Test-DockerEngine)) { Start-DockerDesktop }

New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $environmentFile -PathType Leaf)) {
    $inviteCode = "AKFES-LOCAL-$(New-RandomHex 12)"
    $lines = @(
        "AKFES_LOCAL_DB_PASSWORD=$(New-RandomHex 32)",
        "AKFES_LOCAL_ARDUINO_SECRET=$(New-RandomHex 32)",
        "AKFES_LOCAL_INVITE_SHA256=$(Get-Sha256Hex $inviteCode)",
        "AKFES_LOCAL_APP_SECRET=$(New-RandomHex 32)",
        'AKFES_LOCAL_ADMIN_USERNAMES=["alice-test"]',
        "AKFES_LOCAL_ADMIN_MFA_SECRET=$(New-RandomHex 32)"
    )
    [IO.File]::WriteAllLines($environmentFile, $lines, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($inviteFile, $inviteCode, [Text.UTF8Encoding]::new($false))
}
if (-not (Test-Path -LiteralPath $inviteFile -PathType Leaf)) { throw "Missing local invite file: $inviteFile" }
$inviteCode = (Get-Content -Raw -LiteralPath $inviteFile).Trim()

Write-Host 'Building the local web client...'
$env:VITE_AKFES_API_BASE = 'http://127.0.0.1:1420'
$env:VITE_AKFES_AUTH_BASE = 'http://127.0.0.1:1420'
$env:VITE_AKFES_WS_BASE = 'ws://127.0.0.1:1420'
$env:VITE_AKFES_LOCAL_TEST_BUILD = 'true'
Push-Location $clientDirectory
try {
    if (-not (Test-Path -LiteralPath (Join-Path $clientDirectory 'node_modules') -PathType Container)) {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)." }
    }
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "Client build failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}

Write-Host 'Starting PostgreSQL, Redis, API, and web containers...'
& docker compose --env-file $environmentFile -f $composeFile up --build -d
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit $LASTEXITCODE)." }

$ready = $false
for ($attempt = 1; $attempt -le 90; $attempt++) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:1420/health/ready' -TimeoutSec 3
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
}
if (-not $ready) {
    & docker compose --env-file $environmentFile -f $composeFile ps
    & docker compose --env-file $environmentFile -f $composeFile logs --tail 120 app
    throw 'The local AKFES server did not become ready. Diagnostics are shown above.'
}

$info = @"
AKFES local integration test

Web: http://127.0.0.1:1420/
API ready: http://127.0.0.1:1420/health/ready
Registration invite: $inviteCode

Suggested accounts:
  alice-test
  bob-test

Stop without deleting data:
  powershell -NoProfile -ExecutionPolicy Bypass -File `"$root\STOP_LOCAL_TEST.ps1`"
"@
[IO.File]::WriteAllText($infoFile, $info, [Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host 'AKFES local test server is ready.' -ForegroundColor Green
Write-Host 'URL: http://127.0.0.1:1420/'
Write-Host "Registration invite: $inviteCode" -ForegroundColor Cyan
Write-Host "Test information: $infoFile"

if (-not $NoBrowser) {
    Start-Process 'http://127.0.0.1:1420/?test-client=alice'
    Start-Sleep -Milliseconds 500
    Start-Process 'http://127.0.0.1:1420/?test-client=bob'
}
