[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $PSScriptRoot
$serverDirectory = Join-Path $root 'server-source\server'
$clientDirectory = Join-Path $root 'client-source\client'
$stateDirectory = Join-Path $root '.local-test'
$runtimeDirectory = Join-Path $env:LOCALAPPDATA 'AKFES-LocalTest'
$venvDirectory = Join-Path $runtimeDirectory 'venv'
$pythonExe = Join-Path $venvDirectory 'Scripts\python.exe'
$inviteFile = Join-Path $stateDirectory 'invite-code.txt'
$secretFile = Join-Path $stateDirectory 'native-secrets.env'
$pidFile = Join-Path $stateDirectory 'native-processes.json'
$apiLog = Join-Path $stateDirectory 'api.log'
$apiErrorLog = Join-Path $stateDirectory 'api-error.log'
$webLog = Join-Path $stateDirectory 'web.log'
$webErrorLog = Join-Path $stateDirectory 'web-error.log'

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

function Test-Http([string]$Url) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
        return $response.StatusCode -eq 200
    } catch { return $false }
}

function Stop-SavedProcesses {
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { return }
    try {
        $saved = Get-Content -Raw -LiteralPath $pidFile | ConvertFrom-Json
        foreach ($id in @($saved.api, $saved.web)) {
            if ($id -and (Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue)) {
                Stop-Process -Id ([int]$id) -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

foreach ($command in @('python', 'node', 'npm')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command is required but was not found in PATH." }
}
New-Item -ItemType Directory -Path $stateDirectory,$runtimeDirectory -Force | Out-Null

if (-not (Test-Path -LiteralPath $secretFile -PathType Leaf)) {
    $inviteCode = "AKFES-LOCAL-$(New-RandomHex 12)"
    $secretLines = @(
        "INVITE_CODE=$inviteCode",
        "SECRET_KEY=$(New-RandomHex 32)",
        "ARDUINO_MASTER_SECRET=$(New-RandomHex 32)",
        "ADMIN_MFA_ENCRYPTION_KEY=$(New-RandomHex 32)"
    )
    [IO.File]::WriteAllLines($secretFile,$secretLines,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($inviteFile,$inviteCode,[Text.UTF8Encoding]::new($false))
}
$secrets = @{}
foreach ($line in Get-Content -LiteralPath $secretFile) {
    $parts = $line -split '=',2
    if ($parts.Count -eq 2) { $secrets[$parts[0]] = $parts[1] }
}
foreach ($required in @('INVITE_CODE','SECRET_KEY','ARDUINO_MASTER_SECRET','ADMIN_MFA_ENCRYPTION_KEY')) {
    if (-not $secrets.ContainsKey($required) -or -not $secrets[$required]) { throw "Missing local secret: $required" }
}
$inviteCode = [string]$secrets.INVITE_CODE

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    Write-Host 'Creating the short-path Python environment...'
    & python -m venv $venvDirectory
    if ($LASTEXITCODE -ne 0) { throw "Python venv creation failed (exit $LASTEXITCODE)." }
}

$requirementsMarker = Join-Path $runtimeDirectory 'requirements.sha256'
$requirementsFile = Join-Path $serverDirectory 'requirements.txt'
$currentRequirementsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $requirementsFile).Hash
$installedRequirementsHash = if (Test-Path -LiteralPath $requirementsMarker) { (Get-Content -Raw -LiteralPath $requirementsMarker).Trim() } else { '' }
if ($currentRequirementsHash -ne $installedRequirementsHash) {
    Write-Host 'Installing local Python packages (first run only)...'
    & $pythonExe -m pip install --disable-pip-version-check -r $requirementsFile
    if ($LASTEXITCODE -ne 0) { throw "Python package installation failed (exit $LASTEXITCODE)." }
    [IO.File]::WriteAllText($requirementsMarker,$currentRequirementsHash,[Text.UTF8Encoding]::new($false))
}

if (-not (Test-Path -LiteralPath (Join-Path $clientDirectory 'node_modules') -PathType Container)) {
    Write-Host 'Installing local web packages (first run only)...'
    Push-Location $clientDirectory
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }
}

Stop-SavedProcesses

$databasePath = (Join-Path $stateDirectory 'akfes-local.db').Replace('\','/')
$filesPath = (Join-Path $stateDirectory 'encrypted-files')
New-Item -ItemType Directory -Path $filesPath -Force | Out-Null
$env:DEBUG = 'true'
$env:ROUTE_PROFILE = 'all'
$env:CONTROL_PLANE_ENABLED = 'true'
$env:AUTO_CREATE_SCHEMA = 'true'
$env:DATABASE_URL = "sqlite+aiosqlite:///$databasePath"
$env:REDIS_REALTIME_ENABLED = 'false'
$env:REDIS_REALTIME_SUBSCRIBE_ENABLED = 'false'
$env:REDIS_REQUIRED_FOR_READY = 'false'
$env:RATE_LIMIT_FAIL_CLOSED = 'false'
$env:SECURITY_STATE_LOCAL_FALLBACK = 'true'
$env:AUTH_ISSUER_ENABLED = 'true'
$env:ARDUINO_VERIFIER_ENABLED = 'true'
$env:ARDUINO_MASTER_SECRET = [string]$secrets.ARDUINO_MASTER_SECRET
$env:REGISTRATION_INVITE_SHA256 = Get-Sha256Hex $inviteCode
$env:REQUIRE_FIRST_DEVICE_ARDUINO = 'false'
$env:REQUIRE_DEVICE_POP = 'false'
$env:JWT_ALGORITHM = 'HS256'
$env:SECRET_KEY = [string]$secrets.SECRET_KEY
$env:ADMIN_USERNAMES = '["alice-test"]'
$env:ADMIN_MFA_ENCRYPTION_KEY = [string]$secrets.ADMIN_MFA_ENCRYPTION_KEY
$env:ADMIN_WEBAUTHN_RP_ID = '127.0.0.1'
$env:ADMIN_WEBAUTHN_ORIGIN = 'http://127.0.0.1:1420'
$env:CORS_ORIGINS = '["http://127.0.0.1:1420","http://localhost:1420"]'
$env:TRUSTED_HOSTS = '["127.0.0.1","localhost"]'
$env:WS_ALLOWED_ORIGINS = '["http://127.0.0.1:1420","http://localhost:1420"]'
$env:FILES_DIR = $filesPath
$env:FILE_MIN_FREE_BYTES = '104857600'

$apiProcess = Start-Process -FilePath $pythonExe -ArgumentList @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port','18001') -WorkingDirectory $serverDirectory -RedirectStandardOutput $apiLog -RedirectStandardError $apiErrorLog -WindowStyle Hidden -PassThru
for ($attempt=1;$attempt -le 60;$attempt++) {
    if (Test-Http 'http://127.0.0.1:18001/health/ready') { break }
    if ($apiProcess.HasExited) { throw "Local API exited early. Read $apiErrorLog" }
    Start-Sleep -Milliseconds 500
}
if (-not (Test-Http 'http://127.0.0.1:18001/health/ready')) { throw "Local API did not become ready. Read $apiErrorLog" }

$env:VITE_AKFES_API_BASE = 'http://127.0.0.1:18001'
$env:VITE_AKFES_AUTH_BASE = 'http://127.0.0.1:18001'
$env:VITE_AKFES_WS_BASE = 'ws://127.0.0.1:18001'
$env:VITE_AKFES_LOCAL_TEST_BUILD = 'true'
$npmCommand = (Get-Command npm.cmd -ErrorAction Stop).Source
$webProcess = Start-Process -FilePath $npmCommand -ArgumentList @('run','dev','--','--host','127.0.0.1') -WorkingDirectory $clientDirectory -RedirectStandardOutput $webLog -RedirectStandardError $webErrorLog -WindowStyle Hidden -PassThru
for ($attempt=1;$attempt -le 60;$attempt++) {
    if (Test-Http 'http://127.0.0.1:1420/') { break }
    if ($webProcess.HasExited) { throw "Local web client exited early. Read $webErrorLog" }
    Start-Sleep -Milliseconds 500
}
if (-not (Test-Http 'http://127.0.0.1:1420/')) { throw "Local web client did not become ready. Read $webErrorLog" }

@{api=$apiProcess.Id;web=$webProcess.Id}|ConvertTo-Json|Set-Content -LiteralPath $pidFile -Encoding utf8
Write-Host ''
Write-Host 'AKFES no-Docker local test is ready.' -ForegroundColor Green
Write-Host 'URL: http://127.0.0.1:1420/'
Write-Host "Registration invite: $inviteCode" -ForegroundColor Cyan
Write-Host "Logs: $stateDirectory"
if (-not $NoBrowser) {
    Start-Process 'http://127.0.0.1:1420/?test-client=alice'
    Start-Sleep -Milliseconds 400
    Start-Process 'http://127.0.0.1:1420/?test-client=bob'
}
