param(
    [string]$OutputDirectory = "",
    [switch]$WebOnly
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Root 'client'
$CargoTarget = Join-Path $env:TEMP 'akfes-p125-vultr-client'
# Reuse the verified dependency cache so
# a production rebuild does not depend on live registry access.
$NpmCache = Join-Path $env:TEMP 'akfes-npm-cache'
$ExpectedApi = 'VITE_AKFES_API_BASE=https://api.akfes.pe.kr'
$ExpectedWs = 'VITE_AKFES_WS_BASE=wss://api.akfes.pe.kr'
$ProductionEnv = Join-Path $Client '.env.production'

if (-not $WebOnly) {
    & (Join-Path $PSScriptRoot 'prepare-arduino-toolchain.ps1')
    if ($LASTEXITCODE -ne 0) { throw "offline Arduino toolchain preparation failed (exit $LASTEXITCODE)." }
}

if (-not (Test-Path -LiteralPath $ProductionEnv -PathType Leaf)) { throw 'client/.env.production is missing.' }
$lines = Get-Content -LiteralPath $ProductionEnv
if ($lines -notcontains $ExpectedApi -or $lines -notcontains $ExpectedWs) { throw 'Production client endpoint is not pinned to api.akfes.pe.kr.' }
if ($lines -contains 'VITE_AKFES_LOCAL_TEST_BUILD=true') { throw 'Refusing to build a local-test client as production.' }

if (-not $WebOnly -and -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $CargoFallback = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (-not (Test-Path -LiteralPath $CargoFallback -PathType Leaf)) { throw 'Rust cargo is required.' }
    $env:PATH = "$(Split-Path -Parent $CargoFallback);$env:PATH"
}
$env:VITE_AKFES_API_BASE = 'https://api.akfes.pe.kr'
$env:VITE_AKFES_AUTH_BASE = 'https://api.akfes.pe.kr'
$env:VITE_AKFES_WS_BASE = 'wss://api.akfes.pe.kr'
$env:VITE_AKFES_LOCAL_TEST_BUILD = 'false'
if (-not $WebOnly) {
    $env:CARGO_TARGET_DIR = $CargoTarget
    $env:CARGO_BUILD_JOBS = '1'
    $env:TAURI_CONFIG = '{"build":{"devUrl":null,"beforeDevCommand":null,"beforeBuildCommand":null}}'
}

Push-Location $Client
try {
    npm ci --prefer-offline --cache $NpmCache --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)." }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "frontend build failed (exit $LASTEXITCODE)." }
    if (-not $WebOnly) {
        cargo test --manifest-path (Join-Path $Client 'src-tauri\Cargo.toml')
        if ($LASTEXITCODE -ne 0) { throw "Rust tests failed (exit $LASTEXITCODE)." }
        # The bundled Arduino AVR distribution contains historical file paths that
        # exceed the legacy NSIS path limit. Build the release executable directly
        # and let the purpose-built installer package the toolchain as one payload.
        cargo build --release --manifest-path (Join-Path $Client 'src-tauri\Cargo.toml')
        if ($LASTEXITCODE -ne 0) { throw "Windows client release build failed (exit $LASTEXITCODE)." }
    }
} finally {
    Pop-Location
}

if ($WebOnly) {
    Write-Host "Production web client: $(Join-Path $Client 'dist')"
    return
}

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Root 'dist-client-production' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Exe = Join-Path $CargoTarget 'release\akfes-messenger-client.exe'
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "Built executable not found: $Exe" }
$Target = Join-Path $OutputDirectory 'AKFES-Secure-Messenger.exe'
Copy-Item -LiteralPath $Exe -Destination $Target -Force
$InstallerTarget = Join-Path $OutputDirectory 'AKFES-Secure-Messenger-Setup.exe'
Write-Host 'Creating the Windows installer with the Arduino-safe packager...'
& (Join-Path $PSScriptRoot 'build-windows-installer.ps1') -ApplicationExe $Exe -OutputDirectory $OutputDirectory | Out-Host
if (-not (Test-Path -LiteralPath $InstallerTarget -PathType Leaf)) { throw 'Windows installer was not produced.' }
$Hash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
$InstallerHash = (Get-FileHash -LiteralPath $InstallerTarget -Algorithm SHA256).Hash
Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256.txt') -Encoding ascii -Value @(
    "$InstallerHash  AKFES-Secure-Messenger-Setup.exe"
    "$Hash  AKFES-Secure-Messenger.exe"
)
Write-Host "Production client: $Target"
Write-Host "SHA-256: $Hash"
Write-Host "Windows installer: $InstallerTarget"
Write-Host "Installer SHA-256: $InstallerHash"
