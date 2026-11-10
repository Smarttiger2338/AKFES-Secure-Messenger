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

# This is intentionally a single, repeatable release path.  It builds both the
# installed Windows client and the static web client from the same source, pins
# the exact archive hash in the deployment script, then lets that script verify
# the SSH host fingerprint before uploading anything.
$root = $PSScriptRoot
$clientSource = Join-Path $root 'client-source'
$clientBuild = Join-Path $clientSource 'scripts\build-vultr-production-client.ps1'
$installerOutput = Join-Path $root 'AKFES-Windows-Client-Installer'
$webDist = Join-Path $clientSource 'client\dist'
$serverSource = Join-Path $root 'server-source'
$serverWeb = Join-Path $serverSource 'web'
$archive = Join-Path $root 'AKFES-Server-Release.tar.gz'
$deployScript = Join-Path $root 'DEPLOY_AKFES_VULTR_V10.ps1'

if ($ServerOnly -and $BuildOnly) { throw 'Choose either -ServerOnly or -BuildOnly, not both.' }
foreach ($required in @($clientBuild, $serverSource, $deployScript)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path is missing: $required" }
}
if (-not $BuildOnly -and -not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw "SSH private key is missing: $IdentityFile" }
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'Windows tar.exe is required.' }

Write-Host '1/4 Building the canonical production client source...' -ForegroundColor Cyan
if ($ServerOnly) { & $clientBuild -WebOnly } else { & $clientBuild -OutputDirectory $installerOutput }
if ($LASTEXITCODE -ne 0) { throw "Client build failed (exit $LASTEXITCODE)." }
if (-not (Test-Path -LiteralPath (Join-Path $webDist 'index.html') -PathType Leaf)) { throw 'The web client was not produced.' }
if (-not $ServerOnly -and -not (Test-Path -LiteralPath (Join-Path $installerOutput 'AKFES-Secure-Messenger-Setup.exe') -PathType Leaf)) {
    throw 'The Windows installer was not produced.'
}

Write-Host '2/4 Updating the web client included in the server release...' -ForegroundColor Cyan
$expectedWeb = [System.IO.Path]::GetFullPath((Join-Path $serverSource 'web'))
if ([System.IO.Path]::GetFullPath($serverWeb) -ne $expectedWeb) { throw "Unsafe web output path: $serverWeb" }
if (Test-Path -LiteralPath $serverWeb) {
    $webItem = Get-Item -LiteralPath $serverWeb -Force
    if ($webItem.LinkType -or -not $webItem.PSIsContainer) { throw "Refusing unsafe web output: $serverWeb" }
    Remove-Item -LiteralPath $serverWeb -Recurse -Force
}
New-Item -ItemType Directory -Path $serverWeb | Out-Null
Copy-Item -Path (Join-Path $webDist '*') -Destination $serverWeb -Recurse -Force

Write-Host '3/4 Creating the verified server release archive...' -ForegroundColor Cyan
if (Test-Path -LiteralPath $archive -PathType Leaf) {
    $item = Get-Item -LiteralPath $archive -Force
    if ($item.LinkType) { throw "Refusing to replace linked archive: $archive" }
    Remove-Item -LiteralPath $archive -Force
}
& tar.exe -czf $archive -C $serverSource deploy encrypted-files release server web ADMIN_AND_PROFILE_KO.md README_KO.md VALIDATION_REPORT_KO.md WEB_CLIENT_KO.md
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw 'Server archive creation failed.' }

$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
$deployText = Get-Content -Raw -LiteralPath $deployScript
$replacement = "`$ExpectedArchiveHash = '$archiveHash'"
$updated = [regex]::Replace($deployText, '(?m)^\$ExpectedArchiveHash\s*=\s*''[A-F0-9]{64}''\s*$', $replacement)
if ($updated -eq $deployText) { throw 'Could not update the deployment archive hash.' }
Set-Content -LiteralPath $deployScript -Value $updated -Encoding utf8
Write-Host "Archive SHA-256 pinned: $archiveHash" -ForegroundColor Green

if ($BuildOnly) {
    Write-Host 'Build complete; no network connection was made.' -ForegroundColor Green
    Write-Host "Server archive: $archive"
    if (-not $ServerOnly) { Write-Host "Windows installer: $(Join-Path $installerOutput 'AKFES-Secure-Messenger-Setup.exe')" }
    return
}

Write-Host '4/4 Uploading and validating the release on Vultr...' -ForegroundColor Cyan
& $deployScript -Server $Server -User $User -IdentityFile $IdentityFile -KeepReleaseCount $KeepReleaseCount
if ($LASTEXITCODE -ne 0) { throw "Vultr deployment failed (exit $LASTEXITCODE)." }

Write-Host ''
Write-Host 'Deployment complete.' -ForegroundColor Green
if (-not $ServerOnly) { Write-Host "Windows installer: $(Join-Path $installerOutput 'AKFES-Secure-Messenger-Setup.exe')" }
Write-Host 'Web messenger: https://api.akfes.pe.kr/'
