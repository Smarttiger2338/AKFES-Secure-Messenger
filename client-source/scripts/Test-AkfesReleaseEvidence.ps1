[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][string]$ArtifactDirectory,
    [switch]$RequireWindowsSignature
)

$ErrorActionPreference = 'Stop'
$manifestPath = (Resolve-Path -LiteralPath $Manifest -ErrorAction Stop).Path
$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory -ErrorAction Stop).Path
$data = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -ErrorAction Stop
if ($data.schema -ne 'akfes.release-evidence.v1') { throw 'Unsupported release evidence schema.' }
if ([string]::IsNullOrWhiteSpace([string]$data.sourceIdentity)) { throw 'Release evidence has no source identity.' }
if (-not $data.artifacts -or $data.artifacts.Count -eq 0) { throw 'Release evidence has no artifacts.' }

$expectedThumbprint = ([string]$data.signaturePolicy.expectedWindowsSignerThumbprint -replace '\s','').ToUpperInvariant()
foreach ($record in $data.artifacts) {
    $name = [string]$record.name
    if ([System.IO.Path]::GetFileName($name) -ne $name) { throw "Unsafe artifact name in manifest: $name" }
    $path = Join-Path $artifactRoot $name
    $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
    if ([System.IO.Path]::GetDirectoryName($resolved) -ne $artifactRoot.TrimEnd('\')) { throw "Artifact escaped the expected directory: $name" }
    $actualHash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
    if ($actualHash -ne ([string]$record.sha256).ToUpperInvariant()) { throw "Artifact SHA-256 mismatch: $name" }
    $extension = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    if ($RequireWindowsSignature -and $extension -in @('.exe', '.msi')) {
        $signature = Get-AuthenticodeSignature -LiteralPath $resolved
        if ($signature.Status -ne 'Valid') { throw "Windows signature is not valid: $name ($($signature.Status))" }
        $actualThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        if ($expectedThumbprint -and $actualThumbprint -ne $expectedThumbprint) { throw "Unexpected Windows signer: $name" }
    }
}
Write-Host "PASS: $($data.artifacts.Count) release artifacts match the manifest and signature policy."
