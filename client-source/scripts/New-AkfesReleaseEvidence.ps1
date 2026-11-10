[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceIdentity,
    [Parameter(Mandatory)][string]$OutputManifest,
    [Parameter(Mandatory)][string[]]$Artifacts,
    [string]$ExpectedWindowsSignerThumbprint,
    [switch]$RequireWindowsSignature
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SourceIdentity)) { throw 'SourceIdentity is required.' }
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputManifest)
$outputParent = Split-Path -Parent $resolvedOutput
if ([string]::IsNullOrWhiteSpace($outputParent)) { throw 'OutputManifest must include a parent directory.' }
[System.IO.Directory]::CreateDirectory($outputParent) | Out-Null

$expectedThumbprint = ($ExpectedWindowsSignerThumbprint -replace '\s','').ToUpperInvariant()
$records = foreach ($artifact in $Artifacts) {
    $resolved = (Resolve-Path -LiteralPath $artifact -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
        $signatureRequired = $RequireWindowsSignature -and $item.Extension -in @('.exe', '.msi')
        $signatureStatus = 'NotApplicable'
        $signerThumbprint = $null
        if ($item.Extension -in @('.exe', '.msi')) {
            $signature = Get-AuthenticodeSignature -LiteralPath $resolved
            $signatureStatus = [string]$signature.Status
            if ($signature.SignerCertificate) { $signerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant() }
            if ($signatureRequired -and $signature.Status -ne 'Valid') { throw "Windows artifact is not validly signed: $resolved ($signatureStatus)" }
            if ($signatureRequired -and $expectedThumbprint -and $signerThumbprint -ne $expectedThumbprint) { throw "Unexpected Windows signer for $resolved" }
        }
        [ordered]@{
            name = $item.Name
            sizeBytes = $item.Length
            sha256 = $hash
            windowsSignatureStatus = $signatureStatus
            windowsSignerThumbprint = $signerThumbprint
        }
    }
}

if (-not $records -or $records.Count -eq 0) { throw 'At least one file artifact is required.' }
$manifest = [ordered]@{
    schema = 'akfes.release-evidence.v1'
    sourceIdentity = $SourceIdentity
    createdAtUtc = [DateTime]::UtcNow.ToString('o')
    signaturePolicy = [ordered]@{
        windowsSignatureRequired = [bool]$RequireWindowsSignature
        expectedWindowsSignerThumbprint = if ($expectedThumbprint) { $expectedThumbprint } else { $null }
    }
    artifacts = @($records | Sort-Object name)
}
$json = $manifest | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($resolvedOutput, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -LiteralPath $resolvedOutput -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Host "Release evidence: $resolvedOutput"
Write-Host "Manifest SHA-256: $manifestHash"
