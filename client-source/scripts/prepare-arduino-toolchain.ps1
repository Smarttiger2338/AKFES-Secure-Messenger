param(
    [string]$CliArchive = ""
)

$ErrorActionPreference = 'Stop'
$CliVersion = '1.5.1'
$AvrCoreVersion = '1.8.6'
$ExpectedCliSha256 = 'FABE42E0EB04D00E776A66178299FF95A46C623DBC260F997E58FD514853DD40'
$Root = Split-Path -Parent $PSScriptRoot
$Target = Join-Path $Root 'client\src-tauri\resources\arduino-toolchain'

if (Test-Path -LiteralPath (Join-Path $Target 'READY') -PathType Leaf) {
    $ready = Get-Content -LiteralPath (Join-Path $Target 'READY') -Raw
    if ($ready -match "arduino-cli=$CliVersion" -and $ready -match "arduino-avr=$AvrCoreVersion") {
        Write-Host 'Pinned offline Arduino toolchain is already prepared.'
        exit 0
    }
    throw "An unexpected Arduino toolchain already exists: $Target"
}
if (Test-Path -LiteralPath $Target) { throw "Refusing to overwrite incomplete toolchain: $Target" }

$Stage = Join-Path $env:TEMP ("akfes-arduino-toolchain-" + [Guid]::NewGuid().ToString('N'))
$Extract = Join-Path $Stage 'extract'
$Data = Join-Path $Stage 'data'
$Downloads = Join-Path $Stage 'downloads'
$User = Join-Path $Stage 'user'
New-Item -ItemType Directory -Path $Extract,$Data,$Downloads,$User | Out-Null

if (-not $CliArchive) {
    $CliArchive = Join-Path $Stage "arduino-cli_$($CliVersion)_Windows_64bit.zip"
    Invoke-WebRequest -UseBasicParsing -Uri "https://downloads.arduino.cc/arduino-cli/arduino-cli_$($CliVersion)_Windows_64bit.zip" -OutFile $CliArchive
}
$CliArchive = [IO.Path]::GetFullPath($CliArchive)
if (-not (Test-Path -LiteralPath $CliArchive -PathType Leaf)) { throw "Arduino CLI archive is missing: $CliArchive" }
$ActualHash = (Get-FileHash -LiteralPath $CliArchive -Algorithm SHA256).Hash
if ($ActualHash -ne $ExpectedCliSha256) { throw "Arduino CLI SHA-256 mismatch: $ActualHash" }

Expand-Archive -LiteralPath $CliArchive -DestinationPath $Extract
$Cli = Join-Path $Extract 'arduino-cli.exe'
if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw 'arduino-cli.exe is missing from the verified archive.' }
$Config = Join-Path $Stage 'arduino-cli.yaml'
@"
board_manager:
  additional_urls: []
directories:
  data: $($Data.Replace('\','/'))
  downloads: $($Downloads.Replace('\','/'))
  user: $($User.Replace('\','/'))
updater:
  enable_notification: false
"@ | Set-Content -LiteralPath $Config -Encoding utf8

& $Cli --config-file $Config core update-index
if ($LASTEXITCODE -ne 0) { throw "Arduino package index update failed (exit $LASTEXITCODE)." }
& $Cli --config-file $Config core install "arduino:avr@$AvrCoreVersion"
if ($LASTEXITCODE -ne 0) { throw "Arduino AVR core installation failed (exit $LASTEXITCODE)." }

$requiredAvrFiles = @(
    (Join-Path $Data 'packages/arduino/hardware/avr/1.8.6/boards.txt'),
    (Join-Path $Data 'packages/arduino/hardware/avr/1.8.6/bootloaders/atmega/ATmegaBOOT_168_atmega1280.hex'),
    (Join-Path $Data 'packages/arduino/tools/avr-gcc/7.3.0-atmel3.6.1-arduino7/bin/avr-g++.exe'),
    (Join-Path $Data 'packages/arduino/tools/avr-gcc/7.3.0-atmel3.6.1-arduino7/lib/gcc/avr/7.3.0/device-specs/specs-atmega328p')
)
$missingAvrFiles = @($requiredAvrFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
if ($missingAvrFiles.Count -gt 0) {
    throw "Arduino AVR toolchain is incomplete. Missing: $($missingAvrFiles -join '; ')"
}

$Bundle = Join-Path $Stage 'bundle'
New-Item -ItemType Directory -Path $Bundle | Out-Null
Copy-Item -LiteralPath $Cli -Destination (Join-Path $Bundle 'arduino-cli.exe')
Copy-Item -LiteralPath $Data -Destination (Join-Path $Bundle 'data') -Recurse
@"
arduino-cli=$CliVersion
arduino-cli-sha256=$ExpectedCliSha256
arduino-avr=$AvrCoreVersion
"@ | Set-Content -LiteralPath (Join-Path $Bundle 'READY') -Encoding ascii
@"
Arduino CLI is distributed under GPL-3.0:
https://github.com/arduino/arduino-cli

Arduino AVR Boards licensing information is included in the bundled package files:
https://github.com/arduino/ArduinoCore-avr
"@ | Set-Content -LiteralPath (Join-Path $Bundle 'THIRD_PARTY_LICENSES.txt') -Encoding utf8

$Parent = Split-Path -Parent $Target
New-Item -ItemType Directory -Force -Path $Parent | Out-Null
Move-Item -LiteralPath $Bundle -Destination $Target
Write-Host "Offline Arduino toolchain prepared: $Target"
