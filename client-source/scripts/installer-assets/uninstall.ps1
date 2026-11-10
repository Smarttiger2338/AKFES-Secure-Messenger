$ErrorActionPreference = 'Stop'

$productName = 'AKFES Secure Messenger'
$expectedDir = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\AKFES Secure Messenger'))
$installDir = [IO.Path]::GetFullPath((Split-Path -Parent $PSCommandPath))
if ($installDir -ne $expectedDir) { throw "Refusing to remove an unexpected directory: $installDir" }

$desktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) "$productName.lnk"
$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'AKFES'
$startShortcut = Join-Path $startMenuDir "$productName.lnk"
if (Test-Path -LiteralPath $desktopShortcut -PathType Leaf) { Remove-Item -LiteralPath $desktopShortcut -Force }
if (Test-Path -LiteralPath $startShortcut -PathType Leaf) { Remove-Item -LiteralPath $startShortcut -Force }
if ((Test-Path -LiteralPath $startMenuDir -PathType Container) -and -not (Get-ChildItem -LiteralPath $startMenuDir -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $startMenuDir -Force
}

$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AKFES Secure Messenger'
if (Test-Path -LiteralPath $uninstallKey) { Remove-Item -LiteralPath $uninstallKey -Force }

$appTarget = Join-Path $installDir 'AKFES-Secure-Messenger.exe'
if (Test-Path -LiteralPath $appTarget -PathType Leaf) { Remove-Item -LiteralPath $appTarget -Force }
$toolchainTarget = Join-Path $installDir 'arduino-toolchain'
if (Test-Path -LiteralPath $toolchainTarget -PathType Container) {
    $toolchainItem = Get-Item -LiteralPath $toolchainTarget -Force
    if ($toolchainItem.LinkType -or ($toolchainItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing to traverse an unexpected Arduino toolchain link.' }
    Remove-Item -LiteralPath $toolchainTarget -Recurse -Force
}
Write-Host 'AKFES Secure Messenger has been removed.'
