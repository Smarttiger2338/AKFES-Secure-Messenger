$ErrorActionPreference = 'Stop'

$productName = 'AKFES Secure Messenger'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\AKFES Secure Messenger'
$appSource = Join-Path $PSScriptRoot 'AKFES-Secure-Messenger.exe'
$uninstallSource = Join-Path $PSScriptRoot 'uninstall.ps1'
$toolchainArchive = Join-Path $PSScriptRoot 'arduino-toolchain.tar.gz'
$appTarget = Join-Path $installDir 'AKFES-Secure-Messenger.exe'
$uninstallTarget = Join-Path $installDir 'uninstall.ps1'

if (-not (Test-Path -LiteralPath $appSource -PathType Leaf)) { throw 'The packaged AKFES executable is missing.' }
if (-not (Test-Path -LiteralPath $uninstallSource -PathType Leaf)) { throw 'The packaged uninstaller is missing.' }
if (-not (Test-Path -LiteralPath $toolchainArchive -PathType Leaf)) { throw 'The packaged offline Arduino toolchain is missing.' }

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -LiteralPath $appSource -Destination $appTarget -Force
Copy-Item -LiteralPath $uninstallSource -Destination $uninstallTarget -Force
$toolchainStage = Join-Path $env:TEMP ("akfes-toolchain-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $toolchainStage | Out-Null
& tar.exe -xzf $toolchainArchive -C $toolchainStage
if ($LASTEXITCODE -ne 0) { throw 'The offline Arduino toolchain could not be extracted.' }
$expandedToolchain = Join-Path $toolchainStage 'arduino-toolchain'
if (-not (Test-Path -LiteralPath (Join-Path $expandedToolchain 'READY') -PathType Leaf)) { throw 'The offline Arduino toolchain archive is invalid.' }
Copy-Item -LiteralPath $expandedToolchain -Destination $installDir -Recurse -Force

$shell = New-Object -ComObject WScript.Shell
$desktopShortcut = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) "$productName.lnk"))
$desktopShortcut.TargetPath = $appTarget
$desktopShortcut.WorkingDirectory = $installDir
$desktopShortcut.IconLocation = "$appTarget,0"
$desktopShortcut.Save()

$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'AKFES'
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
$startShortcut = $shell.CreateShortcut((Join-Path $startMenuDir "$productName.lnk"))
$startShortcut.TargetPath = $appTarget
$startShortcut.WorkingDirectory = $installDir
$startShortcut.IconLocation = "$appTarget,0"
$startShortcut.Save()

$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AKFES Secure Messenger'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayName -Value $productName -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name Publisher -Value 'Smarttiger2338' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value $appTarget -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $installDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
$uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallTarget`""
New-ItemProperty -Path $uninstallKey -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null

Start-Process -FilePath $appTarget
