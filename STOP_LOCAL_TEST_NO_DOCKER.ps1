[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$pidFile=Join-Path $root '.local-test\native-processes.json'
if(-not(Test-Path -LiteralPath $pidFile -PathType Leaf)){Write-Host 'No saved no-Docker test processes were found.';exit 0}
$saved=Get-Content -Raw -LiteralPath $pidFile|ConvertFrom-Json
foreach($id in @($saved.api,$saved.web)){
    if($id -and (Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue)){Stop-Process -Id ([int]$id) -ErrorAction Stop}
}
Remove-Item -LiteralPath $pidFile -Force
Write-Host 'AKFES no-Docker test processes stopped. SQLite data and encrypted files were preserved.' -ForegroundColor Green
