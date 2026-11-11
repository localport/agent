# Installs, upgrades and uninstalls the Windows installer on an elevated CI
# runner, checking what each leaves behind. No device is enrolled, so no
# service exists; an upgrade with running services is a live check.
#
#   scripts/ci/test-windows-installer.ps1 <installer.exe> <version>
param(
    [Parameter(Mandatory)] [string] $Installer,
    [Parameter(Mandatory)] [string] $Version
)
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:ProgramFiles 'Localport'
$key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Localport'
$log = Join-Path $env:RUNNER_TEMP 'localport-setup.log'

function Assert([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Output "ok: $Message"
}

function Invoke-Setup([string[]] $Arguments) {
    $p = Start-Process -FilePath $Installer -ArgumentList $Arguments -Wait -PassThru
    return $p.ExitCode
}

function Get-MachinePath { [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' }

# A directory a user can write is refused before anything is installed.
$unsafe = Join-Path $env:RUNNER_TEMP 'unsafe-install'
New-Item -ItemType Directory -Path $unsafe -Force | Out-Null
$code = Invoke-Setup @('/S', "/LOG=$log", "/D=$unsafe")
Assert ($code -ne 0) "a user-writable directory is refused (exit $code)"
Assert (-not (Test-Path (Join-Path $unsafe 'localport.exe'))) 'nothing is installed there'

foreach ($round in 'install', 'upgrade') {
    $code = Invoke-Setup @('/S', "/LOG=$log")
    if ($code -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "FAIL: $round exited $code" }
    foreach ($f in 'localport.exe', 'localport-session.exe', 'uninstall.exe', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES') {
        Assert (Test-Path (Join-Path $dir $f)) "$round installs $f"
    }
    $left = Get-ChildItem -LiteralPath $dir -Force | Where-Object { $_.Name -like '.staging-*' -or $_.Name -like '*.old' }
    Assert ($null -eq $left) "$round leaves no staging directory or .old file"
    $info = (Get-Item (Join-Path $dir 'localport.exe')).VersionInfo
    Assert ($info.ProductName -eq 'Localport' -and $info.ProductVersion -eq $Version) "$round localport.exe carries its VERSIONINFO ($($info.ProductVersion))"
    $k = Get-ItemProperty -LiteralPath $key
    Assert ($k.DisplayVersion -eq $Version -and $k.InstallLocation -eq $dir) "$round writes the uninstall key"
    Assert ($k.QuietUninstallString -eq "`"$dir\uninstall.exe`" /S") "$round writes the quiet uninstall command"
    Assert (@(Get-MachinePath | Where-Object { $_ -eq $dir }).Count -eq 1) "$round has the directory on the machine Path once"
    & (Join-Path $dir 'localport.exe') system preflight $dir
    Assert ($LASTEXITCODE -eq 0) "$round directory passes the service binary rule"
}

# _?= keeps the uninstaller in place, so it runs synchronously; it cannot
# delete itself then, and the directory stays with it.
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "_?=$dir") -Wait -PassThru
Assert ($p.ExitCode -eq 0) "uninstall exits 0"
Assert (-not (Test-Path (Join-Path $dir 'localport.exe'))) 'uninstall removes localport.exe'
Assert (-not (Test-Path (Join-Path $dir 'localport-session.exe'))) 'uninstall removes localport-session.exe'
Assert (-not (Test-Path $key)) 'uninstall removes the uninstall key'
Assert (@(Get-MachinePath | Where-Object { $_ -eq $dir }).Count -eq 0) 'uninstall removes the machine Path entry'
Remove-Item -LiteralPath $dir -Recurse -Force
