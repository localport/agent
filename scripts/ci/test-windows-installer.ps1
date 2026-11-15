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

function Test-InInstallDir([string] $Path) { $Path -eq $dir -or $Path.StartsWith("$dir\", [StringComparison]::OrdinalIgnoreCase) }

# A directory a user can write is refused before anything is installed.
$unsafe = Join-Path $env:RUNNER_TEMP 'unsafe-install'
New-Item -ItemType Directory -Path $unsafe -Force | Out-Null
# Granted here: RUNNER_TEMP may already be user-writable or may be admin-only.
& icacls.exe $unsafe /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls $unsafe exited $LASTEXITCODE" }
$code = Invoke-Setup @('/S', "/LOG=$log", "/D=$unsafe")
Assert ($code -ne 0) "a user-writable directory is refused (exit $code)"
Assert (-not (Test-Path (Join-Path $unsafe 'localport.exe'))) 'nothing is installed there'

# The setup mutex as packaging/windows/localport.nsi takes it: in the private
# namespace bounded by the Administrators SID.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SetupMutex {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateBoundaryDescriptorW(string name, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AddSIDToBoundaryDescriptor(ref IntPtr boundary, IntPtr sid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreatePrivateNamespaceW(IntPtr attributes, IntPtr boundary, string alias);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenPrivateNamespaceW(IntPtr boundary, string alias);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateMutexW(IntPtr attributes, bool owner, string name);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    public static extern bool ClosePrivateNamespace(IntPtr ns, uint flags);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateWellKnownSid(int type, IntPtr domain, IntPtr sid, ref uint size);

    // Hold returns the namespace and mutex handles; the caller closes both.
    public static IntPtr[] Hold() {
        IntPtr bd = CreateBoundaryDescriptorW("LocalportServiceConfig", 0);
        if (bd == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        uint size = 68;
        IntPtr sid = Marshal.AllocHGlobal(68);
        if (!CreateWellKnownSid(26, IntPtr.Zero, sid, ref size)) throw new System.ComponentModel.Win32Exception();
        if (!AddSIDToBoundaryDescriptor(ref bd, sid)) throw new System.ComponentModel.Win32Exception();
        IntPtr ns = CreatePrivateNamespaceW(IntPtr.Zero, bd, "LocalportServiceConfig");
        if (ns == IntPtr.Zero) ns = OpenPrivateNamespaceW(bd, "LocalportServiceConfig");
        if (ns == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        IntPtr m = CreateMutexW(IntPtr.Zero, true, @"LocalportServiceConfig\Setup");
        if (m == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        return new IntPtr[] { ns, m };
    }

    public static IntPtr HoldGlobal(string name) {
        IntPtr m = CreateMutexW(IntPtr.Zero, true, name);
        if (m == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        return m;
    }
}
'@

$held = [SetupMutex]::Hold()
$code = Invoke-Setup @('/S', "/LOG=$log")
[SetupMutex]::CloseHandle($held[1]) | Out-Null
[SetupMutex]::ClosePrivateNamespace($held[0], 0) | Out-Null
Assert ($code -eq 1618) "a held setup mutex refuses a second setup (exit $code)"
Assert (-not (Test-Path (Join-Path $dir 'localport.exe'))) 'the refused setup installs nothing'

$sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
# A pending entry is an NT path (\??\C:\...), on current Windows behind a
# flag prefix such as *1.
function Get-PendingPath([string] $Entry) { $Entry -replace '^[^\\]*\\\?\?\\', '' }

# Pending restart deletions (MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT): pairs of
# source and target, an empty target meaning delete.
function Get-PendingDeletes {
    $v = @((Get-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    for ($i = 0; $i + 1 -lt $v.Count; $i += 2) { if ($v[$i + 1] -eq '') { Get-PendingPath $v[$i] } }
}

# Setup must leave Windows without a pending restart: it queues nothing for
# deletion at restart beyond what Allowed accepts. Checked on native x64 only:
# under x86/x64 emulation on ARM64 a plug-in DLL stays mapped for a moment
# after FreeLibrary, so NSIS queues its $PLUGINSDIR.
$nativeX64 = $env:PROCESSOR_ARCHITECTURE -eq 'AMD64'
function Assert-QueuedOnly([string[]] $Before, [scriptblock] $Allowed, [string] $What) {
    $extra = @(Get-PendingDeletes | Where-Object { $Before -notcontains $_ -and -not (& $Allowed $_) })
    if (-not $nativeX64) {
        Write-Output "skip: $What (emulated on $env:PROCESSOR_ARCHITECTURE; queued: $($extra -join ', '))"
        return
    }
    Assert ($extra.Count -eq 0) "$What (queued: $($extra -join ', '))"
}

# Any account can create a Global name; Global\LocalportSetup held by another
# process must not stop setup.
$squat = [SetupMutex]::HoldGlobal('Global\LocalportSetup')
$queued = @(Get-PendingDeletes)
foreach ($round in 'install', 'upgrade') {
    $code = Invoke-Setup @('/S', "/LOG=$log")
    if ($code -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "FAIL: $round exited $code" }
    foreach ($f in 'localport.exe', 'localport-session.exe', 'uninstall.exe', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES') {
        Assert (Test-Path (Join-Path $dir $f)) "$round installs $f"
    }
    $left = @(Get-ChildItem -LiteralPath (Join-Path $dir '.localport-txn') -Force -ErrorAction SilentlyContinue)
    Assert ($left.Count -eq 0) "$round leaves no transaction directory"
    $info = (Get-Item (Join-Path $dir 'localport.exe')).VersionInfo
    Assert ($info.ProductName -eq 'Localport' -and $info.ProductVersion -eq $Version) "$round localport.exe carries its VERSIONINFO ($($info.ProductVersion))"
    $k = Get-ItemProperty -LiteralPath $key
    Assert ($k.DisplayVersion -eq $Version -and $k.InstallLocation -eq $dir) "$round writes the uninstall key"
    Assert ($k.QuietUninstallString -eq "`"$dir\uninstall.exe`" /S") "$round writes the quiet uninstall command"
    Assert (@(Get-MachinePath | Where-Object { $_ -eq $dir }).Count -eq 1) "$round has the directory on the machine Path once"
    & (Join-Path $dir 'localport.exe') system rollback $dir
    Assert ($LASTEXITCODE -eq 0) "$round leaves no open transaction (system rollback exits 0)"
    Assert (-not (Test-Path 'HKLM:\SOFTWARE\Localport\Installer')) "$round leaves no open-transaction record"
}
Assert-QueuedOnly $queued { $false } 'install and upgrade queue nothing for restart'

$held = [SetupMutex]::Hold()
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "_?=$dir") -Wait -PassThru
[SetupMutex]::CloseHandle($held[1]) | Out-Null
[SetupMutex]::ClosePrivateNamespace($held[0], 0) | Out-Null
Assert ($p.ExitCode -eq 1618) "a held setup mutex refuses the uninstaller (exit $($p.ExitCode))"
Assert (Test-Path (Join-Path $dir 'localport.exe')) 'the refused uninstaller removes nothing'

function Assert-Uninstalled([string] $Mode) {
    Assert (-not (Test-Path (Join-Path $dir 'localport.exe'))) "$Mode uninstall removes localport.exe"
    Assert (-not (Test-Path (Join-Path $dir 'localport-session.exe'))) "$Mode uninstall removes localport-session.exe"
    Assert (-not (Test-Path $key)) "$Mode uninstall removes the uninstall key"
    Assert (-not (Test-Path 'HKLM:\SOFTWARE\Localport')) "$Mode uninstall leaves no Localport registry key"
    Assert (@(Get-MachinePath | Where-Object { $_ -eq $dir }).Count -eq 0) "$Mode uninstall removes the machine Path entry"
}

# _?= runs the uninstaller in place and synchronously. Its own image is in
# use, so it and the directory are queued for deletion at the next restart.
$unlog = Join-Path $env:RUNNER_TEMP 'localport-uninstall.log'
$queued = @(Get-PendingDeletes)
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "/LOG=$unlog", "_?=$dir") -Wait -PassThru
if ($p.ExitCode -ne 0) { Get-Content $unlog -ErrorAction SilentlyContinue; throw "FAIL: uninstall exited $($p.ExitCode)" }
Assert-Uninstalled 'in-place'
$pending = @(Get-PendingDeletes)
Assert ($pending -contains (Join-Path $dir 'uninstall.exe')) 'in-place uninstall queues uninstall.exe for deletion at restart'
Assert ($pending -contains $dir) 'in-place uninstall queues the install directory for deletion at restart'
Assert-QueuedOnly $queued { param($p) $p -eq $dir -or $p -eq (Join-Path $dir 'uninstall.exe') } 'in-place uninstall queues nothing else for restart'

# Leave the machine as found: drop the queued deletions under the install
# directory, so a restart cannot remove the next install's files.
function Clear-InstallDirPending {
    $all = @((Get-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    $keep = for ($i = 0; $i + 1 -lt $all.Count; $i += 2) {
        if (-not ($all[$i + 1] -eq '' -and (Test-InInstallDir (Get-PendingPath $all[$i])))) { $all[$i]; $all[$i + 1] }
    }
    if (@($keep).Count) { Set-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -Type MultiString -Value @($keep) }
    else { Remove-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue }
}

# Waits for the temp copy a default-mode uninstaller starts.
function Wait-UninstallerCopy { Get-Process | Where-Object { $_.Path -like '*\~nsu*.tmp\*' } | Wait-Process -Timeout 300 }

# The uninstaller left behind by a committed uninstall (as after a power loss
# before it removed itself) finishes the cleanup when run again.
Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "/LOG=$unlog") -Wait | Out-Null
Wait-UninstallerCopy
Assert (-not (Test-Path $dir)) 'an uninstaller run again after a committed uninstall removes itself and the directory'
Clear-InstallDirPending

# Without _?= the uninstaller copies itself to <temp>\~nsuN.tmp\Un.exe, which
# NSIS queues for deletion at restart, starts the copy and exits; the copy
# deletes uninstall.exe and the directory.
$code = Invoke-Setup @('/S', "/LOG=$log")
if ($code -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "FAIL: reinstall exited $code" }
$queued = @(Get-PendingDeletes)
Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "/LOG=$unlog") -Wait | Out-Null
Wait-UninstallerCopy
Assert-Uninstalled 'temp-copy'
Assert (-not (Test-Path (Join-Path $dir 'uninstall.exe'))) 'temp-copy uninstall removes uninstall.exe'
Assert (-not (Test-Path $dir)) 'temp-copy uninstall removes the install directory'
Assert (-not (@(Get-PendingDeletes) | Where-Object { Test-InInstallDir $_ })) 'temp-copy uninstall queues nothing in the install directory'
Assert-QueuedOnly $queued { param($p) $p -match '\\~nsu\d+\.tmp(\\Un\.exe)?$' } "temp-copy uninstall queues only NSIS's own uninstaller copy for restart"

# A step the uninstaller cannot start (here localport.exe is not a program)
# fails the uninstall with 1603 and removes nothing, the uninstaller included.
$code = Invoke-Setup @('/S', "/LOG=$log")
if ($code -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "FAIL: reinstall exited $code" }
[IO.File]::WriteAllText((Join-Path $dir 'localport.exe'), 'not a program')
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "/LOG=$unlog", "_?=$dir") -Wait -PassThru
Assert ($p.ExitCode -eq 1603) "an uninstall step that cannot start exits 1603 (exit $($p.ExitCode))"
Assert ((Test-Path (Join-Path $dir 'uninstall.exe')) -and (Test-Path $key)) 'an uninstall step that cannot start removes nothing'

# /PURGE runs after the commit point: when it fails (here agent.yaml, the
# first file it deletes, held open without sharing) the uninstall stands,
# exits 93 (AG093) and the uninstaller still removes itself. This deletes the
# device state, so it runs only where there is none.
$state = Join-Path $env:ProgramData 'localport-device'
Assert (-not (Test-Path $state)) "no device state at $state before the purge test"
$code = Invoke-Setup @('/S', "/LOG=$log")
if ($code -ne 0) { Get-Content $log -ErrorAction SilentlyContinue; throw "FAIL: reinstall exited $code" }
New-Item -ItemType Directory -Path $state | Out-Null
$heldFile = [IO.File]::Open((Join-Path $state 'agent.yaml'), 'Create', 'ReadWrite', 'None')
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', '/PURGE', "/LOG=$unlog", "_?=$dir") -Wait -PassThru
$heldFile.Dispose()
Assert ($p.ExitCode -eq 93) "a failed purge exits 93 (exit $($p.ExitCode))"
Assert-Uninstalled 'purge-failed'
Assert (@(Get-PendingDeletes) -contains (Join-Path $dir 'uninstall.exe')) 'a failed purge still removes the uninstaller'
Clear-InstallDirPending
Remove-Item -LiteralPath $dir, $state -Recurse -Force -ErrorAction SilentlyContinue
[SetupMutex]::CloseHandle($squat) | Out-Null
