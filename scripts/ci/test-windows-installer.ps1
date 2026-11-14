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

# Any account can create a Global name; holding the one an earlier installer
# used must not stop setup.
$squat = [SetupMutex]::HoldGlobal('Global\LocalportSetup')
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

$held = [SetupMutex]::Hold()
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "_?=$dir") -Wait -PassThru
[SetupMutex]::CloseHandle($held[1]) | Out-Null
[SetupMutex]::ClosePrivateNamespace($held[0], 0) | Out-Null
Assert ($p.ExitCode -eq 1618) "a held setup mutex refuses the uninstaller (exit $($p.ExitCode))"
Assert (Test-Path (Join-Path $dir 'localport.exe')) 'the refused uninstaller removes nothing'

# _?= keeps the uninstaller in place, so it runs synchronously; its own
# image is then queued for deletion at reboot, and the directory stays.
$p = Start-Process -FilePath (Join-Path $dir 'uninstall.exe') -ArgumentList @('/S', "_?=$dir") -Wait -PassThru
Assert ($p.ExitCode -eq 0) "uninstall exits 0"
Assert (-not (Test-Path (Join-Path $dir 'localport.exe'))) 'uninstall removes localport.exe'
Assert (-not (Test-Path (Join-Path $dir 'localport-session.exe'))) 'uninstall removes localport-session.exe'
Assert (-not (Test-Path $key)) 'uninstall removes the uninstall key'
Assert (-not (Test-Path 'HKLM:\SOFTWARE\Localport')) 'uninstall leaves no Localport registry key'
Assert (@(Get-MachinePath | Where-Object { $_ -eq $dir }).Count -eq 0) 'uninstall removes the machine Path entry'
[SetupMutex]::CloseHandle($squat) | Out-Null
Remove-Item -LiteralPath $dir -Recurse -Force
