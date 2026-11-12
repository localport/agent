; Localport Windows installer (NSIS 3.13, no third-party plugins).
;
; The installer only extracts files into a transaction's staging directory
; and runs the `localport system` steps (internal/cli/system.go) from a copy
; of the new localport.exe, checking each exit status; the steps make every
; change to the machine as one transaction. It never enrols a
; device: services are registered by an elevated `localport connect` or
; `localport service install`, and re-registered here on upgrade.
;
; makensis defines (agent/Makefile):
;   VERSION    release version, e.g. 1.4.0
;   VERSION4   four-part file version, e.g. 1.4.0.0
;   SRCDIR     directory holding localport.exe, localport-session.exe,
;              LICENSE, NOTICE, THIRD_PARTY_NOTICES and, in the second pass,
;              uninstall.exe
;   OUTFILE    the installer to write
;   WRITE_UNINSTALLER  first pass only: the output writes uninstall.exe to its
;              own directory and exits, so the uninstaller can be signed
;              before the second pass embeds it.
;
; Switches: /S silent, /D=<dir> install directory (NSIS), /LOG=<file> appends
; each step's output to <file>; the uninstaller takes /S and /PURGE.

Unicode true
ManifestSupportedOS Win10
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include LogicLib.nsh
!include x64.nsh
!include FileFunc.nsh

!define APP "Localport"
!define PUBLISHER "Localport"
!define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Localport"
!define MUTEX "Global\LocalportSetup"

Name "${APP}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Localport"
InstallDirRegKey HKLM "${UNKEY}" "InstallLocation"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION4}"
VIFileVersion "${VERSION4}"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright Localport"

Var LogFile

; Step runs `localport system <args>` from EXE and stops the install on a
; non-zero exit, with the step's output in the details and the log. ARGS
; quotes paths with double quotes, so the messages use backticks.
!macro Step EXE ARGS
  nsExec::ExecToStack '"${EXE}" system ${ARGS}'
  Pop $0
  Pop $1
  DetailPrint `localport system ${ARGS}: exit $0`
  DetailPrint "$1"
  ${If} $LogFile != ""
    FileOpen $2 "$LogFile" a
    FileSeek $2 0 END
    FileWrite $2 `localport system ${ARGS}: exit $0$\r$\n$1$\r$\n`
    FileClose $2
  ${EndIf}
  ${If} $0 != 0
    SetErrorLevel $0
    Abort `localport system ${ARGS} failed (exit $0)`
  ${EndIf}
!macroend

; RequireSingle refuses a second installer or uninstaller running at once,
; exiting with Windows Installer's ERROR_INSTALL_ALREADY_RUNNING.
!macro RequireSingle
  System::Call 'kernel32::CreateMutexW(p 0, i 0, w "${MUTEX}") p .r0 ?e'
  Pop $1
  ${If} $1 == 183 ; ERROR_ALREADY_EXISTS
    SetErrorLevel 1618
    Abort "another Localport installer or uninstaller is running"
  ${EndIf}
!macroend

!macro Require64Bit
  ${IfNot} ${RunningX64}
    ; ERROR_INSTALL_PLATFORM_UNSUPPORTED
    SetErrorLevel 1633
    Abort "Localport needs 64-bit Windows"
  ${EndIf}
  SetRegView 64
  ${DisableX64FSRedirection}
!macroend

!macro ReadLogOption
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/LOG=" $LogFile
  ${If} ${Errors}
    StrCpy $LogFile ""
  ${EndIf}
!macroend

!ifdef WRITE_UNINSTALLER

; First pass: write uninstall.exe beside this program and exit.
Function .onInit
  WriteUninstaller "$EXEDIR\uninstall.exe"
  Quit
FunctionEnd

Section
SectionEnd

!else

Var Txn

Function .onInit
  !insertmacro Require64Bit
  !insertmacro RequireSingle
  !insertmacro ReadLogOption
FunctionEnd

Section "Install"
  ; Every step runs from the new localport.exe in $PLUGINSDIR, which NSIS
  ; creates admin-only, so a first install needs no earlier binary. The Go
  ; steps make every change as one transaction (internal/cli/system.go);
  ; NSIS only extracts the release into the transaction's staging directory.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${SRCDIR}\localport.exe"
  ; The transaction id is $PLUGINSDIR's base name, unique per run.
  ${GetFileName} "$PLUGINSDIR" $Txn
  !insertmacro Step "$PLUGINSDIR\localport.exe" 'begin "$INSTDIR" "$Txn"'

  ClearErrors
  SetOutPath "$INSTDIR\.localport-txn\$Txn\staging"
  File "${SRCDIR}\localport.exe"
  File "${SRCDIR}\localport-session.exe"
  ; Signed in the first pass, embedded here.
  File "${SRCDIR}\uninstall.exe"
  File "${SRCDIR}\LICENSE"
  File "${SRCDIR}\NOTICE"
  File "${SRCDIR}\THIRD_PARTY_NOTICES"
  ${If} ${Errors}
    ; Nothing outside staging changed yet; rollback removes the transaction.
    SetOutPath "$PLUGINSDIR"
    !insertmacro Step "$PLUGINSDIR\localport.exe" 'rollback "$INSTDIR"'
    SetErrorLevel 84
    Abort "extracting the release failed; nothing was changed"
  ${EndIf}
  SetOutPath "$PLUGINSDIR"
  ; apply rolls every change back itself when any step fails.
  !insertmacro Step "$PLUGINSDIR\localport.exe" 'apply "$INSTDIR" "$Txn"'
SectionEnd

!endif

; The uninstaller exists only in the first pass; the second embeds the
; signed uninstall.exe it wrote.
!ifdef WRITE_UNINSTALLER

Function un.onInit
  !insertmacro Require64Bit
  !insertmacro RequireSingle
  !insertmacro ReadLogOption
FunctionEnd

Section "Uninstall"
  ; Runs from a copy, so the transaction can move $INSTDIR\localport.exe.
  InitPluginsDir
  ClearErrors
  CopyFiles /SILENT "$INSTDIR\localport.exe" "$PLUGINSDIR\localport.exe"
  ${If} ${Errors}
    SetErrorLevel 89
    Abort "$INSTDIR\localport.exe is missing; nothing was changed"
  ${EndIf}
  SetOutPath "$PLUGINSDIR"
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $R1
  ${If} ${Errors}
    !insertmacro Step "$PLUGINSDIR\localport.exe" 'uninstall "$INSTDIR"'
  ${Else}
    !insertmacro Step "$PLUGINSDIR\localport.exe" 'uninstall "$INSTDIR" --purge'
  ${EndIf}
SectionEnd

!endif
