; Localport Windows installer (NSIS 3.13, no third-party plugins).
;
; The installer only extracts files, writes the uninstaller and the Add/Remove
; Programs key, and runs the `localport system` steps (internal/cli/system.go)
; from the new localport.exe, checking each exit status. It never enrols a
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

; RequireSingle refuses a second installer or uninstaller running at once.
!macro RequireSingle
  System::Call 'kernel32::CreateMutexW(p 0, i 0, w "${MUTEX}") p .r0 ?e'
  Pop $1
  ${If} $1 == 183 ; ERROR_ALREADY_EXISTS
    SetErrorLevel 3
    Abort "another Localport installer or uninstaller is running"
  ${EndIf}
!macroend

!macro Require64Bit
  ${IfNot} ${RunningX64}
    SetErrorLevel 2
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

Var Staging

Function .onInit
  !insertmacro Require64Bit
  !insertmacro RequireSingle
  !insertmacro ReadLogOption
FunctionEnd

Section "Install"
  ; Every step runs from the new localport.exe in $PLUGINSDIR, which NSIS
  ; creates admin-only, so a first install needs no earlier binary.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${SRCDIR}\localport.exe"
  !insertmacro Step "$PLUGINSDIR\localport.exe" 'preflight "$INSTDIR"'

  ; The staging directory's name is unique per run ($PLUGINSDIR's).
  ${GetFileName} "$PLUGINSDIR" $R1
  StrCpy $Staging ".staging-$R1"
  SetOutPath "$INSTDIR\$Staging"
  File "${SRCDIR}\localport.exe"
  File "${SRCDIR}\localport-session.exe"

  !insertmacro Step "$PLUGINSDIR\localport.exe" 'stop "$INSTDIR"'
  !insertmacro Step "$PLUGINSDIR\localport.exe" 'commit "$INSTDIR" "$Staging"'

  SetOutPath "$INSTDIR"
  File "${SRCDIR}\LICENSE"
  File "${SRCDIR}\NOTICE"
  File "${SRCDIR}\THIRD_PARTY_NOTICES"
  ; Signed in the first pass, embedded here.
  File "${SRCDIR}\uninstall.exe"

  WriteRegStr HKLM "${UNKEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNKEY}" "DisplayIcon" '"$INSTDIR\localport.exe"'
  WriteRegStr HKLM "${UNKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNKEY}" "EstimatedSize" "$0"

  !insertmacro Step "$INSTDIR\localport.exe" 'path add "$INSTDIR"'
  !insertmacro Step "$INSTDIR\localport.exe" 'reregister "$INSTDIR"'
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
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $R1
  ${If} ${Errors}
    !insertmacro Step "$INSTDIR\localport.exe" 'preuninstall "$INSTDIR"'
  ${Else}
    !insertmacro Step "$INSTDIR\localport.exe" 'preuninstall "$INSTDIR" --purge'
  ${EndIf}
  !insertmacro Step "$INSTDIR\localport.exe" 'path remove "$INSTDIR"'

  Delete "$INSTDIR\localport.exe"
  Delete "$INSTDIR\localport-session.exe"
  Delete "$INSTDIR\localport.exe.old"
  Delete "$INSTDIR\localport-session.exe.old"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD_PARTY_NOTICES"
  Delete "$INSTDIR\uninstall.exe"
  DeleteRegKey HKLM "${UNKEY}"
  ; Only when empty: anything else in the directory is not ours to remove.
  RMDir "$INSTDIR"
SectionEnd

!endif
