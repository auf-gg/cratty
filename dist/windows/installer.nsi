; NSIS installer for Cratty.
; Invoked from CI (.github/workflows/build.yml) with defines:
;   makensis -DVERSION=<x.y.z> -DARCH=<x86_64|aarch64> -DBINDIR=target/release \
;            -DICON=assets/cratty.ico -DLICENSEFILE=LICENSE dist/windows/installer.nsi
;
; The in-app updater (src/update.rs) downloads this installer and runs it with
; /S: the old cratty.exe is replaced once the app exits, then the new version
; is started.

!include "MUI2.nsh"

!ifndef VERSION
  !error "VERSION is not set (pass -DVERSION=...)"
!endif

# CI passes -DOUTFILE=<workspace>/cratty-<version>-<arch>-setup.exe so the
# installer always lands where the artifact upload glob expects it.
!ifndef OUTFILE
  !define OUTFILE "cratty-${VERSION}-${ARCH}-setup.exe"
!endif

!define APPNAME "Cratty"
!define PUBLISHER "auf-gg"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
Unicode true
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\${APPNAME}"
InstallDirRegKey HKCU "Software\${APPNAME}" "InstallDir"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_FINISHPAGE_RUN "$INSTDIR\cratty.exe"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSEFILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

Section "${APPNAME}" SecInstall
  SectionIn RO
  SetOutPath "$INSTDIR"
  ; Wait up to ~10 s for a running cratty.exe (e.g. the one that started the
  ; update) to exit and release the file.
  StrCpy $0 0
  wait:
  ClearErrors
  Delete "$INSTDIR\cratty.exe"
  IfErrors 0 free
  IntOp $0 $0 + 1
  IntCmp $0 50 free
  Sleep 200
  Goto wait
  free:
  File "${BINDIR}\cratty.exe"
  File /oname=LICENSE.txt "${LICENSEFILE}"

  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\cratty.exe"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKCU "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$INSTDIR\cratty.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""

  ; Silent install = in-app update: start the new version.
  IfSilent 0 +2
  Exec '"$INSTDIR\cratty.exe"'
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${APPNAME}"
  Delete "$INSTDIR\cratty.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
  DeleteRegKey HKCU "Software\${APPNAME}"
SectionEnd
