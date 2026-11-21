; Benign NSIS test installer for the REA sweep's installer unpacking (never run).
; payload.exe = sample.exe (the program the script executes); helper.dll = sample.exe
; padded with zeros, so it is the LARGEST PE member but not the one executed.
Unicode true
SetCompressor /SOLID lzma
SetDateSave off
Name "Loadout Fixture"
OutFile "installer.exe"
InstallDir "$LOCALAPPDATA\LoadoutFixture"
RequestExecutionLevel user
Page instfiles
Section "Main"
  SetOutPath "$INSTDIR"
  File "payload.exe"
  File "helper.dll"
  File "readme.txt"
  WriteRegStr HKCU "Software\LoadoutFixture" "Path" "$INSTDIR\payload.exe"
  ExecWait '"$INSTDIR\payload.exe" --fixture'
SectionEnd
