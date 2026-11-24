#define AppName "CryptoGuard"
#define AppVersion "1.0.1"

[Setup]
; Retain the original AppId so future releases can upgrade an existing installation.
AppId={{B87B671C-FA7C-41C1-A8A6-FF6AEB6D0342}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Shresth & Pratyush
AppComments=Cryptojacking Detector - KCC ITM mini project
DefaultDirName={localappdata}\Programs\CryptoGuard
DefaultGroupName=CryptoGuard
OutputDir=installer
OutputBaseFilename=CryptoGuard-Setup-{#AppVersion}
SetupIconFile=app-icon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
WizardStyle=modern
UninstallDisplayIcon={app}\CryptoGuard.exe
DisableProgramGroupPage=yes

[Files]
; Install the entire existing PyInstaller folder, including _internal.
Source: "dist\CryptoGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Icons]
Name: "{autoprograms}\CryptoGuard"; Filename: "{app}\CryptoGuard.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\CryptoGuard"; Filename: "{app}\CryptoGuard.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\CryptoGuard.exe"; Description: "Launch CryptoGuard"; Flags: nowait postinstall skipifsilent
