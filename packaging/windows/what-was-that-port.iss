#define AppName "What Was That Port"
#define AppVersion "0.2.0"
#define AppPublisher "what-was-that-port contributors"
#define AppExeName "what-was-that-port.exe"

[Setup]
AppId={{9AEB5611-3C0D-4CB3-9F8F-000000020000}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\What Was That Port
DefaultGroupName={#AppName}
OutputDir=..\..\dist\windows-installer
OutputBaseFilename=what-was-that-port-{#AppVersion}-setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest

[Files]
Source: "..\..\dist\windows\what-was-that-port.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\windows\what-was-that-port-worker.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
