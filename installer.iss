#define MyAppName "LogAI"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "NPC520"
#define MyAppURL "https://github.com/NPC520/LogAI"
#define MyAppExeName "LogAI.exe"

[Setup]
AppId={{8F3A2C45-6D7E-4A9B-A1C2-E5F678901235}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
SetupIconFile=E:\LogAI\icon.ico
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=.\Output
OutputBaseFilename=LogAI_Setup_{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
PrivilegesRequired=lowest
DisableDirPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons"

[Files]
Source: "dist\LogAI.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch LogAI"; Flags: nowait postinstall skipifsilent