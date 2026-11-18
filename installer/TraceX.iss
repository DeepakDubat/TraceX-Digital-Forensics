; Script generated for TraceX – Digital Forensics & Cyber Investigation Suite
; Inno Setup 6 / 7 compatible script

#define MyAppName "TraceX – Digital Forensics & Cyber Investigation Suite"
#define MyAppShortName "TraceX"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "TraceX Cyber Investigation Labs"
#define MyAppURL "https://tracex-forensics.local"
#define MyAppExeName "TraceX.exe"
#define SourceDir "..\dist\TraceX"

[Setup]
AppId={{C8E1B9A2-4D3F-4F8A-9A7B-2E3D4C5B6A7F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\TraceX
DefaultGroupName={#MyAppShortName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=TraceX-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=installer_assets\app_icon.ico

[Types]
Name: "standard"; Description: "Standard Installation (Recommended: Bundled Application, Runtimes, and Rule Sets)"; Flags: iscustom
Name: "minimal"; Description: "Minimal Installation (Application and Bundled Runtime Only)"

[Components]
Name: "core"; Description: "TraceX Desktop Application & Headless Backend Engine"; Types: minimal standard; Flags: fixed
Name: "rules"; Description: "Production YARA Signatures & Multi-Platform Threat Rules"; Types: standard

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startmenuicon"; Description: "Create Start Menu Shortcuts"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: core
Source: "tool_manifest.json"; DestDir: "{app}\installer"; Flags: ignoreversion; Components: core

[Icons]
Name: "{group}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{group}\{cm:UninstallProgram,{#MyAppShortName}}"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppShortName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// Explicit check to preserve user forensic cases and evidence during uninstallation
function InitializeUninstall(): Boolean;
var
  DataDir: String;
begin
  Result := True;
  DataDir := ExpandConstant('{localappdata}\TraceX');
  if DirExists(DataDir) then
  begin
    MsgBox('TraceX will now be uninstalled.' + #13#10#13#10 +
           'IMPORTANT: Your investigation cases, evidence records, and Chain-of-Custody logs in:' + #13#10 +
           DataDir + #13#10#13#10 +
           'have been PRESERVED and will NOT be erased.', mbInformation, MB_OK);
  end;
end;

