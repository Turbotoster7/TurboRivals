; TurboRivals - Inno Setup script
;
; Builds dist\TurboRivalsSetup.exe out of the one-folder PyInstaller build in
; dist\TurboRivals. Run it through ..\build.ps1, which makes that folder first.
;
; Per-user on purpose: PrivilegesRequired=lowest installs into
; %LOCALAPPDATA%\Programs without a UAC prompt. The launcher needs
; administrator rights only at runtime, for the hosts file and the firewall,
; and it asks for them itself with its own ELEVATE button.

#define AppName      "TurboRivals"
; Read from ..\VERSION so the setup, the exe resource and the launcher window
; can never disagree about which build this is.
#define VerFile FileOpen("..\VERSION")
#define AppVersion Trim(FileRead(VerFile))
#expr FileClose(VerFile)
#if AppVersion == ""
  #error Could not read the version from ..\VERSION
#endif
#define AppPublisher "TurboRivals"
#define AppExe       "TurboRivals.exe"

[Setup]
AppId={{8F3A6C21-4E7B-4D59-9A2C-1B5E0F7D3A88}
AppName={#AppName}
AppVersion={#AppVersion}
; Without this, Inno's default AppVerName makes "Apps & features" read
; "TurboRivals version 1.0.0 1.0.0" - the version is its own column already.
AppVerName={#AppName}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=TurboRivalsSetup-{#AppVersion}
SetupIconFile=..\launcher\web\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\{#AppName}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; There is deliberately no [UninstallDelete]: saved progress, player names and
; the certificate live in %LOCALAPPDATA%\TurboRivals and stay behind on
; uninstall. That is the user's data, not installation leftovers.
;
; [Code] has to stay last - everything below it is Pascal, including what would
; otherwise look like a comment line.

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  { Take the hosts redirect down BEFORE the files go, while the exe that knows
    how to do it still exists. A leftover "gosredirector.ea.com" entry breaks
    the EA App and every other EA game, and the user would have just deleted
    the only tool that removes it.

    It needs administrator rights, so it may well fail - that is fine and not
    worth stopping an uninstall over. We only say so, and only then. }
  if CurUninstallStep = usUninstall then
  begin
    if Exec(ExpandConstant('{app}\{#AppExe}'), '--hosts-off', '',
            SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      if ResultCode <> 0 then
        MsgBox('Could not take the hosts redirect down (administrator rights '
               + 'are needed for that).'#13#10#13#10
               + 'If the game or the EA App misbehaves afterwards, remove the '
               + 'TurboRivals block from:'#13#10
               + 'C:\Windows\System32\drivers\etc\hosts',
               mbInformation, MB_OK);
    end;
  end;
end;
