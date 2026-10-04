; Instalador del agente de Threat Hunting para Windows (Inno Setup 6).
; Lo compila el workflow .github/workflows/build-agent-windows.yml.
;
; Instalación desatendida (despliegue masivo):
;   ThreatHuntingAgent-Setup.exe /VERYSILENT /SERVER=https://mi-servidor /KEY=clave

#define AppVersion GetEnv("AGENT_VERSION")
#if AppVersion == ""
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6F1C2B7E-4D8A-4E2B-9C3F-1A2B3C4D5E6F}
AppName=Threat Hunting Agent
AppVersion={#AppVersion}
AppPublisher=Threat Hunting
DefaultDirName={autopf}\ThreatHuntingAgent
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=ThreatHuntingAgent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=Threat Hunting Agent
CloseApplications=no
SetupLogging=yes

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\..\dist\th_agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "register_task.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Solo SYSTEM y Administradores pueden leer la configuración y el token del agente
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\ThreatHuntingAgent"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\register_task.ps1"" -ExePath ""{app}\th_agent.exe"""; Flags: runhidden waituntilterminated; StatusMsg: "Iniciando el agente..."

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\register_task.ps1"" -Remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTask"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\ThreatHuntingAgent"

[Code]
var
  ServerPage: TInputQueryWizardPage;

function JsonEscape(S: String): String;
begin
  StringChangeEx(S, '\', '\\', True);
  StringChangeEx(S, '"', '\"', True);
  Result := S;
end;

function ServerUrl(): String;
begin
  Result := Trim(ServerPage.Values[0]);
  while (Length(Result) > 0) and (Result[Length(Result)] = '/') do
    Result := Copy(Result, 1, Length(Result) - 1);
end;

function ValidationError(): String;
var
  Url: String;
begin
  Result := '';
  Url := Lowercase(ServerUrl());
  if (Pos('http://', Url) <> 1) and (Pos('https://', Url) <> 1) then
    Result := 'La URL del servidor debe empezar por http:// o https://'
  else if Trim(ServerPage.Values[1]) = '' then
    Result := 'Indica la clave de enrolamiento (THL_ENROLL_KEY del servidor).';
end;

procedure InitializeWizard();
begin
  ServerPage := CreateInputQueryPage(wpWelcome,
    'Conexión con el servidor',
    '¿A qué servidor de Threat Hunting debe reportar este equipo?',
    'Escribe la dirección pública del servidor (por ejemplo https://mi-dominio.ngrok-free.app) ' +
    'y la clave de enrolamiento configurada en el servidor.');
  ServerPage.Add('URL del servidor:', False);
  ServerPage.Add('Clave de enrolamiento:', True);
  ServerPage.Values[0] := ExpandConstant('{param:SERVER|}');
  ServerPage.Values[1] := ExpandConstant('{param:KEY|}');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Err: String;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    Err := ValidationError();
    if Err <> '' then
    begin
      MsgBox(Err, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := ValidationError();  { cubre también la instalación desatendida }
  if Result <> '' then
    Exit;
  { detiene una versión anterior antes de sobrescribir los archivos }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN ThreatHuntingAgent', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM th_agent.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Dir: String;
  Lines: TArrayOfString;
begin
  if CurStep = ssInstall then
  begin
    Dir := ExpandConstant('{commonappdata}\ThreatHuntingAgent');
    ForceDirectories(Dir);
    SetArrayLength(Lines, 5);
    Lines[0] := '{';
    Lines[1] := '  "server": "' + JsonEscape(ServerUrl()) + '",';
    Lines[2] := '  "enroll_key": "' + JsonEscape(Trim(ServerPage.Values[1])) + '",';
    Lines[3] := '  "interval": 60';
    Lines[4] := '}';
    if not SaveStringsToUTF8File(Dir + '\config.json', Lines, False) then
      MsgBox('No se pudo escribir ' + Dir + '\config.json', mbError, MB_OK);
  end;
end;
