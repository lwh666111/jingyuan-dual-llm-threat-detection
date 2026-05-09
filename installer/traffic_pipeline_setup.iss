#define MyAppName "靖渊 AI 攻击态势感知平台"
#define MyAppNameEn "Jingyuan AI Threat Perception Platform"
#define MyAppPublisher "Jingyuan Security Team"
#define MyAppURL "https://github.com/lwh666111/jingyuan-dual-llm-threat-detection"
#define MyAppExe "install_oneclick.bat"
#ifndef SourceRoot
  #define SourceRoot ".."
#endif

[Setup]
AppId={{ED0F9EA4-CE11-4D6A-AB4C-DFA5A759E8D2}
AppName={#MyAppName}
AppVersion=2026.05
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\JingyuanTrafficPipeline
DefaultGroupName={#MyAppName}
DisableDirPage=no
DisableProgramGroupPage=yes
LicenseFile={#SourceRoot}\LICENSE
OutputDir={#SourceRoot}\dist
OutputBaseFilename=JingyuanTrafficPipeline_Setup_ManualDeps
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupLogging=yes
CloseApplications=yes
CloseApplicationsFilter=python.exe,node.exe,powershell.exe,cmd.exe
ChangesEnvironment=yes

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务"; Flags: unchecked

[Files]
; Excludes large runtime/cache/repo metadata
Source: "{#SourceRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: ".git\*,.github\*,dist\*,installer\build\*,output\*,input\*,result\*,result_threshold_test\*,__pycache__\*,.venv\*,venv\*,node_modules\*,*.pyc,*.pyo,*.log,*.tmp,llm\rag\*.db,llm\rag\*.db-*"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppNameEn}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "立即执行一键环境安装并启动平台"; Flags: postinstall skipifsilent
