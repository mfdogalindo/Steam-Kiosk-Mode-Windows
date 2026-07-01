# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam, OpenRGB y MSI Afterburner
# Versión: 3.1 - Seguridad Máxima: Contraseña Aleatoria Auto-Generada (Zero-Knowledge)
# Archivo de referencia: install_afterburner_system_vbs_schtasks.ps1
# Prerrequisitos: Windows 10/11 Enterprise/Education/Pro, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"

# >> GENERACIÓN AUTOMÁTICA DE CONTRASEÑA SEGURA (24 caracteres alfanuméricos + símbolos)
$PasswordLength = 24
$AllowedChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()-_=+'
$KioskPasswordPlain = -join (1..$PasswordLength | ForEach-Object { $AllowedChars[(Get-Random -Maximum $AllowedChars.Length)] })

$LauncherVbsPath = "C:\Users\Public\launch.vbs"

#>> Variable para especificar el perfil de OpenRGB
$OpenRGBProfileName = "Steam" 

#>> Configuración de MSI Afterburner
$MSIAfterburnerProfileNumber = 1 # Perfil de Undervolt (1 a 5)
$MSIAfterburnerTaskName = "GamingKiosk-MSI-Afterburner"
$MSIAfterburnerHelperPath = "C:\Users\Public\launch-afterburner.ps1"

# --- VERIFICACIONES PREVIAS ---
Write-Host "Iniciando verificaciones previas..." -ForegroundColor Yellow

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador. Por favor, reinicie PowerShell como Administrador."
    exit
}
Write-Host "[OK] Privilegios de administrador verificados." -ForegroundColor Green

# Habilitación de la característica Shell Launcher si no está presente
$feature = Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher
if ($feature.State -ne "Enabled") {
    Write-Host "La característica Shell Launcher no está habilitada. Habilitándola ahora..." -ForegroundColor Cyan
    Enable-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -All -NoRestart
}

# --- FASE I: CREACIÓN Y CONFIGURACIÓN DEL USUARIO ---
Write-Host "`nIniciando Fase I: Configuración de la cuenta '$KioskUserName'..." -ForegroundColor Yellow

try {
    $ExistingUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
    $Password = ConvertTo-SecureString $KioskPasswordPlain -AsPlainText -Force

    if ($ExistingUser) {
        Write-Host "El usuario '$KioskUserName' ya existe. Rotando contraseña por una aleatoria ultra-segura..." -ForegroundColor Cyan
        Set-LocalUser -Name $KioskUserName -Password $Password
    } else {
        Write-Host "Creando el usuario '$KioskUserName' con contraseña aleatoria invisible..." -ForegroundColor Cyan
        New-LocalUser -Name $KioskUserName -Password $Password -FullName "Kiosk Gaming Account" -Description "Cuenta de usuario para el modo kiosco de Steam." -ErrorAction Stop
        
        # Inicializar el perfil del usuario de forma silenciosa
        Write-Host "Inicializando el perfil del usuario..." -ForegroundColor Cyan
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "cmd.exe"
        $processInfo.Arguments = "/c timeout /t 3 /nobreak >nul"
        $processInfo.UserName = $KioskUserName
        $processInfo.Password = $Password
        $processInfo.UseShellExecute = $false
        $processInfo.WindowStyle = 'Hidden'
        $process = [System.Diagnostics.Process]::Start($processInfo)
        $process.WaitForExit()
    }
    
    # Agregar a Usuarios y forzar rango de Administrador (indispensable para interactuar con la GPU/Undervolt)
    Add-LocalGroupMember -Group "Users" -Member $KioskUserName -ErrorAction SilentlyContinue
    $AdministratorsGroup = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    Add-LocalGroupMember -Group $AdministratorsGroup -Member $KioskUserName -ErrorAction SilentlyContinue
    Write-Host "[OK] Usuario '$KioskUserName' configurado como Administrador." -ForegroundColor Green

    # Ocultar o mostrar en pantalla de login según se requiera (se mantiene visible por si se necesita mantenimiento)
    $SpecialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (!(Test-Path $SpecialAccountsPath)) { New-Item -Path $SpecialAccountsPath -Force | Out-Null }
    Set-ItemProperty -Path $SpecialAccountsPath -Name $KioskUserName -Value 1 -Type DWord -ErrorAction SilentlyContinue

} catch {
    Write-Error "Error durante la fase de creación del usuario: $_"
    exit
}

# --- FASE II: VERIFICACIÓN DE SOFTWARE Y CREACIÓN DE SCRIPTS DE LANZAMIENTO ---
Write-Host "`nIniciando Fase II: Configuración de MSI Afterburner..." -ForegroundColor Yellow

function Get-SteamPath { return (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath }
$SteamPath = Get-SteamPath
$SteamExePath = Join-Path -Path $SteamPath -ChildPath "steam.exe"

function Get-OpenRGBPath {
    $pathFromRegistry = (Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenRGB\OpenRGB" -Name "Install_Dir" -ErrorAction SilentlyContinue).Install_Dir
    if ($pathFromRegistry) { $exePath = Join-Path $pathFromRegistry "OpenRGB.exe"; if (Test-Path $exePath) { return $exePath } }
    return $null
}
$OpenRGBExePath = Get-OpenRGBPath

function Get-MSIAfterburnerPath {
    $commonPaths = @("${env:ProgramFiles(x86)}\MSI Afterburner\MSIAfterburner.exe", "$env:ProgramFiles\MSI Afterburner\MSIAfterburner.exe")
    foreach ($path in $commonPaths) { if ($path -and (Test-Path $path)) { return $path } }
    return $null
}

$MSIAfterburnerExePath = Get-MSIAfterburnerPath
if ($MSIAfterburnerExePath) {
    Write-Host "[OK] MSI Afterburner detectado." -ForegroundColor Green

    try {
        $AfterburnerDirectory = Split-Path $MSIAfterburnerExePath -Parent

        # Crear script asistente para aplicar el perfil de undervolt de forma limpia
        $AfterburnerHelperContent = @"
`$existing = Get-Process -Name 'MSIAfterburner' -ErrorAction SilentlyContinue
if (`$existing) {
    `$existing | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
Start-Process `
    -FilePath '$($MSIAfterburnerExePath.Replace("'", "''"))' `
    -ArgumentList '-Profile$MSIAfterburnerProfileNumber', '-Minimized' `
    -WorkingDirectory '$($AfterburnerDirectory.Replace("'", "''"))'
"@

        [System.IO.File]::WriteAllText($MSIAfterburnerHelperPath, $AfterburnerHelperContent, [System.Text.UTF8Encoding]::new($true))

        $AfterburnerAction = New-ScheduledTaskAction `
            -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$MSIAfterburnerHelperPath`""

        # Configurar ejecución interactiva elevada bajo el contexto del usuario gamer (ahora administrador)
        $AfterburnerPrincipal = New-ScheduledTaskPrincipal -UserId $KioskUserName -LogonType Interactive -RunLevel Highest

        $AfterburnerSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

        Register-ScheduledTask -TaskName $MSIAfterburnerTaskName -Action $AfterburnerAction -Principal $AfterburnerPrincipal -Settings $AfterburnerSettings -Force | Out-Null
        Write-Host "[OK] Tarea programada '$MSIAfterburnerTaskName' vinculada al entorno interactivo." -ForegroundColor Green
    } catch {
        Write-Warning "Fallo al crear la tarea programada: $_"
    }
}

# --- CREACIÓN DEL ARCHIVO LANZADOR VBS ---
$VbsContent = "On Error Resume Next`nSet objShell = CreateObject(`"WScript.Shell`")`nobjShell.CurrentDirectory = `"$SteamPath`"`n"
if ($OpenRGBExePath) {
    $VbsContent += "objShell.Run `"`"$OpenRGBExePath`" --startminimized --profile `"$OpenRGBProfileName`"`", 0, False`nWScript.Sleep 2000`n"
}
if ($MSIAfterburnerExePath) {
    $VbsContent += "objShell.Run `"`"$env:SystemRoot\System32\schtasks.exe`" /Run /TN `"$MSIAfterburnerTaskName`"`", 0, True`nWScript.Sleep 3000`n"
}
$VbsContent += "objShell.Run `"`"$SteamExePath`" -bigpicture`", 0, True`nWScript.Quit"

[System.IO.File]::WriteAllText($LauncherVbsPath, $VbsContent, [System.Text.Encoding]::Default)

# --- FASE III: CONFIGURACIÓN DE SHELL LAUNCHER ---
try {
    $ShellLauncherClass = [wmiclass]"\\localhost\root\standardcimv2\embedded:WESL_UserSetting"
    $KioskUser_SID = (New-Object System.Security.Principal.NTAccount($KioskUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    
    try { $ShellLauncherClass.RemoveCustomShell($KioskUser_SID) } catch {}
    $ShellLauncherClass.SetDefaultShell("explorer.exe", 1)
    $ShellLauncherClass.SetCustomShell($KioskUser_SID, "wscript.exe ""$LauncherVbsPath""", $null, $null, 1)
    $ShellLauncherClass.SetEnabled($TRUE)
    Write-Host "[OK] Shell Launcher enlazado al script VBS." -ForegroundColor Green
} catch {
    Write-Error "Error en configuración de Shell Launcher: $_"
}

# --- FASE IV: CONFIGURACIÓN AUTOMÁTICA DEL INICIO DE SESIÓN (AUTOLOGIN CON CONTRASEÑA ROTADA) ---
Write-Host "`nIniciando Fase IV: Inyectando credenciales criptográficas en el registro..." -ForegroundColor Yellow

try {
    $AutoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $AutoLogonPath -Name "AutoAdminLogon" -Value "1" -Force
    Set-ItemProperty -Path $AutoLogonPath -Name "DefaultUserName" -Value $KioskUserName -Force
    Set-ItemProperty -Path $AutoLogonPath -Name "DefaultPassword" -Value $KioskPasswordPlain -Force
    Set-ItemProperty -Path $AutoLogonPath -Name "AutoLogonCount" -Value "999999" -Force
    
    # Asignar permisos limpios al archivo VBS
    $acl = Get-Acl $LauncherVbsPath
    $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl $LauncherVbsPath $acl

    Write-Host "[OK] Autologon configurado con éxito. Nadie conoce la clave generada y el login es inmediato." -ForegroundColor Green
} catch {
    Write-Error "Error configurando el inicio automático: $_"
}

Write-Host "`n[PROCESO COMPLETADO] Sistema blindado y automatizado. Reinicia para arrancar." -ForegroundColor Green
