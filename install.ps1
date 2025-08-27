# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam y OpenRGB
# Versión: 2.2 - CORREGIDO - Soluciona problema de ejecución del VBS
# Autor: Especialista en Automatización de Sistemas (Corregido por Claude)
# Prerrequisitos: Windows 10/11 Enterprise/Education/Pro, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"
$LauncherVbsPath = "C:\Users\Public\launch.vbs"

#>> Variable para especificar el perfil de OpenRGB
$OpenRGBProfileName = "Steam" # Ejemplo: "Steam", "GamingDefault", etc.

# --- VERIFICACIONES PREVIAS ---
Write-Host "Iniciando verificaciones previas..." -ForegroundColor Yellow

# Verificación de privilegios de administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador. Por favor, reinicie PowerShell como Administrador."
    exit
}
Write-Host "[OK] Privilegios de administrador verificados." -ForegroundColor Green

# Verificar edición de Windows
$WindowsEdition = (Get-WmiObject -Class Win32_OperatingSystem).Caption
Write-Host "Edición de Windows detectada: $WindowsEdition" -ForegroundColor Cyan
if ($WindowsEdition -notmatch "Enterprise|Education|Pro") {
    Write-Warning "Shell Launcher podría no ser compatible con su edición de Windows. Se requiere Enterprise, Education o Pro."
}

# Habilitación de la característica Shell Launcher si no está presente
$feature = Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher
if ($feature.State -ne "Enabled") {
    Write-Host "La característica Shell Launcher no está habilitada. Habilitándola ahora..." -ForegroundColor Cyan
    Enable-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -All -NoRestart
    Write-Host "[OK] Característica Shell Launcher habilitada. Se recomienda reiniciar el sistema después de completar el script." -ForegroundColor Green
} else {
    Write-Host "[OK] La característica Shell Launcher ya está habilitada." -ForegroundColor Green
}

# --- FASE I: CREACIÓN Y CONFIGURACIÓN DEL USUARIO ---
Write-Host "`nIniciando Fase I: Creación y configuración de la cuenta de usuario '$KioskUserName'..." -ForegroundColor Yellow

try {
    $ExistingUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
    if ($ExistingUser) {
        Write-Host "El usuario '$KioskUserName' ya existe. Se omitirá la creación." -ForegroundColor Cyan
    } else {
        Write-Host "Creando el usuario '$KioskUserName'..." -ForegroundColor Cyan
        
        Write-Host "Se requiere una contraseña temporal para crear e inicializar correctamente el perfil del usuario." -ForegroundColor Yellow
        Write-Host "Al final del script, tendrá la opción de eliminarla para permitir el inicio de sesión automático." -ForegroundColor Yellow
        do {
            $Password = Read-Host -AsSecureString "Introduzca una contraseña para '$KioskUserName' (mín. 8 caracteres)"
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            
            if ($PlainPassword.Length -lt 8) {
                Write-Warning "La contraseña debe tener al menos 8 caracteres."
            }
        } while ($PlainPassword.Length -lt 8)
        
        New-LocalUser -Name $KioskUserName -Password $Password -FullName "Kiosk Gaming Account" -Description "Cuenta de usuario para el modo kiosco de Steam."
        Write-Host "[OK] Usuario '$KioskUserName' creado exitosamente." -ForegroundColor Green
        
        # Inicializar el perfil del usuario
        Write-Host "Inicializando el perfil del usuario '$KioskUserName'..." -ForegroundColor Cyan
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "cmd.exe"
        $processInfo.Arguments = "/c timeout /t 5 /nobreak >nul"
        $processInfo.UserName = $KioskUserName
        $processInfo.Password = $Password
        $processInfo.UseShellExecute = $false
        $processInfo.WindowStyle = 'Hidden'
        $process = [System.Diagnostics.Process]::Start($processInfo)
        $process.WaitForExit()
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        if (Test-Path "C:\Users\$KioskUserName\AppData") {
            Write-Host "[OK] El perfil de usuario ha sido inicializado correctamente." -ForegroundColor Green
        } else {
            Write-Warning "No se pudo verificar la inicialización del perfil de usuario."
        }
    }
    
    # Asegurar visibilidad en la pantalla de login
    Add-LocalGroupMember -Group "Users" -Member $KioskUserName -ErrorAction SilentlyContinue
    $SpecialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (!(Test-Path $SpecialAccountsPath)) {
        New-Item -Path $SpecialAccountsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $SpecialAccountsPath -Name $KioskUserName -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[OK] Usuario configurado como visible en la pantalla de login." -ForegroundColor Green

} catch {
    Write-Error "Error durante la fase de creación del usuario. Detalles: $_"
    exit
}

# --- FASE II: VERIFICACIÓN DE SOFTWARE Y CREACIÓN DE SCRIPTS DE LANZAMIENTO ---
Write-Host "`nIniciando Fase II: Verificación de software y creación de scripts de lanzamiento..." -ForegroundColor Yellow

# Función para obtener la ruta de Steam
function Get-SteamPath {
    return (Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath
}

$SteamPath = Get-SteamPath
if (-not $SteamPath) {
    Write-Error "No se encontró la instalación de Steam. Por favor, instale Steam y vuelva a ejecutar el script."
    exit
}
$SteamExePath = Join-Path -Path $SteamPath -ChildPath "steam.exe"
Write-Host "[OK] Ruta de Steam encontrada: $SteamExePath" -ForegroundColor Green

# Buscar OpenRGB
function Get-OpenRGBPath {
    $pathFromRegistry = (Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenRGB\OpenRGB" -Name "Install_Dir" -ErrorAction SilentlyContinue).Install_Dir
    if ($pathFromRegistry) {
        $exePath = Join-Path $pathFromRegistry "OpenRGB.exe"
        if (Test-Path $exePath) { return $exePath }
    }
    # Búsqueda alternativa
    $commonPaths = @(
        "$env:ProgramFiles\OpenRGB\OpenRGB.exe",
        "$env:ProgramFiles(x86)\OpenRGB\OpenRGB.exe"
    )
    foreach ($path in $commonPaths) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

$OpenRGBExePath = Get-OpenRGBPath
if ($OpenRGBExePath) {
    Write-Host "[OK] Ruta de OpenRGB encontrada: $OpenRGBExePath" -ForegroundColor Green
} else {
    Write-Warning "No se encontró la instalación de OpenRGB. Se omitirá su lanzamiento."
}

# CORRECCIÓN PRINCIPAL: Crear VBS con sintaxis correcta y manejo robusto
$VbsContent = @"
On Error Resume Next

Set objShell = CreateObject("WScript.Shell")

' Cambiar al directorio de Steam para evitar problemas de ruta
objShell.CurrentDirectory = "$SteamPath"

"@

if ($OpenRGBExePath) {
    if (-not [string]::IsNullOrWhiteSpace($OpenRGBProfileName)) {
        $VbsContent += @"

' Lanzar OpenRGB con perfil específico
objShell.Run """$OpenRGBExePath"" --startminimized --profile ""$OpenRGBProfileName""", 0, False
WScript.Sleep 2000

"@
        Write-Host "OpenRGB se configurará para cargar el perfil: '$OpenRGBProfileName'" -ForegroundColor Cyan
    } else {
        $VbsContent += @"

' Lanzar OpenRGB sin perfil específico
objShell.Run """$OpenRGBExePath"" --startminimized", 0, False
WScript.Sleep 2000

"@
        Write-Host "OpenRGB se configurará para iniciar minimizado sin un perfil específico." -ForegroundColor Cyan
    }
}

$VbsContent += @"

' Lanzar Steam en modo Big Picture y esperar
' CRÍTICO: Usar True para esperar que Steam termine antes de que el script VBS termine
' Esto mantiene el proceso shell activo
objShell.Run """$SteamExePath"" -bigpicture", 0, True

' Si Steam se cierra, el script termina y Shell Launcher puede reiniciarlo
WScript.Quit
"@

# Crear el archivo VBS con la sintaxis corregida
try {
    # Usar codificación ANSI para evitar problemas con caracteres especiales
    [System.IO.File]::WriteAllText($LauncherVbsPath, $VbsContent, [System.Text.Encoding]::Default)
    Write-Host "[OK] Script VBS creado en: $LauncherVbsPath" -ForegroundColor Green
} catch {
    Write-Error "No se pudo crear el script VBS. Detalles: $_"
    exit
}

# --- FASE III: CONFIGURACIÓN DE SHELL LAUNCHER ---
Write-Host "`nIniciando Fase III: Configuración de Shell Launcher..." -ForegroundColor Yellow

$COMPUTER = "localhost"
$NAMESPACE = "root\standardcimv2\embedded"
$restart_shell = 1 # MANTENER: Reinicia el shell si se cierra para mayor estabilidad

function Get-UsernameSID($AccountName) {
    try {
        return (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Error "No se pudo obtener el SID para la cuenta '$AccountName'. Detalles: $_"
        return $null
    }
}

try {
    $ShellLauncherClass = [wmiclass]"\\$COMPUTER\${NAMESPACE}:WESL_UserSetting"
    $KioskUser_SID = Get-UsernameSID($KioskUserName)
    if (-not $KioskUser_SID) { exit }

    Write-Host "[OK] SID para '$KioskUserName' obtenido: $KioskUser_SID" -ForegroundColor Green

    # Limpiar configuraciones previas para este usuario
    try {
        $ShellLauncherClass.RemoveCustomShell($KioskUser_SID)
        Write-Host "Limpiando configuración de Shell Launcher previa para el usuario." -ForegroundColor Cyan
    } catch {}

    # Configurar el shell predeterminado (explorer.exe) para todos los demás
    $ShellLauncherClass.SetDefaultShell("explorer.exe", $restart_shell)
    Write-Host "[OK] Shell predeterminado configurado como 'explorer.exe'." -ForegroundColor Green

    # CRÍTICO: Usar wscript.exe para ejecutar el VBS, no directamente el archivo VBS
    $ShellLauncherClass.SetCustomShell($KioskUser_SID, "wscript.exe ""$LauncherVbsPath""", $null, $null, $restart_shell)
    Write-Host "[OK] Shell personalizado para '$KioskUserName' configurado para ejecutar VBS con wscript.exe." -ForegroundColor Green

    # Habilitar Shell Launcher
    $ShellLauncherClass.SetEnabled($TRUE)
    if (($ShellLauncherClass.IsEnabled()).Enabled) {
        Write-Host "[OK] Shell Launcher ha sido habilitado." -ForegroundColor Green
    } else {
        Write-Warning "No se pudo habilitar Shell Launcher."
    }

} catch {
    Write-Error "Ocurrió un error durante la configuración de WMI. Detalles: $_"
    exit
}

# --- CONFIGURACIÓN ADICIONAL PARA SOLUCIONAR PANTALLA NEGRA ---
Write-Host "`nConfigurando ajustes adicionales para prevenir pantalla negra..." -ForegroundColor Yellow

# Configurar el registro para mejorar la inicialización del usuario
$UserInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Asegurar que Userinit se ejecute correctamente
Set-ItemProperty -Path $UserInitPath -Name "Userinit" -Value "C:\Windows\system32\userinit.exe," -Force
Write-Host "[OK] Configuración de Userinit verificada." -ForegroundColor Green

# Configurar políticas de grupo locales para el usuario kiosco si es necesario
$PolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (!(Test-Path $PolicyPath)) {
    New-Item -Path $PolicyPath -Force | Out-Null
}

# --- CONFIGURACIÓN ADICIONAL PARA VBS ---
Write-Host "`nConfigurando permisos y asociaciones para archivos VBS..." -ForegroundColor Yellow

# Verificar que WScript está disponible y configurado correctamente
$WScriptPath = "$env:SystemRoot\System32\WScript.exe"
if (Test-Path $WScriptPath) {
    Write-Host "[OK] WScript.exe encontrado en: $WScriptPath" -ForegroundColor Green
    
    # Asegurar permisos de ejecución en el archivo VBS
    try {
        $acl = Get-Acl $LauncherVbsPath
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl $LauncherVbsPath $acl
        Write-Host "[OK] Permisos configurados para el archivo VBS." -ForegroundColor Green
    } catch {
        Write-Warning "No se pudieron configurar los permisos del archivo VBS: $_"
    }
} else {
    Write-Error "No se encontró WScript.exe. Esto podría causar problemas con la ejecución del VBS."
}

# --- FASE IV: CONFIGURACIÓN FINAL DE CONTRASEÑA ---
Write-Host "`nIniciando Fase IV: Configuración final de contraseña..." -ForegroundColor Yellow
Write-Warning "ADVERTENCIA DE SEGURIDAD: Eliminar la contraseña permitirá el inicio de sesión automático."

$choice = Read-Host "¿Desea eliminar la contraseña del usuario '$KioskUserName' para habilitar el autologin? (s/n)"

if ($choice -eq 's' -or $choice -eq 'S') {
    try {
        Set-LocalUser -Name $KioskUserName -Password ([securestring]::new())
        Write-Host "[OK] Se ha eliminado la contraseña para el usuario '$KioskUserName'." -ForegroundColor Green
        
        # Configurar inicio de sesión automático si se elimina la contraseña
        $AutoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $AutoLogonPath -Name "AutoAdminLogon" -Value "1" -Force
        Set-ItemProperty -Path $AutoLogonPath -Name "DefaultUserName" -Value $KioskUserName -Force
        Set-ItemProperty -Path $AutoLogonPath -Name "DefaultPassword" -Value "" -Force
        Set-ItemProperty -Path $AutoLogonPath -Name "AutoLogonCount" -Value "999999" -Force
        Write-Host "[OK] Inicio de sesión automático configurado para '$KioskUserName'." -ForegroundColor Green
        
    } catch {
        Write-Error "No se pudo eliminar la contraseña. Detalles: $_"
    }
} else {
    Write-Host "Se conservará la contraseña del usuario. Deberá ingresarla en cada inicio de sesión." -ForegroundColor Cyan
}
