# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam y OpenRGB
# Versión: 2.0 - Revisado y mejorado según solicitud
# Autor: Especialista en Automatización de Sistemas (Modificado por Gemini)
# Prerrequisitos: Windows 10/11 Enterprise/Education/Pro, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"
#>> El script de inicio ahora será un VBS para un lanzamiento oculto.
$LauncherVbsPath = "C:\Users\Public\launch.vbs"

#>> Nueva variable para especificar el perfil de OpenRGB. Dejar en blanco ("") si no se desea cargar un perfil.
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
        
        #>> Se solicita contraseña, que es necesaria para la inicialización del perfil.
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
        
        #>> MEJORA: Forzar la inicialización del perfil de usuario.
        # Esto es crucial para que aplicaciones como Steam y OpenRGB puedan guardar datos.
        # Se inicia un proceso simple y oculto como el nuevo usuario para que Windows cree su perfil.
        Write-Host "Inicializando el perfil del usuario '$KioskUserName' para asegurar la persistencia de datos..." -ForegroundColor Cyan
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "cmd.exe"
        $processInfo.Arguments = "/c exit" # Un comando rápido que no hace nada visible.
        $processInfo.UserName = $KioskUserName
        $processInfo.Password = $Password
        $processInfo.UseShellExecute = $false
        $processInfo.WindowStyle = 'Hidden'
        $process = [System.Diagnostics.Process]::Start($processInfo)
        $process.WaitForExit()
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) # Limpiar la contraseña de la memoria
        
        if (Test-Path "C:\Users\$KioskUserName\AppData") {
            Write-Host "[OK] El perfil de usuario ha sido inicializado correctamente." -ForegroundColor Green
        } else {
            Write-Warning "No se pudo verificar la inicialización del perfil de usuario. Las aplicaciones podrían no guardar su configuración."
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

# --- FASE II: VERIFICACIÓN DE SOFTWARE Y CREACIÓN DE SCRIPT DE LANZAMIENTO ---
Write-Host "`nIniciando Fase II: Verificación de software y creación de script de lanzamiento..." -ForegroundColor Yellow

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

#>> MEJORA: Buscar OpenRGB
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

#>> MEJORA: Crear el contenido del script VBS para un lanzamiento silencioso.
$VbsContent = @"
Set WshShell = CreateObject("WScript.Shell")

' Lanza Steam en modo Big Picture de forma oculta
WshShell.Run """$SteamExePath"" -bigpicture", 0, false

"@

#>> Añadir lógica para OpenRGB si fue encontrado
if ($OpenRGBExePath) {
    $openRgbArgs = "--startminimized"
    if (-not [string]::IsNullOrWhiteSpace($OpenRGBProfileName)) {
        $openRgbArgs += " --profile $OpenRGBProfileName"
        Write-Host "OpenRGB se configuró para cargar el perfil: '$OpenRGBProfileName'" -ForegroundColor Cyan
    } else {
        Write-Host "OpenRGB se configuró para iniciar minimizado sin un perfil específico." -ForegroundColor Cyan
    }

    $VbsContent += @"

' Espera 15 segundos para que Steam se inicie antes de lanzar OpenRGB
WScript.Sleep(15000) 

' Lanza OpenRGB minimizado y con el perfil especificado (si existe) de forma oculta
WshShell.Run """$OpenRGBExePath"" $openRgbArgs", 0, false
"@
}

# Crear el archivo VBS
try {
    New-Item -Path $LauncherVbsPath -ItemType File -Force -Value $VbsContent | Out-Null
    Write-Host "[OK] Script de lanzamiento VBS creado en: $LauncherVbsPath" -ForegroundColor Green
} catch {
    Write-Error "No se pudo crear el script de lanzamiento VBS. Detalles: $_"
    exit
}

# --- FASE III: CONFIGURACIÓN DE SHELL LAUNCHER ---
Write-Host "`nIniciando Fase III: Configuración de Shell Launcher..." -ForegroundColor Yellow

$COMPUTER = "localhost"
$NAMESPACE = "root\standardcimv2\embedded"
$restart_shell = 0 # Reinicia el shell si se cierra

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

    #>> Configurar el shell personalizado para lanzar el script VBS
    $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherVbsPath, $null, $null, $restart_shell)
    Write-Host "[OK] Shell personalizado para '$KioskUserName' configurado para lanzar '$LauncherVbsPath'." -ForegroundColor Green

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

# --- FASE IV: CONFIGURACIÓN FINAL DE CONTRASEÑA ---
Write-Host "`nIniciando Fase IV: Configuración final de contraseña..." -ForegroundColor Yellow
Write-Warning "ADVERTENCIA DE SEGURIDAD: Eliminar la contraseña permitirá el inicio de sesión automático. Esto es conveniente para un kiosco, pero cualquier persona con acceso físico podrá usar esta cuenta."

$choice = Read-Host "¿Desea eliminar la contraseña del usuario '$KioskUserName' para habilitar el autologin? (s/n)"

if ($choice -eq 's' -or $choice -eq 'S') {
    try {
        Set-LocalUser -Name $KioskUserName -Password ([securestring]::new())
        Write-Host "[OK] Se ha eliminado la contraseña para el usuario '$KioskUserName'." -ForegroundColor Green
    } catch {
        Write-Error "No se pudo eliminar la contraseña. Detalles: $_"
    }
} else {
    Write-Host "Se conservará la contraseña del usuario. Deberá ingresarla en cada inicio de sesión." -ForegroundColor Cyan
}

# --- FINALIZACIÓN ---
Write-Host "`n--- Proceso de configuración de Kiosco completado ---" -ForegroundColor Magenta
Write-Host "Para verificar, cierre la sesión actual e inicie sesión como '$KioskUserName'." -ForegroundColor Magenta
Write-Host "El sistema debería iniciar directamente en Steam (modo Big Picture) sin mostrar el escritorio." -ForegroundColor Magenta

