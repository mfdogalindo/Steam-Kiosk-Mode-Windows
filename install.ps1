# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam
# Versión: 1.4 - Corregida la creación de perfil de usuario y añadido soporte para OpenRGB
# Autor: Especialista en Automatización de Sistemas
# Prerrequisitos: Windows 10/11 Enterprise/Education, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"
$LauncherVbsPath = "C:\Users\Public\launcher.vbs" # Cambiado de .bat a .vbs

# Parámetro para limpiar configuración existente
$CleanExistingConfig = $TRUE  # Cambiar a $false si no quiere limpiar configuraciones existentes

# --- VERIFICACIONES PREVIAS ---
Write-Host "Iniciando verificaciones previas..." -ForegroundColor Yellow

# Verificación de privilegios de administrador - CORREGIDO
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador. Por favor, reinicie PowerShell como Administrador."
    exit
}
Write-Host "[OK] Privilegios de administrador verificados." -ForegroundColor Green

# Verificar edición de Windows
$WindowsEdition = (Get-WmiObject -Class Win32_OperatingSystem).Caption
Write-Host "Edición de Windows detectada: $WindowsEdition" -ForegroundColor Cyan

if ($WindowsEdition -notmatch "Enterprise|Education|Pro") {
    Write-Warning "Shell Launcher requiere Windows 10/11 Enterprise, Education o Pro. Su edición podría no ser compatible."
    $Continue = Read-Host "¿Desea continuar de todos modos? (s/n)"
    if ($Continue -ne "s" -and $Continue -ne "S") {
        exit
    }
}

# Verificar política de ejecución de PowerShell
$ExecutionPolicy = Get-ExecutionPolicy
Write-Host "Política de ejecución actual: $ExecutionPolicy" -ForegroundColor Cyan

if ($ExecutionPolicy -eq "Restricted") {
    Write-Warning "La política de ejecución está restringida. Esto podría causar problemas."
    Write-Host "Para solucionarlo, ejecute: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
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

# --- FASE I: CREACIÓN DEL USUARIO ---
Write-Host "`nIniciando Fase I: Creación de la cuenta de usuario '$KioskUserName'..." -ForegroundColor Yellow

try {
    # Verificar si el usuario ya existe
    $ExistingUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
    if ($ExistingUser) {
        Write-Host "El usuario '$KioskUserName' ya existe. Verificando configuración..." -ForegroundColor Cyan
        Write-Host "Estado del usuario: $($ExistingUser.Enabled)" -ForegroundColor Cyan

        # Asegurar que el usuario esté habilitado
        if (-not $ExistingUser.Enabled) {
            Enable-LocalUser -Name $KioskUserName
            Write-Host "[OK] Usuario '$KioskUserName' habilitado." -ForegroundColor Green
        }
    } else {
        Write-Host "Creando el usuario '$KioskUserName'..." -ForegroundColor Cyan

        # Solicitar contraseña
        Write-Host "Se requiere una contraseña para la creación inicial del usuario." -ForegroundColor Cyan
        Write-Host "Al final del script, se le preguntará si desea configurar el inicio de sesión automático (sin contraseña)." -ForegroundColor Yellow
        do {
            $Password = Read-Host -AsSecureString "Introduzca una contraseña para el usuario '$KioskUserName' (mínimo 8 caracteres)"
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

            if ($PlainPassword.Length -lt 8) {
                Write-Warning "La contraseña debe tener al menos 8 caracteres. Intente nuevamente."
            }
        } while ($PlainPassword.Length -lt 8)

        # Crear el usuario con configuración específica para aparecer en login
        $NewUser = New-LocalUser -Name $KioskUserName -Password $Password -FullName "Kiosk Gaming Account" -Description "Cuenta de usuario para el modo kiosco de Steam." -AccountNeverExpires -PasswordNeverExpires
        Write-Host "[OK] Usuario '$KioskUserName' creado exitosamente." -ForegroundColor Green

        # Verificar que el usuario fue creado correctamente
        $CreatedUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
        if ($CreatedUser) {
            Write-Host "[OK] Verificación: Usuario '$KioskUserName' existe en el sistema." -ForegroundColor Green
            Write-Host "    - Habilitado: $($CreatedUser.Enabled)" -ForegroundColor Gray
            Write-Host "    - Nombre completo: $($CreatedUser.FullName)" -ForegroundColor Gray
            Write-Host "    - Descripción: $($CreatedUser.Description)" -ForegroundColor Gray
        } else {
            Write-Error "Error: El usuario no fue creado correctamente."
            exit
        }

        # Forzar la creación del perfil de usuario para asegurar la inicialización completa
        Write-Host "Forzando la creación del perfil de usuario para '$KioskUserName'..." -ForegroundColor Cyan
        Write-Host "Esto asegura que Steam y otros programas puedan guardar datos correctamente." -ForegroundColor Gray

        try {
            $Credential = New-Object System.Management.Automation.PSCredential($KioskUserName, $Password)
            Start-Process "cmd.exe" -ArgumentList "/c, exit" -Credential $Credential -WindowStyle Hidden -Wait

            $UserProfilePath = "C:\Users\$KioskUserName"
            if (Test-Path $UserProfilePath) {
                Write-Host "[OK] Perfil de usuario para '$KioskUserName' inicializado correctamente en '$UserProfilePath'." -ForegroundColor Green
            } else {
                Write-Error "El perfil de usuario no se creó como se esperaba. La configuración podría ser inestable."
            }
        } catch {
            Write-Error "Ocurrió un error al forzar la creación del perfil de usuario. Detalles: $_"
            Write-Warning "Es posible que deba iniciar sesión manualmente como '$KioskUserName' una vez para completar la configuración."
        }
    }

    # Configuraciones adicionales para que el usuario aparezca en la pantalla de login
    Write-Host "Configurando visibilidad del usuario en la pantalla de login..." -ForegroundColor Cyan

    # 1. Agregar el usuario al grupo Users
    try {
        Add-LocalGroupMember -Group "Users" -Member $KioskUserName -ErrorAction SilentlyContinue
        Write-Host "[OK] Usuario agregado al grupo 'Users'." -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like "*already a member*") {
            Write-Host "[OK] Usuario ya pertenece al grupo 'Users'." -ForegroundColor Green
        } else {
            Write-Warning "No se pudo agregar al grupo Users: $_"
        }
    }

    # 2. Configurar el registro para que el usuario aparezca en la pantalla de login
    $WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $SpecialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

    # Crear la clave SpecialAccounts si no existe
    if (!(Test-Path $SpecialAccountsPath)) {
        New-Item -Path $SpecialAccountsPath -Force | Out-Null
        Write-Host "[OK] Clave de registro SpecialAccounts creada." -ForegroundColor Green
    }

    # Asegurar que el usuario NO esté oculto (valor 0 = oculto, 1 = visible)
    Set-ItemProperty -Path $SpecialAccountsPath -Name $KioskUserName -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[OK] Usuario configurado como visible en la pantalla de login." -ForegroundColor Green

    # 4. Verificar políticas locales que podrían ocultar el usuario
    Write-Host "Verificando políticas locales..." -ForegroundColor Cyan

    # Verificar si hay una política que oculte usuarios
    $HideUsersPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $DontDisplayLastUserName = Get-ItemProperty -Path $HideUsersPath -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    if ($DontDisplayLastUserName -and $DontDisplayLastUserName.DontDisplayLastUserName -eq 1) {
        Write-Host "Detectada política que oculta nombres de usuario. Esto es normal en algunos sistemas." -ForegroundColor Yellow
    }

    Write-Host "[OK] Configuración del usuario completada." -ForegroundColor Green
    Write-Host "Información importante:" -ForegroundColor Yellow
    Write-Host "- Si no ve el usuario en la pantalla de login, presione Ctrl+Alt+Del" -ForegroundColor Gray
    Write-Host "- O haga clic en 'Otro usuario' si está disponible" -ForegroundColor Gray
    Write-Host "- Ingrese manualmente: Usuario=$KioskUserName, Contraseña=(la que ingresó)" -ForegroundColor Gray

} catch {
    Write-Error "Error al crear el usuario '$KioskUserName'. Detalles: $_"
    Write-Host "Información adicional de depuración:" -ForegroundColor Yellow
    Write-Host "- PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "- Windows Version: $((Get-WmiObject -Class Win32_OperatingSystem).Caption)" -ForegroundColor Gray
    exit
}

# --- FASE II: VERIFICACIÓN E INSTALACIÓN DE SOFTWARE ---
Write-Host "`nIniciando Fase II: Verificación e Instalación de Software..." -ForegroundColor Yellow

# --- Función para obtener la ruta de instalación de Steam ---
function Get-SteamPath {
    $SteamRegPath = "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam"
    $SteamPath = (Get-ItemProperty -Path $SteamRegPath -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath
    return $SteamPath
}

# --- Función para descargar e instalar Steam ---
function Install-Steam {
    Write-Host "No se encontró Steam. Intentando descargar e instalar automáticamente..." -ForegroundColor Cyan
    $InstallerUrl = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    $InstallerPath = Join-Path $env:TEMP "SteamSetup.exe"

    try {
        Write-Host "Descargando el instalador de Steam desde $InstallerUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
        Write-Host "[OK] Instalador descargado en $InstallerPath" -ForegroundColor Green

        Write-Host "Iniciando la instalación silenciosa de Steam... Esto puede tardar unos minutos." -ForegroundColor Cyan
        Start-process -FilePath $InstallerPath -ArgumentList "/S" -Wait -Verb RunAs
        Write-Host "[OK] Instalación de Steam completada." -ForegroundColor Green
    } catch {
        Write-Error "Ocurrió un error durante la descarga o instalación de Steam. Detalles: $_"
        return $FALSE
    } finally {
        if (Test-Path $InstallerPath) { Remove-Item $InstallerPath -Force }
    }
    return $TRUE
}

# --- Función para obtener la ruta de OpenRGB ---
function Get-OpenRGBPath {
    $OpenRGBPath = $env:ProgramFiles + "\OpenRGB\OpenRGB.exe"
    if (Test-Path $OpenRGBPath) { return $OpenRGBPath }

    $OpenRGBPath = $env:LOCALAPPDATA + "\OpenRGB\OpenRGB.exe"
    if (Test-Path $OpenRGBPath) { return $OpenRGBPath }

    # Búsqueda en el registro (si OpenRGB crea una clave de desinstalación)
    $UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $OpenRGBEntry = Get-ChildItem -Path $UninstallKey | Get-ItemProperty | Where-Object { $_.DisplayName -eq "OpenRGB" }
    if ($OpenRGBEntry) {
        $InstallLocation = $OpenRGBEntry.InstallLocation
        if (Test-Path (Join-Path $InstallLocation "OpenRGB.exe")) {
            return (Join-Path $InstallLocation "OpenRGB.exe")
        }
    }
    return $null
}

# --- Lógica principal de verificación e instalación ---
$SteamPath = Get-SteamPath
if (-not $SteamPath) {
    if (Install-Steam) {
        Start-Sleep -Seconds 5
        $SteamPath = Get-SteamPath
    }
}

if (-not $SteamPath) {
    Write-Error "No se pudo encontrar la ruta de instalación de Steam. Verifique la instalación manualmente."
    exit
}
$SteamExePath = Join-Path -Path $SteamPath -ChildPath "steam.exe"
Write-Host "[OK] Ruta de Steam encontrada: $SteamExePath" -ForegroundColor Green

$OpenRGBExePath = Get-OpenRGBPath
if (-not $OpenRGBExePath) {
    Write-Warning "No se encontró OpenRGB. Se omitirá su inicio."
} else {
    Write-Host "[OK] Ruta de OpenRGB encontrada: $OpenRGBExePath" -ForegroundColor Green
}

# --- FASE III: CREACIÓN DEL SCRIPT DE LANZAMIENTO VBS ---
Write-Host "`nIniciando Fase III: Creación del script de lanzamiento VBS..." -ForegroundColor Yellow

$VbsContent = @"
' Crear un objeto Shell para ejecutar comandos
Set WshShell = CreateObject("WScript.Shell")

' Iniciar Steam en modo Big Picture de forma oculta (parámetro 0)
WshShell.Run """$SteamExePath"" -bigpicture", 0, false

' Iniciar OpenRGB si se encontró la ruta
#if ($OpenRGBExePath)
' Esperar un poco para que Steam se estabilice antes de lanzar OpenRGB
WScript.Sleep(10000) ' 10 segundos de espera
' Iniciar OpenRGB minimizado (parámetro 7) con el perfil "Steam"
WshShell.Run """$OpenRGBExePath"" --profile Steam", 7, false
#end
"@

# Crear el archivo VBS
try {
    # Reemplazar las variables de PowerShell en el contenido de VBS
    $VbsContent = $ExecutionContext.InvokeCommand.ExpandString($VbsContent)
    New-Item -Path $LauncherVbsPath -ItemType File -Force -Value $VbsContent | Out-Null
    Write-Host "[OK] Script de lanzamiento VBS creado en: $LauncherVbsPath" -ForegroundColor Green
} catch {
    Write-Error "No se pudo crear el script de lanzamiento VBS en '$LauncherVbsPath'. Detalles: $_"
    exit
}

# --- FASE IV: CONFIGURACIÓN DE SHELL LAUNCHER ---
Write-Host "`nIniciando Fase IV: Configuración de Shell Launcher..." -ForegroundColor Yellow

# Definición de constantes y funciones auxiliares
$COMPUTER = "localhost"
$NAMESPACE = "root\standardcimv2\embedded"
$restart_shell = 0
$do_nothing = 3

function Get-UsernameSID($AccountName) {
    try {
        $NTUserObject = New-Object System.Security.Principal.NTAccount($AccountName)
        $NTUserSID = $NTUserObject.Translate([System.Security.Principal.SecurityIdentifier])
        return $NTUserSID.Value
    } catch {
        Write-Error "No se pudo obtener el SID para la cuenta '$AccountName'. Detalles: $_"
        return $null
    }
}

function Set-ShellLauncher($KioskUser_SID, $LauncherPath) {
    $ShellLauncherClass = [wmiclass]"\\$COMPUTER\${NAMESPACE}:WESL_UserSetting"

    # Limpiar configuraciones existentes
    $ShellLauncherClass.SetEnabled($FALSE)
    $existingConfigs = $ShellLauncherClass.GetCustomShellConfigurations()
    if ($existingConfigs) {
        foreach ($config in $existingConfigs) {
            $ShellLauncherClass.RemoveCustomShell($config.Sid)
        }
    }
    $ShellLauncherClass.SetDefaultShell("explorer.exe", $restart_shell)

    # Configurar el shell personalizado para el usuario del kiosco
    $ShellLauncherClass.SetCustomShell($KioskUser_SID, "wscript.exe `"$LauncherPath`"")
    Write-Host "[OK] Shell personalizado para '$KioskUserName' configurado para lanzar '$LauncherPath'." -ForegroundColor Green

    # Habilitar Shell Launcher
    $ShellLauncherClass.SetEnabled($TRUE)
    if ($($ShellLauncherClass.IsEnabled()).Enabled) {
        Write-Host "[OK] Shell Launcher ha sido habilitado." -ForegroundColor Green
    } else {
        Write-Warning "No se pudo habilitar Shell Launcher."
    }
}

try {
    $KioskUser_SID = Get-UsernameSID($KioskUserName)
    if ($KioskUser_SID) {
        Set-ShellLauncher -KioskUser_SID $KioskUser_SID -LauncherPath $LauncherVbsPath
    }
} catch {
    Write-Error "Ocurrió un error durante la configuración de WMI. Detalles: $_"
    exit
}

# --- FASE V: OPCIÓN DE INICIO DE SESIÓN AUTOMÁTICO ---
Write-Host "`nIniciando Fase V: Configuración de inicio de sesión automático..." -ForegroundColor Yellow

$AutoLoginChoice = Read-Host "¿Desea que el usuario '$KioskUserName' inicie sesión automáticamente al encender el PC? (s/n)"
if ($AutoLoginChoice -eq 's' -or $AutoLoginChoice -eq 'S') {
    Write-Host "Configurando inicio de sesión automático..." -ForegroundColor Cyan
    Write-Warning "ADVERTENCIA: La contraseña se guardará en el registro. Esto es una consideración de seguridad."

    $WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    # Convertir SecureString a texto plano para el registro
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Set-ItemProperty -Path $WinlogonPath -Name "AutoAdminLogon" -Value "1"
    Set-ItemProperty -Path $WinlogonPath -Name "DefaultUserName" -Name $KioskUserName
    Set-ItemProperty -Path $WinlogonPath -Name "DefaultPassword" -Value $PlainPassword

    Write-Host "[OK] Inicio de sesión automático configurado para '$KioskUserName'." -ForegroundColor Green
} else {
    Write-Host "Se omitió la configuración de inicio de sesión automático." -ForegroundColor Gray
}


# --- FINALIZACIÓN ---
Write-Host "`n--- Proceso de configuración de Kiosco completado ---" -ForegroundColor Magenta
Write-Host "Para verificar la configuración, reinicie el equipo." -ForegroundColor Magenta
Write-Host "El usuario '$KioskUserName' debería iniciar sesión y lanzar Steam automáticamente." -ForegroundColor Magenta
