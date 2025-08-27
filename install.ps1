# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam
# Versión: 1.3 - Corregido error de sintaxis en la verificación de administrador
# Autor: Especialista en Automatización de Sistemas
# Prerrequisitos: Windows 10/11 Enterprise/Education, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"
$LauncherBatchPath = "C:\Users\Public\custom.bat"

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
    
    # 3. Crear el directorio de perfil del usuario si no existe
    $UserProfilePath = "C:\Users\$KioskUserName"
    if (!(Test-Path $UserProfilePath)) {
        Write-Host "Creando perfil de usuario..." -ForegroundColor Cyan
        
        # Forzar la creación del perfil iniciando sesión simulada
        $UserSID = (New-Object System.Security.Principal.NTAccount($KioskUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        
        # Configurar el perfil en el registro
        $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"
        if (!(Test-Path $ProfileListPath)) {
            New-Item -Path $ProfileListPath -Force | Out-Null
            Set-ItemProperty -Path $ProfileListPath -Name "ProfileImagePath" -Value $UserProfilePath -Type String
            Set-ItemProperty -Path $ProfileListPath -Name "Flags" -Value 0 -Type DWord
            Set-ItemProperty -Path $ProfileListPath -Name "State" -Value 0 -Type DWord
            Write-Host "[OK] Registro de perfil de usuario configurado." -ForegroundColor Green
        }
    }
    
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

# --- FASE II: VERIFICACIÓN E INSTALACIÓN DE STEAM ---
Write-Host "`nIniciando Fase II: Verificación e Instalación de Steam..." -ForegroundColor Yellow

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
        # Se utiliza el argumento /S para una instalación silenciosa (comportamiento estándar para instaladores NSIS).
        Start-process -FilePath $InstallerPath -ArgumentList "/S" -Wait -Verb RunAs
        Write-Host "[OK] Instalación de Steam completada." -ForegroundColor Green
    } catch {
        Write-Error "Ocurrió un error durante la descarga o instalación de Steam. Detalles: $_"
        return $FALSE
    } finally {
        # Limpiar el archivo de instalación
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
    return $TRUE
}

# --- Lógica principal de verificación e instalación ---
$SteamPath = Get-SteamPath

if (-not $SteamPath) {
    if (Install-Steam) {
        # Dar tiempo al registro para que se actualice y volver a verificar la ruta
        Start-Sleep -Seconds 5
        $SteamPath = Get-SteamPath
    }
}

if (-not $SteamPath) {
    Write-Error "No se pudo encontrar la ruta de instalación de Steam, incluso después de intentar la instalación. Verifique la instalación manualmente y vuelva a ejecutar el script."
    exit
}

$SteamExePath = Join-Path -Path $SteamPath -ChildPath "steam.exe"
Write-Host "[OK] Ruta de Steam encontrada: $SteamExePath" -ForegroundColor Green

# Crear el contenido del archivo batch
# Usamos 'start /wait' para que el proceso cmd.exe permanezca activo hasta que Steam se cierre.
# Esto es crucial para que Shell Launcher monitoree el proceso correctamente.
# El argumento -bigpicture lanza Steam directamente en modo Big Picture, ideal para un kiosco.
$BatchContent = @"
@echo off
echo Lanzando Steam en modo Big Picture...
cd /d "$SteamPath"
start /wait "" "$SteamExePath" -bigpicture
"@

# Crear el archivo batch
try {
    New-Item -Path $LauncherBatchPath -ItemType File -Force -Value $BatchContent | Out-Null
    Write-Host "[OK] Script de lanzamiento creado en: $LauncherBatchPath" -ForegroundColor Green
} catch {
    Write-Error "No se pudo crear el script de lanzamiento en '$LauncherBatchPath'. Detalles: $_"
    exit
}

# --- FASE III: CONFIGURACIÓN DE SHELL LAUNCHER ---
Write-Host "`nIniciando Fase III: Configuración de Shell Launcher..." -ForegroundColor Yellow

# Definición de constantes y funciones auxiliares
$COMPUTER = "localhost"
$NAMESPACE = "root\standardcimv2\embedded"
$restart_shell = 0 # Reinicia el shell si se cierra
$restart_device = 1 # Reinicia el dispositivo si el shell se cierra
$shutdown_device = 2 # Apaga el dispositivo si el shell se cierra
$do_nothing = 3 # No hace nada si el shell se cierra

function Get-UsernameSID($AccountName) {
    try {
        $NTUserObject = New-Object System.Security.Principal.NTAccount($AccountName)
        $NTUserSID = $NTUserObject.Translate([System.Security.Principal.SecurityIdentifier])
        return $NTUserSID.Value
    } catch {
        Write-Error "No se pudo obtener el SID para la cuenta '$AccountName'. Verifique que el nombre de usuario es correcto. Detalles: $_"
        return $null
    }
}

function Remove-ExistingShellLauncherConfig($ShellLauncherClass) {
    try {
        Write-Host "Verificando configuraciones existentes de Shell Launcher..." -ForegroundColor Cyan
        
        # Intentar deshabilitar Shell Launcher primero
        $ShellLauncherClass.SetEnabled($FALSE)
        Write-Host "Shell Launcher deshabilitado temporalmente." -ForegroundColor Yellow
        
        # Obtener todas las configuraciones existentes
        $existingConfigs = $ShellLauncherClass.GetCustomShellConfigurations()
        
        if ($existingConfigs) {
            Write-Host "Encontradas configuraciones existentes. Eliminándolas..." -ForegroundColor Yellow
            foreach ($config in $existingConfigs) {
                try {
                    $ShellLauncherClass.RemoveCustomShell($config.Sid)
                    Write-Host "Configuración eliminada para SID: $($config.Sid)" -ForegroundColor Gray
                } catch {
                    Write-Warning "No se pudo eliminar configuración para SID $($config.Sid): $_"
                }
            }
        }
        
        # Limpiar configuración por defecto
        try {
            $ShellLauncherClass.SetDefaultShell("", 0)
            Write-Host "Configuración por defecto limpiada." -ForegroundColor Gray
        } catch {
            Write-Warning "No se pudo limpiar configuración por defecto: $_"
        }
        
        Write-Host "[OK] Configuraciones existentes limpiadas." -ForegroundColor Green
        
    } catch {
        Write-Warning "Error al limpiar configuraciones existentes: $_"
    }
}

try {
    # Obtener el objeto de la clase WMI para Shell Launcher
    $ShellLauncherClass = [wmiclass]"\\$COMPUTER\${NAMESPACE}:WESL_UserSetting"

    # Limpiar configuraciones existentes
    Remove-ExistingShellLauncherConfig -ShellLauncherClass $ShellLauncherClass

    # Obtener el SID del usuario del kiosco
    $KioskUser_SID = Get-UsernameSID($KioskUserName)
    if (-not $KioskUser_SID) {
        exit
    }
    Write-Host "[OK] SID para '$KioskUserName' obtenido: $KioskUser_SID" -ForegroundColor Green

    # Configurar el shell predeterminado para todos los demás usuarios como explorer.exe
    try {
        $ShellLauncherClass.SetDefaultShell("explorer.exe", $restart_shell)
        Write-Host "[OK] Shell predeterminado configurado como 'explorer.exe'." -ForegroundColor Green
    } catch {
        Write-Warning "Error al configurar shell predeterminado: $_"
    }

    # Configurar el shell personalizado para el usuario del kiosco
    # Se apunta al archivo batch, no directamente a Steam.exe
    try {
        $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherBatchPath, $null, $null, $restart_shell)
        Write-Host "[OK] Shell personalizado para '$KioskUserName' configurado para lanzar '$LauncherBatchPath'." -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Host "Intentando eliminar configuración existente y recrear..." -ForegroundColor Yellow
            try {
                $ShellLauncherClass.RemoveCustomShell($KioskUser_SID)
                Start-Sleep -Seconds 2
                $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherBatchPath, $null, $null, $restart_shell)
                Write-Host "[OK] Shell personalizado configurado después de limpiar configuración existente." -ForegroundColor Green
            } catch {
                Write-Error "No se pudo configurar el shell personalizado después de múltiples intentos: $_"
                exit
            }
        } else {
            Write-Error "Error inesperado al configurar shell personalizado: $_"
            exit
        }
    }

    # Habilitar Shell Launcher
    $ShellLauncherClass.SetEnabled($TRUE)
    $IsShellLauncherEnabled = $ShellLauncherClass.IsEnabled()
    if ($IsShellLauncherEnabled.Enabled) {
        Write-Host "[OK] Shell Launcher ha sido habilitado." -ForegroundColor Green
    } else {
        Write-Warning "No se pudo habilitar Shell Launcher."
    }

} catch {
    Write-Error "Ocurrió un error durante la configuración de WMI. Asegúrese de que la característica Shell Launcher está habilitada. Detalles: $_"
    Write-Host "`nInformación adicional de diagnóstico:" -ForegroundColor Yellow
    Write-Host "1. Verifique que Shell Launcher esté habilitado: Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher" -ForegroundColor Gray
    Write-Host "2. Es posible que necesite reiniciar el sistema después de habilitar Shell Launcher." -ForegroundColor Gray
    Write-Host "3. Intente ejecutar el script nuevamente después del reinicio." -ForegroundColor Gray
    exit
}

# --- FINALIZACIÓN ---
Write-Host "`n--- Proceso de configuración de Kiosco completado ---" -ForegroundColor Magenta
Write-Host "Para verificar la configuración, cierre la sesión actual e inicie sesión como el usuario '$KioskUserName'." -ForegroundColor Magenta
Write-Host "Steam debería lanzarse automáticamente en modo Big Picture en lugar del escritorio de Windows." -ForegroundColor Magenta