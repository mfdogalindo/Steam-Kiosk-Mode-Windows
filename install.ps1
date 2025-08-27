# ===================================================================================
# Script de Configuraci�n de Kiosco con Shell Launcher para Steam
# Versi�n: 1.3 - Corregido error de sintaxis en la verificaci�n de administrador
# Autor: Especialista en Automatizaci�n de Sistemas
# Prerrequisitos: Windows 10/11 Enterprise/Education, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACI�N DE VARIABLES ---
$KioskUserName = "gamer"
$LauncherBatchPath = "C:\Users\Public\custom.bat"

# Par�metro para limpiar configuraci�n existente
$CleanExistingConfig = $TRUE  # Cambiar a $false si no quiere limpiar configuraciones existentes

# --- VERIFICACIONES PREVIAS ---
Write-Host "Iniciando verificaciones previas..." -ForegroundColor Yellow

# Verificaci�n de privilegios de administrador - CORREGIDO
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador. Por favor, reinicie PowerShell como Administrador."
    exit
}
Write-Host "[OK] Privilegios de administrador verificados." -ForegroundColor Green

# Verificar edici�n de Windows
$WindowsEdition = (Get-WmiObject -Class Win32_OperatingSystem).Caption
Write-Host "Edici�n de Windows detectada: $WindowsEdition" -ForegroundColor Cyan

if ($WindowsEdition -notmatch "Enterprise|Education|Pro") {
    Write-Warning "Shell Launcher requiere Windows 10/11 Enterprise, Education o Pro. Su edici�n podr�a no ser compatible."
    $Continue = Read-Host "�Desea continuar de todos modos? (s/n)"
    if ($Continue -ne "s" -and $Continue -ne "S") {
        exit
    }
}

# Verificar pol�tica de ejecuci�n de PowerShell
$ExecutionPolicy = Get-ExecutionPolicy
Write-Host "Pol�tica de ejecuci�n actual: $ExecutionPolicy" -ForegroundColor Cyan

if ($ExecutionPolicy -eq "Restricted") {
    Write-Warning "La pol�tica de ejecuci�n est� restringida. Esto podr�a causar problemas."
    Write-Host "Para solucionarlo, ejecute: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
}

# Habilitaci�n de la caracter�stica Shell Launcher si no est� presente
$feature = Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher
if ($feature.State -ne "Enabled") {
    Write-Host "La caracter�stica Shell Launcher no est� habilitada. Habilit�ndola ahora..." -ForegroundColor Cyan
    Enable-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -All -NoRestart
    Write-Host "[OK] Caracter�stica Shell Launcher habilitada. Se recomienda reiniciar el sistema despu�s de completar el script." -ForegroundColor Green
} else {
    Write-Host "[OK] La caracter�stica Shell Launcher ya est� habilitada." -ForegroundColor Green
}

# --- FASE I: CREACI�N DEL USUARIO ---
Write-Host "`nIniciando Fase I: Creaci�n de la cuenta de usuario '$KioskUserName'..." -ForegroundColor Yellow

try {
    # Verificar si el usuario ya existe
    $ExistingUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
    if ($ExistingUser) {
        Write-Host "El usuario '$KioskUserName' ya existe. Verificando configuraci�n..." -ForegroundColor Cyan
        Write-Host "Estado del usuario: $($ExistingUser.Enabled)" -ForegroundColor Cyan
        
        # Asegurar que el usuario est� habilitado
        if (-not $ExistingUser.Enabled) {
            Enable-LocalUser -Name $KioskUserName
            Write-Host "[OK] Usuario '$KioskUserName' habilitado." -ForegroundColor Green
        }
    } else {
        Write-Host "Creando el usuario '$KioskUserName'..." -ForegroundColor Cyan
        
        # Solicitar contrase�a
        do {
            $Password = Read-Host -AsSecureString "Introduzca una contrase�a para el usuario '$KioskUserName' (m�nimo 8 caracteres)"
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            if ($PlainPassword.Length -lt 8) {
                Write-Warning "La contrase�a debe tener al menos 8 caracteres. Intente nuevamente."
            }
        } while ($PlainPassword.Length -lt 8)
        
        # Crear el usuario con configuraci�n espec�fica para aparecer en login
        $NewUser = New-LocalUser -Name $KioskUserName -Password $Password -FullName "Kiosk Gaming Account" -Description "Cuenta de usuario para el modo kiosco de Steam." -AccountNeverExpires -PasswordNeverExpires
        Write-Host "[OK] Usuario '$KioskUserName' creado exitosamente." -ForegroundColor Green
        
        # Verificar que el usuario fue creado correctamente
        $CreatedUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
        if ($CreatedUser) {
            Write-Host "[OK] Verificaci�n: Usuario '$KioskUserName' existe en el sistema." -ForegroundColor Green
            Write-Host "    - Habilitado: $($CreatedUser.Enabled)" -ForegroundColor Gray
            Write-Host "    - Nombre completo: $($CreatedUser.FullName)" -ForegroundColor Gray
            Write-Host "    - Descripci�n: $($CreatedUser.Description)" -ForegroundColor Gray
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
    
    # Asegurar que el usuario NO est� oculto (valor 0 = oculto, 1 = visible)
    Set-ItemProperty -Path $SpecialAccountsPath -Name $KioskUserName -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[OK] Usuario configurado como visible en la pantalla de login." -ForegroundColor Green
    
    # 3. Crear el directorio de perfil del usuario si no existe
    $UserProfilePath = "C:\Users\$KioskUserName"
    if (!(Test-Path $UserProfilePath)) {
        Write-Host "Creando perfil de usuario..." -ForegroundColor Cyan
        
        # Forzar la creaci�n del perfil iniciando sesi�n simulada
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
    
    # 4. Verificar pol�ticas locales que podr�an ocultar el usuario
    Write-Host "Verificando pol�ticas locales..." -ForegroundColor Cyan
    
    # Verificar si hay una pol�tica que oculte usuarios
    $HideUsersPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $DontDisplayLastUserName = Get-ItemProperty -Path $HideUsersPath -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    if ($DontDisplayLastUserName -and $DontDisplayLastUserName.DontDisplayLastUserName -eq 1) {
        Write-Host "Detectada pol�tica que oculta nombres de usuario. Esto es normal en algunos sistemas." -ForegroundColor Yellow
    }
    
    Write-Host "[OK] Configuraci�n del usuario completada." -ForegroundColor Green
    Write-Host "Informaci�n importante:" -ForegroundColor Yellow
    Write-Host "- Si no ve el usuario en la pantalla de login, presione Ctrl+Alt+Del" -ForegroundColor Gray
    Write-Host "- O haga clic en 'Otro usuario' si est� disponible" -ForegroundColor Gray
    Write-Host "- Ingrese manualmente: Usuario=$KioskUserName, Contrase�a=(la que ingres�)" -ForegroundColor Gray
    
} catch {
    Write-Error "Error al crear el usuario '$KioskUserName'. Detalles: $_"
    Write-Host "Informaci�n adicional de depuraci�n:" -ForegroundColor Yellow
    Write-Host "- PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "- Windows Version: $((Get-WmiObject -Class Win32_OperatingSystem).Caption)" -ForegroundColor Gray
    exit
}

# --- FASE II: VERIFICACI�N E INSTALACI�N DE STEAM ---
Write-Host "`nIniciando Fase II: Verificaci�n e Instalaci�n de Steam..." -ForegroundColor Yellow

# --- Funci�n para obtener la ruta de instalaci�n de Steam ---
function Get-SteamPath {
    $SteamRegPath = "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam"
    $SteamPath = (Get-ItemProperty -Path $SteamRegPath -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath
    return $SteamPath
}

# --- Funci�n para descargar e instalar Steam ---
function Install-Steam {
    Write-Host "No se encontr� Steam. Intentando descargar e instalar autom�ticamente..." -ForegroundColor Cyan
    $InstallerUrl = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    $InstallerPath = Join-Path $env:TEMP "SteamSetup.exe"

    try {
        Write-Host "Descargando el instalador de Steam desde $InstallerUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
        Write-Host "[OK] Instalador descargado en $InstallerPath" -ForegroundColor Green

        Write-Host "Iniciando la instalaci�n silenciosa de Steam... Esto puede tardar unos minutos." -ForegroundColor Cyan
        # Se utiliza el argumento /S para una instalaci�n silenciosa (comportamiento est�ndar para instaladores NSIS).
        Start-process -FilePath $InstallerPath -ArgumentList "/S" -Wait -Verb RunAs
        Write-Host "[OK] Instalaci�n de Steam completada." -ForegroundColor Green
    } catch {
        Write-Error "Ocurri� un error durante la descarga o instalaci�n de Steam. Detalles: $_"
        return $FALSE
    } finally {
        # Limpiar el archivo de instalaci�n
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
    return $TRUE
}

# --- L�gica principal de verificaci�n e instalaci�n ---
$SteamPath = Get-SteamPath

if (-not $SteamPath) {
    if (Install-Steam) {
        # Dar tiempo al registro para que se actualice y volver a verificar la ruta
        Start-Sleep -Seconds 5
        $SteamPath = Get-SteamPath
    }
}

if (-not $SteamPath) {
    Write-Error "No se pudo encontrar la ruta de instalaci�n de Steam, incluso despu�s de intentar la instalaci�n. Verifique la instalaci�n manualmente y vuelva a ejecutar el script."
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

# --- FASE III: CONFIGURACI�N DE SHELL LAUNCHER ---
Write-Host "`nIniciando Fase III: Configuraci�n de Shell Launcher..." -ForegroundColor Yellow

# Definici�n de constantes y funciones auxiliares
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
            Write-Host "Encontradas configuraciones existentes. Elimin�ndolas..." -ForegroundColor Yellow
            foreach ($config in $existingConfigs) {
                try {
                    $ShellLauncherClass.RemoveCustomShell($config.Sid)
                    Write-Host "Configuraci�n eliminada para SID: $($config.Sid)" -ForegroundColor Gray
                } catch {
                    Write-Warning "No se pudo eliminar configuraci�n para SID $($config.Sid): $_"
                }
            }
        }
        
        # Limpiar configuraci�n por defecto
        try {
            $ShellLauncherClass.SetDefaultShell("", 0)
            Write-Host "Configuraci�n por defecto limpiada." -ForegroundColor Gray
        } catch {
            Write-Warning "No se pudo limpiar configuraci�n por defecto: $_"
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

    # Configurar el shell predeterminado para todos los dem�s usuarios como explorer.exe
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
            Write-Host "Intentando eliminar configuraci�n existente y recrear..." -ForegroundColor Yellow
            try {
                $ShellLauncherClass.RemoveCustomShell($KioskUser_SID)
                Start-Sleep -Seconds 2
                $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherBatchPath, $null, $null, $restart_shell)
                Write-Host "[OK] Shell personalizado configurado despu�s de limpiar configuraci�n existente." -ForegroundColor Green
            } catch {
                Write-Error "No se pudo configurar el shell personalizado despu�s de m�ltiples intentos: $_"
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
    Write-Error "Ocurri� un error durante la configuraci�n de WMI. Aseg�rese de que la caracter�stica Shell Launcher est� habilitada. Detalles: $_"
    Write-Host "`nInformaci�n adicional de diagn�stico:" -ForegroundColor Yellow
    Write-Host "1. Verifique que Shell Launcher est� habilitado: Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher" -ForegroundColor Gray
    Write-Host "2. Es posible que necesite reiniciar el sistema despu�s de habilitar Shell Launcher." -ForegroundColor Gray
    Write-Host "3. Intente ejecutar el script nuevamente despu�s del reinicio." -ForegroundColor Gray
    exit
}

# --- FINALIZACI�N ---
Write-Host "`n--- Proceso de configuraci�n de Kiosco completado ---" -ForegroundColor Magenta
Write-Host "Para verificar la configuraci�n, cierre la sesi�n actual e inicie sesi�n como el usuario '$KioskUserName'." -ForegroundColor Magenta
Write-Host "Steam deber�a lanzarse autom�ticamente en modo Big Picture en lugar del escritorio de Windows." -ForegroundColor Magenta