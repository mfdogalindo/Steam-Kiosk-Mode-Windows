# ===================================================================================
# Script de Configuración de Kiosco con Shell Launcher para Steam
# Versión: 1.4 - Modificado para perfil de usuario y VBS launcher
# Autor: Especialista en Automatización de Sistemas
# Prerrequisitos: Windows 10/11 Enterprise/Education, PowerShell ejecutado como Administrador.
# ===================================================================================

# --- CONFIGURACIÓN DE VARIABLES ---
$KioskUserName = "gamer"
$LauncherVbsPath = "C:\Users\Public\launcher.vbs"

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
        } else {
            Write-Error "Error: El usuario no fue creado correctamente."
            exit
        }

        # Forzar la inicialización del perfil de usuario para guardar configuraciones
        Write-Host "Forzando la inicialización del perfil para '$KioskUserName'. Esto puede tardar un momento..." -ForegroundColor Cyan
        try {
            $Credential = New-Object System.Management.Automation.PSCredential($KioskUserName, $Password)
            Start-Process powershell.exe -Credential $Credential -ArgumentList "-Command `"exit`"" -NoNewWindow -Wait
            
            # Verificar que el perfil se haya creado
            $UserProfilePath = "C:\Users\$KioskUserName"
            if (Test-Path "$UserProfilePath\AppData") {
                Write-Host "[OK] El perfil de usuario para '$KioskUserName' ha sido inicializado correctamente." -ForegroundColor Green
            } else {
                Write-Warning "El perfil de usuario no parece haberse creado correctamente (Falta AppData). Las aplicaciones podrían no guardar la configuración."
            }
        } catch {
            Write-Warning "Ocurrió un error durante la inicialización forzada del perfil: $_"
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
    $SpecialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (!(Test-Path $SpecialAccountsPath)) {
        New-Item -Path $SpecialAccountsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $SpecialAccountsPath -Name $KioskUserName -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[OK] Usuario configurado como visible en la pantalla de login." -ForegroundColor Green
    
} catch {
    Write-Error "Error en la Fase I. Detalles: $_"
    exit
}

# --- FASE II: VERIFICACIÓN E INSTALACIÓN DE APLICACIONES ---
Write-Host "`nIniciando Fase II: Verificación e Instalación de Aplicaciones..." -ForegroundColor Yellow

# --- Función para obtener la ruta de instalación de Steam ---
function Get-SteamPath {
    $SteamRegPath = "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam"
    $SteamPath = (Get-ItemProperty -Path $SteamRegPath -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath
    return $SteamPath
}

# --- Función para obtener la ruta de instalación de OpenRGB ---
function Get-OpenRGBPath {
    Write-Host "Buscando instalación de OpenRGB..." -ForegroundColor Cyan
    $SearchPaths = @(
        (Join-Path $env:ProgramFiles "OpenRGB\OpenRGB.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "OpenRGB\OpenRGB.exe"),
        "C:\Users\Public\OpenRGB\OpenRGB.exe"
    )
    foreach ($path in $SearchPaths) {
        if (Test-Path $path) {
            Write-Host "[OK] OpenRGB encontrado en: $path" -ForegroundColor Green
            return $path
        }
    }
    Write-Warning "No se pudo encontrar OpenRGB.exe en rutas estándar. Se omitirá su configuración."
    return $null
}

# --- Función para descargar e instalar Steam ---
function Install-Steam {
    Write-Host "No se encontró Steam. Intentando descargar e instalar automáticamente..." -ForegroundColor Cyan
    $InstallerUrl = "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"
    $InstallerPath = Join-Path $env:TEMP "SteamSetup.exe"
    try {
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
        Start-process -FilePath $InstallerPath -ArgumentList "/S" -Wait -Verb RunAs
    } catch {
        Write-Error "Ocurrió un error durante la descarga o instalación de Steam. Detalles: $_"
        return $FALSE
    } finally {
        if (Test-Path $InstallerPath) { Remove-Item $InstallerPath -Force }
    }
    return $TRUE
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
    Write-Error "No se pudo encontrar la ruta de instalación de Steam. Abortando."
    exit
}
$SteamExePath = Join-Path -Path $SteamPath -ChildPath "steam.exe"
Write-Host "[OK] Ruta de Steam encontrada: $SteamExePath" -ForegroundColor Green

$OpenRGBPath = Get-OpenRGBPath

# Crear el contenido del script VBS
$VbsContent = @"
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run """"$SteamExePath"""" & " -bigpicture", 1, false
WScript.Sleep(15000) ' Esperar 15 segundos para que Steam inicie
"@

if ($OpenRGBPath) {
    $VbsContent += "`r`n" + 'WshShell.Run """"' + $OpenRGBPath + '"""" & " --startminimized --profile Steam", 7, false'
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
        
        $ShellLauncherClass.SetEnabled($FALSE)
        Write-Host "Shell Launcher deshabilitado temporalmente." -ForegroundColor Yellow
        
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
    $ShellLauncherClass = [wmiclass]"\\$COMPUTER\${NAMESPACE}:WESL_UserSetting"

    if ($CleanExistingConfig) {
        Remove-ExistingShellLauncherConfig -ShellLauncherClass $ShellLauncherClass
    }

    $KioskUser_SID = Get-UsernameSID($KioskUserName)
    if (-not $KioskUser_SID) {
        exit
    }
    Write-Host "[OK] SID para '$KioskUserName' obtenido: $KioskUser_SID" -ForegroundColor Green

    try {
        $ShellLauncherClass.SetDefaultShell("explorer.exe", $restart_shell)
        Write-Host "[OK] Shell predeterminado configurado como 'explorer.exe'." -ForegroundColor Green
    } catch {
        Write-Warning "Error al configurar shell predeterminado: $_"
    }

    try {
        $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherVbsPath, $null, $null, $restart_shell)
        Write-Host "[OK] Shell personalizado para '$KioskUserName' configurado para lanzar '$LauncherVbsPath'." -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Host "Intentando eliminar configuración existente y recrear..." -ForegroundColor Yellow
            try {
                $ShellLauncherClass.RemoveCustomShell($KioskUser_SID)
                Start-Sleep -Seconds 2
                $ShellLauncherClass.SetCustomShell($KioskUser_SID, $LauncherVbsPath, $null, $null, $restart_shell)
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

    $ShellLauncherClass.SetEnabled($TRUE)
    $IsShellLauncherEnabled = $ShellLauncherClass.IsEnabled()
    if ($IsShellLauncherEnabled.Enabled) {
        Write-Host "[OK] Shell Launcher ha sido habilitado." -ForegroundColor Green
    } else {
        Write-Warning "No se pudo habilitar Shell Launcher."
    }

} catch {
    Write-Error "Ocurrió un error durante la configuración de WMI. Detalles: $_"
    exit
}

# --- FINALIZACIÓN ---
Write-Host "`n--- Proceso de configuración de Kiosco completado ---" -ForegroundColor Magenta
Write-Host "Para verificar la configuración, cierre la sesión actual e inicie sesión como el usuario '$KioskUserName'." -ForegroundColor Magenta
Write-Host "Steam debería lanzarse automáticamente en lugar del escritorio de Windows." -ForegroundColor Magenta
