# ===================================================================================
# Script de Reversi�n de Configuraci�n de Kiosco Steam
# Versi�n: 1.4 - Limpieza final de caracteres y codificaci�n (corregido)
# Autor: Especialista en Automatizaci�n de Sistemas
# Prop�sito: Revertir completamente la configuraci�n de kiosco Steam
# Prerrequisitos: Windows 10/11, PowerShell ejecutado como Administrador
# ===================================================================================

# --- CONFIGURACI�N DE VARIABLES ---
$KioskUserName    = "gamer"
$LauncherBatchPath = "C:\Users\Public\custom.bat"

# --- FUNCIONES AUXILIARES ---
function Show-Banner {
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host "                  SCRIPT DE REVERSI�N DE CONFIGURACI�N KIOSCO STEAM" -ForegroundColor Red
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "ADVERTENCIA: Este script eliminar� la configuraci�n de kiosco Steam" -ForegroundColor Yellow
    Write-Host ("y puede eliminar el usuario '{0}' y desinstalar Steam." -f $KioskUserName) -ForegroundColor Yellow
    Write-Host ""
}

function Confirm-Action {
    param(
        [string]$Message,
        [string]$DefaultChoice = "N"
    )

    do {
        $choice = Read-Host ("{0} (S/N) [Por defecto: {1}]" -f $Message, $DefaultChoice)
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $choice = $DefaultChoice
        }
        $choice = $choice.ToUpper()
    } while ($choice -ne "S" -and $choice -ne "N")

    return $choice -eq "S"
}

function Get-SteamPath {
    $SteamRegPath = "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam"
    $p = Get-ItemProperty -Path $SteamRegPath -Name "InstallPath" -ErrorAction SilentlyContinue
    if ($p) { return $p.InstallPath } else { return $null }
}

function Get-SteamUninstaller {
    $UninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($key in $UninstallKeys) {
        $apps = Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*Steam*" -and $_.UninstallString
        }
        if ($apps) {
            return $apps[0].UninstallString
        }
    }
    return $null
}

# --- VERIFICACIONES INICIALES ---
Show-Banner

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador. Por favor, reinicie PowerShell como Administrador."
    exit
}
Write-Host "[OK] Privilegios de administrador verificados." -ForegroundColor Green

if (-not (Confirm-Action "�Est� seguro de que desea proceder con la reversi�n de la configuraci�n de kiosco?")) {
    Write-Host "Operaci�n cancelada por el usuario." -ForegroundColor Yellow
    exit
}

# --- FASE I: DESHABILITAR Y LIMPIAR SHELL LAUNCHER ---
Write-Host "`n=== FASE I: LIMPIANDO CONFIGURACI�N DE SHELL LAUNCHER ===" -ForegroundColor Magenta

try {
    $NAMESPACE = "root\standardcimv2\embedded"
    # Construcci�n m�s segura de la ruta de clase WMI
    $wmipath = "\\localhost\" + $NAMESPACE + ":WESL_UserSetting"
    $ShellLauncherClass = [wmiclass]$wmipath

    Write-Host "Deshabilitando Shell Launcher..." -ForegroundColor Cyan
    $ShellLauncherClass.SetEnabled($FALSE)
    Write-Host "[OK] Shell Launcher deshabilitado." -ForegroundColor Green

    Write-Host "Eliminando configuraciones personalizadas..." -ForegroundColor Cyan
    $existingConfigs = $ShellLauncherClass.GetCustomShellConfigurations()
    if ($existingConfigs) {
        foreach ($config in $existingConfigs) {
            try {
                $ShellLauncherClass.RemoveCustomShell($config.Sid)
                Write-Host ("  - Configuraci�n eliminada para SID: {0}" -f $config.Sid) -ForegroundColor Gray
            }
            catch {
                Write-Warning ("No se pudo eliminar configuraci�n para SID {0}: {1}" -f $config.Sid, $_)
            }
        }
    }

    Write-Host "Restaurando shell por defecto a explorer.exe..." -ForegroundColor Cyan
    $ShellLauncherClass.SetDefaultShell("explorer.exe", 0)
    Write-Host "[OK] Shell por defecto restaurado." -ForegroundColor Green
}
catch {
    Write-Warning ("Error al limpiar Shell Launcher: {0}" -f $_)
    Write-Host "Esto puede ser normal si Shell Launcher no estaba configurado." -ForegroundColor Gray
}

# --- FASE II: ELIMINAR ARCHIVOS DE LANZAMIENTO ---
Write-Host "`n=== FASE II: ELIMINANDO ARCHIVOS DE LANZAMIENTO ===" -ForegroundColor Magenta

if (Test-Path $LauncherBatchPath) {
    try {
        Remove-Item $LauncherBatchPath -Force
        Write-Host ("[OK] Archivo de lanzamiento eliminado: {0}" -f $LauncherBatchPath) -ForegroundColor Green
    }
    catch {
        Write-Warning ("No se pudo eliminar el archivo de lanzamiento: {0}" -f $_)
    }
} else {
    Write-Host "INFO: Archivo de lanzamiento no encontrado." -ForegroundColor Cyan
}

# --- FASE III: GESTI�N DEL USUARIO ---
Write-Host ("`n=== FASE III: GESTI�N DEL USUARIO '{0}' ===" -f $KioskUserName) -ForegroundColor Magenta

$ExistingUser = Get-LocalUser -Name $KioskUserName -ErrorAction SilentlyContinue
if ($ExistingUser) {
    if (Confirm-Action ("�Desea ELIMINAR completamente el usuario '{0}'?" -f $KioskUserName) "N") {
        try {
            Write-Host "Cerrando sesiones activas del usuario (si existen)..." -ForegroundColor Cyan
            $UserSessions = (query user 2>$null) | Where-Object { $_ -match $KioskUserName }
            if ($UserSessions) {
                $parts = -split $UserSessions
                if ($parts.Length -ge 3) {
                    $SessionId = $parts[2]
                    logoff $SessionId
                    Start-Sleep -Seconds 2
                }
            }

            Write-Host ("Eliminando usuario '{0}'..." -f $KioskUserName) -ForegroundColor Cyan
            Remove-LocalUser -Name $KioskUserName
            Write-Host ("[OK] Usuario '{0}' eliminado." -f $KioskUserName) -ForegroundColor Green

            $UserProfilePath = "C:\Users\$KioskUserName"
            if ((Test-Path $UserProfilePath) -and (Confirm-Action ("�Desea eliminar tambi�n el directorio del perfil ({0})?" -f $UserProfilePath) "N")) {
                Write-Host "Eliminando directorio del perfil..." -ForegroundColor Cyan
                Remove-Item $UserProfilePath -Recurse -Force
                Write-Host "[OK] Directorio del perfil eliminado." -ForegroundColor Green
            }
        }
        catch {
            Write-Error ("Error al eliminar el usuario '{0}': {1}" -f $KioskUserName, $_)
        }
    } else {
        Write-Host ("Usuario '{0}' conservado." -f $KioskUserName) -ForegroundColor Cyan
        if (Confirm-Action ("�Desea DESHABILITAR el usuario '{0}' en su lugar?" -f $KioskUserName) "S") {
            Disable-LocalUser -Name $KioskUserName
            Write-Host ("[OK] Usuario '{0}' deshabilitado." -f $KioskUserName) -ForegroundColor Green
        }
    }
} else {
    Write-Host ("INFO: Usuario '{0}' no encontrado." -f $KioskUserName) -ForegroundColor Cyan
}

# --- FASE IV: GESTI�N DE STEAM ---
Write-Host "`n=== FASE IV: GESTI�N DE STEAM ===" -ForegroundColor Magenta

if (Get-SteamPath) {
    if (Confirm-Action "�Desea DESINSTALAR Steam completamente?" "N") {
        try {
            Write-Host "Cerrando procesos de Steam..." -ForegroundColor Cyan
            Get-process steam* -ErrorAction SilentlyContinue | Stop-process -Force

            $SteamUninstaller = Get-SteamUninstaller
            if ($SteamUninstaller) {
                Write-Host "Ejecutando desinstalador oficial de Steam..." -ForegroundColor Cyan
                # Invocaci�n m�s robusta de cmd con argumentos separados
                Start-process -FilePath "cmd.exe" -ArgumentList "/c", $SteamUninstaller -Wait
                Write-Host "[OK] Proceso de desinstalaci�n finalizado." -ForegroundColor Green
            } else {
                Write-Warning "No se encontr� el desinstalador oficial. Se intentar� eliminar manualmente."
                $SteamPath = Get-SteamPath
                if ($SteamPath) {
                    Remove-Item $SteamPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                Remove-Item "HKLM:\SOFTWARE\WOW6432Node\Valve" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "[OK] Archivos de Steam eliminados manualmente." -ForegroundColor Green
            }
        }
        catch {
            Write-Error ("Error durante la desinstalaci�n de Steam: {0}" -f $_)
        }
    } else {
        Write-Host "Steam conservado." -ForegroundColor Cyan
    }
} else {
    Write-Host "INFO: Steam no encontrado en el sistema." -ForegroundColor Cyan
}

# --- FASE V: DESHABILITAR CARACTER�STICAS DE WINDOWS ---
Write-Host "`n=== FASE V: GESTI�N DE CARACTER�STICAS DE WINDOWS ===" -ForegroundColor Magenta

try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -eq "Enabled") {
        if (Confirm-Action "�Desea DESHABILITAR la caracter�stica Shell Launcher de Windows?" "S") {
            Write-Host "Deshabilitando caracter�stica Shell Launcher..." -ForegroundColor Cyan
            Disable-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher -NoRestart
            Write-Host "[OK] Caracter�stica deshabilitada. Se requiere un reinicio." -ForegroundColor Green
        }
    } else {
        Write-Host "INFO: La caracter�stica Shell Launcher ya est� deshabilitada o no est� presente." -ForegroundColor Cyan
    }
}
catch {
    Write-Warning ("No se pudo verificar la caracter�stica Shell Launcher: {0}" -f $_)
}

# --- FINALIZACI�N ---
Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "                         REVERSI�N COMPLETADA" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "`nPor favor, REINICIE el sistema para que todos los cambios surtan efecto." -ForegroundColor Yellow
