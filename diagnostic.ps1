# ===================================================================================
# Script de Diagnóstico y Corrección de Visibilidad de Usuario
# Versión: 1.0
# Propósito: Diagnosticar y corregir problemas de visibilidad de usuarios en login
# ===================================================================================

param(
    [string]$UserName = "gamer"
)

Write-Host "=== Diagnóstico de Visibilidad de Usuario: $UserName ===" -ForegroundColor Magenta

# Verificar privilegios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Este script debe ejecutarse con privilegios de Administrador."
    exit
}

# 1. Verificar si el usuario existe
Write-Host "`n1. Verificando existencia del usuario..." -ForegroundColor Yellow
$User = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($User) {
    Write-Host "? Usuario '$UserName' encontrado" -ForegroundColor Green
    Write-Host "  - Habilitado: $($User.Enabled)" -ForegroundColor Gray
    Write-Host "  - Último inicio de sesión: $($User.LastLogon)" -ForegroundColor Gray
    Write-Host "  - Contraseña requerida: $($User.PasswordRequired)" -ForegroundColor Gray
} else {
    Write-Host "? Usuario '$UserName' NO encontrado" -ForegroundColor Red
    exit
}

# 2. Verificar membresía de grupos
Write-Host "`n2. Verificando membresía de grupos..." -ForegroundColor Yellow
try {
    $UserGroups = Get-LocalGroup | Where-Object { 
        (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | Where-Object Name -like "*$UserName") 
    }
    if ($UserGroups) {
        Write-Host "? Usuario pertenece a los siguientes grupos:" -ForegroundColor Green
        foreach ($group in $UserGroups) {
            Write-Host "  - $($group.Name)" -ForegroundColor Gray
        }
    } else {
        Write-Host "? Usuario no pertenece a ningún grupo visible" -ForegroundColor Yellow
        Write-Host "Agregando al grupo Users..." -ForegroundColor Cyan
        Add-LocalGroupMember -Group "Users" -Member $UserName -ErrorAction SilentlyContinue
        Write-Host "? Usuario agregado al grupo Users" -ForegroundColor Green
    }
} catch {
    Write-Warning "Error verificando grupos: $_"
}

# 3. Verificar configuración del registro
Write-Host "`n3. Verificando configuración del registro..." -ForegroundColor Yellow

$SpecialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
if (Test-Path $SpecialAccountsPath) {
    $HiddenStatus = Get-ItemProperty -Path $SpecialAccountsPath -Name $UserName -ErrorAction SilentlyContinue
    if ($HiddenStatus) {
        if ($HiddenStatus.$UserName -eq 0) {
            Write-Host "? Usuario está marcado como OCULTO en el registro" -ForegroundColor Yellow
            Write-Host "Corrigiendo..." -ForegroundColor Cyan
            Set-ItemProperty -Path $SpecialAccountsPath -Name $UserName -Value 1
            Write-Host "? Usuario marcado como VISIBLE" -ForegroundColor Green
        } else {
            Write-Host "? Usuario marcado como VISIBLE en el registro" -ForegroundColor Green
        }
    } else {
        Write-Host "? Usuario no tiene entrada específica (comportamiento por defecto)" -ForegroundColor Cyan
    }
} else {
    Write-Host "? No existe configuración de SpecialAccounts" -ForegroundColor Cyan
}

# 4. Verificar perfil de usuario
Write-Host "`n4. Verificando perfil de usuario..." -ForegroundColor Yellow
$UserProfilePath = "C:\Users\$UserName"
if (Test-Path $UserProfilePath) {
    Write-Host "? Directorio de perfil existe: $UserProfilePath" -ForegroundColor Green
} else {
    Write-Host "? Directorio de perfil NO existe" -ForegroundColor Yellow
    Write-Host "Esto puede causar problemas en el primer inicio de sesión" -ForegroundColor Gray
}

# 5. Verificar políticas locales
Write-Host "`n5. Verificando políticas locales..." -ForegroundColor Yellow
$WinlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$DontDisplayLastUserName = Get-ItemProperty -Path $WinlogonPath -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
if ($DontDisplayLastUserName -and $DontDisplayLastUserName.DontDisplayLastUserName -eq 1) {
    Write-Host "? Política activa: No mostrar último nombre de usuario" -ForegroundColor Yellow
    Write-Host "  Esto requiere ingreso manual de credenciales" -ForegroundColor Gray
}

$AutoAdminLogon = Get-ItemProperty -Path $WinlogonPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
if ($AutoAdminLogon -and $AutoAdminLogon.AutoAdminLogon -eq "1") {
    Write-Host "? Auto-login está configurado" -ForegroundColor Cyan
}

# 6. Verificar configuración de UAC
Write-Host "`n6. Verificando configuración de UAC..." -ForegroundColor Yellow
$UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ConsentPromptBehaviorUser = Get-ItemProperty -Path $UACPath -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
if ($ConsentPromptBehaviorUser) {
    Write-Host "? Configuración UAC para usuarios: $($ConsentPromptBehaviorUser.ConsentPromptBehaviorUser)" -ForegroundColor Cyan
}

# 7. Forzar visibilidad del usuario
Write-Host "`n7. Aplicando correcciones de visibilidad..." -ForegroundColor Yellow

# Crear la entrada en SpecialAccounts si no existe
if (!(Test-Path $SpecialAccountsPath)) {
    New-Item -Path $SpecialAccountsPath -Force | Out-Null
    Write-Host "? Clave SpecialAccounts creada" -ForegroundColor Green
}

# Asegurar que el usuario esté visible
Set-ItemProperty -Path $SpecialAccountsPath -Name $UserName -Value 1 -Type DWord
Write-Host "? Usuario configurado como visible" -ForegroundColor Green

# Habilitar el usuario si está deshabilitado
if (-not $User.Enabled) {
    Enable-LocalUser -Name $UserName
    Write-Host "? Usuario habilitado" -ForegroundColor Green
}

# 8. Instrucciones finales
Write-Host "`n=== INSTRUCCIONES PARA ACCEDER AL USUARIO ===" -ForegroundColor Magenta
Write-Host "Si el usuario '$UserName' no aparece en la pantalla de login:" -ForegroundColor Yellow
Write-Host ""
Write-Host "MÉTODO 1 - Ctrl+Alt+Del:" -ForegroundColor Cyan
Write-Host "  1. Presione Ctrl+Alt+Del en la pantalla de login" -ForegroundColor Gray
Write-Host "  2. Seleccione 'Cambiar usuario' o ingrese credenciales manualmente" -ForegroundColor Gray
Write-Host ""
Write-Host "MÉTODO 2 - Otro usuario:" -ForegroundColor Cyan  
Write-Host "  1. Busque un enlace 'Otro usuario' en la pantalla de login" -ForegroundColor Gray
Write-Host "  2. Haga clic e ingrese:" -ForegroundColor Gray
Write-Host "     Usuario: $UserName" -ForegroundColor Gray
Write-Host "     Contraseña: (la contraseña que configuró)" -ForegroundColor Gray
Write-Host ""
Write-Host "MÉTODO 3 - Reiniciar:" -ForegroundColor Cyan
Write-Host "  1. Reinicie el sistema" -ForegroundColor Gray
Write-Host "  2. Los cambios del registro pueden requerir reinicio" -ForegroundColor Gray
Write-Host ""
Write-Host "Si sigue teniendo problemas, verifique:" -ForegroundColor Yellow
Write-Host "- Políticas de grupo locales o de dominio" -ForegroundColor Gray
Write-Host "- Configuración de seguridad local" -ForegroundColor Gray
Write-Host "- Software de terceros que modifique la pantalla de login" -ForegroundColor Gray