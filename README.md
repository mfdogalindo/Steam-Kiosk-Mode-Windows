# Steam Kiosk Configuration Scripts

[🇺🇸 English](#english) | [🇪🇸 Español](#español)

---

## English

### Overview
This repository contains PowerShell scripts to configure, diagnose, and revert a Windows machine as a Steam gaming kiosk. The kiosk mode automatically launches Steam in Big Picture mode instead of the Windows desktop for a dedicated gaming experience.

### Scripts Included

#### 📦 `install.ps1` - Main Installation Script
Configures your Windows machine as a Steam kiosk by:
- Creating a dedicated "gamer" user account
- Installing Steam automatically if not present
- Configuring Windows Shell Launcher to replace the desktop with Steam Big Picture
- Setting up all necessary permissions and registry entries

#### 🔍 `diagnostic.ps1` - User Visibility Diagnostic Script
Diagnoses and fixes user visibility issues in the Windows login screen:
- Checks if the "gamer" user exists and is properly configured
- Verifies group memberships and permissions
- Fixes registry entries for user visibility
- Provides manual login instructions if needed

#### ↩️ `revert.ps1` - Reversion Script
Completely reverts the kiosk configuration:
- Removes Shell Launcher configuration
- Optionally deletes the "gamer" user account
- Optionally uninstalls Steam
- Restores normal Windows desktop functionality
- Provides interactive prompts for selective restoration

### System Requirements

- **Windows 10/11** (Enterprise, Education, or Pro editions recommended)
- **Administrator privileges** required
- **PowerShell 5.0+**
- **Internet connection** (for Steam download if not installed)

### Installation Instructions

#### Step 1: Prepare Your System
1. Open **PowerShell as Administrator**
2. Set execution policy if needed:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

#### Step 2: Download and Unblock Scripts
1. Download all three scripts to the same folder
2. Unblock the scripts to avoid security warnings:
   ```powershell
   Unblock-File -Path .\install.ps1
   Unblock-File -Path .\diagnostic.ps1
   Unblock-File -Path .\revert.ps1
   ```

#### Step 3: Run Installation
1. Execute the main installation script:
   ```powershell
   .\install.ps1
   ```
2. Follow the prompts:
   - Enter a password for the "gamer" user (minimum 8 characters)
   - Wait for Steam installation and configuration
   - Allow the script to enable Shell Launcher feature

#### Step 4: Test the Configuration
1. **Log out** of your current Windows session
2. **Log in as "gamer"** using the password you created
3. Steam should launch automatically in Big Picture mode

### Troubleshooting

#### User Not Visible in Login Screen
If the "gamer" user doesn't appear in the Windows login screen:

1. **Run the diagnostic script:**
   ```powershell
   .\diagnostic.ps1
   ```

2. **Manual login methods:**
   - Press `Ctrl+Alt+Del` at the login screen
   - Click "Other user" and manually enter:
     - Username: `gamer`
     - Password: (your configured password)

3. **System restart:** Some registry changes require a restart to take effect

#### Steam Doesn't Launch Automatically
- Restart the system after installation
- Verify Shell Launcher is enabled: 
  ```powershell
  Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher
  ```
- Check if the batch file exists: `C:\Users\Public\custom.bat`

#### Configuration Errors
- Ensure you're running PowerShell as Administrator
- Verify Windows edition supports Shell Launcher
- Run the cleanup script first if you're reinstalling:
  ```powershell
  .\cleanup.ps1
  ```

### Reverting Changes

To completely remove the kiosk configuration:

1. **Run the reversion script:**
   ```powershell
   .\revert.ps1
   ```

2. **Follow the interactive prompts:**
   - Choose whether to delete the "gamer" user
   - Choose whether to uninstall Steam
   - Choose whether to disable Shell Launcher

3. **Restart your system** to apply all changes

### Security Considerations

- The "gamer" user has limited privileges (Users group only)
- Steam runs in a contained environment
- Normal Windows security features remain active
- Administrator access is still available through other user accounts

### Advanced Configuration

#### Customizing the Kiosk User
Edit the variables at the top of `install.ps1`:
```powershell
$KioskUserName = "your_custom_name"
$LauncherBatchPath = "C:\Users\Public\your_custom_launcher.bat"
```

#### Adding Additional Software
Modify the batch file at `C:\Users\Public\custom.bat` to launch additional applications alongside Steam.

### Support

For issues or questions:
1. Check the troubleshooting section above
2. Run the diagnostic script for automated problem detection
3. Review Windows Event Logs for detailed error information

---

## Español

### Descripción General
Este repositorio contiene scripts de PowerShell para configurar, diagnosticar y revertir una máquina Windows como un kiosco de juegos Steam. El modo kiosco lanza automáticamente Steam en modo Big Picture en lugar del escritorio de Windows para una experiencia de juego dedicada.

### Scripts Incluidos

#### 📦 `install.ps1` - Script Principal de Instalación
Configura tu máquina Windows como un kiosco Steam mediante:
- Creación de una cuenta de usuario dedicada "gamer"
- Instalación automática de Steam si no está presente
- Configuración de Windows Shell Launcher para reemplazar el escritorio con Steam Big Picture
- Configuración de todos los permisos y entradas de registro necesarios

#### 🔍 `diagnostic.ps1` - Script de Diagnóstico de Visibilidad de Usuario
Diagnostica y corrige problemas de visibilidad del usuario en la pantalla de inicio de sesión de Windows:
- Verifica si el usuario "gamer" existe y está configurado correctamente
- Verifica membresías de grupos y permisos
- Corrige entradas del registro para visibilidad del usuario
- Proporciona instrucciones de inicio de sesión manual si es necesario

#### ↩️ `revert.ps1` - Script de Reversión
Revierte completamente la configuración del kiosco:
- Elimina la configuración de Shell Launcher
- Opcionalmente elimina la cuenta de usuario "gamer"
- Opcionalmente desinstala Steam
- Restaura la funcionalidad normal del escritorio de Windows
- Proporciona indicaciones interactivas para restauración selectiva

### Requisitos del Sistema

- **Windows 10/11** (se recomiendan las ediciones Enterprise, Education o Pro)
- **Privilegios de administrador** requeridos
- **PowerShell 5.0+**
- **Conexión a internet** (para descarga de Steam si no está instalado)

### Instrucciones de Instalación

#### Paso 1: Preparar el Sistema
1. Abrir **PowerShell como Administrador**
2. Configurar política de ejecución si es necesario:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

#### Paso 2: Descargar y Desbloquear Scripts
1. Descargar los tres scripts en la misma carpeta
2. Desbloquear los scripts para evitar advertencias de seguridad:
   ```powershell
   Unblock-File -Path .\install.ps1
   Unblock-File -Path .\diagnostic.ps1
   Unblock-File -Path .\revert.ps1
   ```

#### Paso 3: Ejecutar Instalación
1. Ejecutar el script principal de instalación:
   ```powershell
   .\install.ps1
   ```
2. Seguir las indicaciones:
   - Ingresar contraseña para el usuario "gamer" (mínimo 8 caracteres)
   - Esperar la instalación y configuración de Steam
   - Permitir que el script habilite la característica Shell Launcher

#### Paso 4: Probar la Configuración
1. **Cerrar sesión** de tu sesión actual de Windows
2. **Iniciar sesión como "gamer"** usando la contraseña que creaste
3. Steam debería lanzarse automáticamente en modo Big Picture

### Solución de Problemas

#### Usuario No Visible en Pantalla de Inicio de Sesión
Si el usuario "gamer" no aparece en la pantalla de inicio de sesión de Windows:

1. **Ejecutar el script de diagnóstico:**
   ```powershell
   .\diagnostic.ps1
   ```

2. **Métodos de inicio de sesión manual:**
   - Presionar `Ctrl+Alt+Supr` en la pantalla de inicio de sesión
   - Hacer clic en "Otro usuario" e ingresar manualmente:
     - Nombre de usuario: `gamer`
     - Contraseña: (tu contraseña configurada)

3. **Reiniciar sistema:** Algunos cambios del registro requieren un reinicio para tener efecto

#### Steam No Se Lanza Automáticamente
- Reiniciar el sistema después de la instalación
- Verificar que Shell Launcher esté habilitado:
  ```powershell
  Get-WindowsOptionalFeature -Online -FeatureName Client-EmbeddedShellLauncher
  ```
- Verificar si existe el archivo batch: `C:\Users\Public\custom.bat`

#### Errores de Configuración
- Asegurar que estás ejecutando PowerShell como Administrador
- Verificar que la edición de Windows soporte Shell Launcher
- Ejecutar primero el script de limpieza si estás reinstalando:
  ```powershell
  .\cleanup.ps1
  ```

### Revertir Cambios

Para eliminar completamente la configuración del kiosco:

1. **Ejecutar el script de reversión:**
   ```powershell
   .\revert.ps1
   ```

2. **Seguir las indicaciones interactivas:**
   - Elegir si eliminar el usuario "gamer"
   - Elegir si desinstalar Steam
   - Elegir si deshabilitar Shell Launcher

3. **Reiniciar el sistema** para aplicar todos los cambios

### Consideraciones de Seguridad

- El usuario "gamer" tiene privilegios limitados (solo grupo Users)
- Steam se ejecuta en un ambiente contenido
- Las características normales de seguridad de Windows permanecen activas
- El acceso de administrador sigue disponible a través de otras cuentas de usuario

### Configuración Avanzada

#### Personalizar el Usuario del Kiosco
Editar las variables al inicio de `install.ps1`:
```powershell
$KioskUserName = "tu_nombre_personalizado"
$LauncherBatchPath = "C:\Users\Public\tu_launcher_personalizado.bat"
```

#### Agregar Software Adicional
Modificar el archivo batch en `C:\Users\Public\custom.bat` para lanzar aplicaciones adicionales junto con Steam.

### Soporte

Para problemas o preguntas:
1. Revisar la sección de solución de problemas arriba
2. Ejecutar el script de diagnóstico para detección automatizada de problemas
3. Revisar los Registros de Eventos de Windows para información detallada de errores

---

### File Structure / Estructura de Archivos

```
steam-kiosk-scripts/
├── install.ps1          # Main installation script / Script principal de instalación
├── diagnostic.ps1       # User visibility diagnostic / Diagnóstico de visibilidad de usuario
├── revert.ps1          # Configuration reversion / Reversión de configuración
└── README.md           # This documentation / Esta documentación
```

### License / Licencia

This project is provided as-is for educational and practical use. Please test in a non-production environment first.

Este proyecto se proporciona tal como está para uso educativo y práctico. Por favor, prueba primero en un entorno que no sea de producción.