Auditor Python Seguridad – Community Edition 

Versión demostrativa educativa del auditor y analizador de seguridad en Windows orientado a Blue Team.

Autor: Eros Baccigalupi
Año: 2025
Licencia: MIT (solo esta edición)

Descripción

Esta es la versión Community del proyecto Auditor Python Seguridad, desarrollada con fines educativos y de demostración.
Permite evaluar conceptos básicos de auditoría en sistemas Windows, mostrando parte de las capacidades del sistema completo:

La versión completa (privada/comercial) incluye:

-Detección de soluciones antimalware registradas (WMI).
-Auditorías completas de políticas, cuentas y contraseñas.
-Comprobaciones de integridad.
-Sincronización horaria.
-Escaneos opcionales de puertos con nmap (requiere python-nmap y el binario nmap).
-Detección de soluciones antimalware registradas (WMI).
-Identificación de servicios críticos e inseguros.
-Verificación de cuentas predeterminadas y prueba IPC$.
-Lectura de políticas locales (secedit) para evaluar la política de contraseñas.
-Detección de agentes SIEM/FIM y comprobación del servicio EventLog.
-Generación automática de reportes TXT/CSV con evidencias.
-Generación de reportes PCI‑DSS.

⚙️Requisitos

Windows 10/11/Server

Python 3.8 o superior

Instalación de dependencias mínimas:
```bash
pip install psutil wmi
```
🚀Ejecución
```bash
python auditor_demo.py
```
Ejecutar preferentemente como Administrador para obtener resultados completos

Ejemplo de salida:
```yaml
Antivirus detectados:
Windows Defender

Servicios inseguros:
No se encontraron servicios inseguros.
```

📁Estructura del repositorio:
```
auditor_python_seguridad_community/
├─ auditor_demo.py
├─ README.md
├─ LICENSE
└─ screenshots/
   ├─ demo_console.png
   └─ ejecutable_preview.png
```

📜Avisos

Esta edición es únicamente demostrativa.
El código completo y las funcionalidades avanzadas se mantienen bajo licencia propietaria.
Para uso comercial, integración o acceso a la versión completa, contactarse con el autor.

⚖️Licencia

Versión Community Edition bajo licencia MIT.
El proyecto original y completo se encuentra protegido bajo licencia propietaria.
