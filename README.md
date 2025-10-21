# Auditor Python Seguridad

**Lo mejor de lo mejor** — Auditor y Analizador de Seguridad Windows orientado a Blue Team.

**Autores:** Eros Baccigalupi  
**Año:** 2025  
**Licencia:** MIT

## Descripción
Herramienta educativa desarrollada en Python que combina:
- Chequeos de cumplimiento (estilo PCI-DSS) y hardening de configuración en Windows.
- Detección básica de indicios de amenazas (presencia de soluciones antimalware, patrones sospechosos, servicios inseguros).
- Salida en TXT y CSV con evidencias para auditoría.

## Características principales
- Detección de soluciones antimalware registradas (WMI).
- Identificación de servicios críticos e inseguros.
- Verificación de cuentas predeterminadas y prueba IPC$.
- Lectura de políticas locales (secedit) para evaluar la política de contraseñas.
- Detección de agentes SIEM/FIM y comprobación del servicio EventLog.
- Escaneo opcional de puertos con nmap (requiere python-nmap y el binario nmap).
- Generación de reportes TXT y CSV con evidencias.

## Requisitos
- Windows (recomendado Windows 10/11/Server)  
- Python 3.8+  
- Privilegios de Administrador para obtener resultados completos

Instalar dependencias:
```bash
pip install -r requirements.txt
```

## Uso rápido
```bash
python src/auditor_seguridad.py
```
Ejecutar como Administrador. Los resultados se guardan en archivos `Auditoria_PCI_DSS_<HOST>_<FECHA>.txt` y `.csv`.

## Estructura del repositorio
```
auditor-python-seguridad/
├─ src/
│  └─ auditor_seguridad.py
├─ docs/
│  └─ manual_tecnico.md
├─ README.md
├─ LICENSE
└─ requirements.txt
```

## Contribuir
1. Haz fork del repositorio.
2. Crea una rama feature: `feature/mi-cambio`.
3. Agrega commits claros y abre un Pull Request.
4. Mantén documentación y pruebas actualizadas.

## Avisos legales / Ética
No uses esta herramienta para escanear sistemas sin autorización. Su uso no autorizado puede ser ilegal y causar daños. Emplea el script únicamente en entornos de prueba o con permiso explícito.

## Licencia
Proyecto bajo licencia MIT. Ver archivo `LICENSE`.
