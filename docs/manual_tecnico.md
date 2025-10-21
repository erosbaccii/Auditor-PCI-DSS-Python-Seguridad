# Manual técnico (breve)

## Objetivo
Explicar brevemente los chequeos implementados y cómo interpretar los resultados.

## Chequeos incluidos
- Detección de antivirus: usa WMI (root\SecurityCenter2) para listar productos antimalware.
- Servicios: identifica servicios críticos e inseguros (telnet, ftp, remote registry, SNMP).
- Cuentas predeterminadas: busca cuentas comunes del sistema y prueba acceso IPC$.
- Política de contraseñas: exporta la política local con `secedit` y extrae parámetros relevantes.
- Usuarios inactivos: analiza la salida de `net user` para identificar inactividad > 90 días.
- Protector de pantalla: comprueba `ScreenSaverIsSecure` y `ScreenSaveTimeOut`.
- EventLog y agentes: verifica que el servicio EventLog esté activo y busca agentes SIEM/FIM comunes.
- FIM candidates: busca procesos y rutas típicas de soluciones de File Integrity Monitoring.
- Sincronización de hora: consulta `w32tm /query /status` para validar origen NTP.
- Nmap (opcional): escaneo de puertos 1-1024 mediante python-nmap (si está disponible).

## Formato de salida
El script genera:
- `Auditoria_PCI_DSS_<HOST>_<FECHA>.txt` — informe plano con evidencias por chequeo.
- `Auditoria_PCI_DSS_<HOST>_<FECHA>.csv` — versión estructurada para hojas de cálculo.

## Recomendaciones
- Ejecutar con privilegios de Administrador.
- Usar en entornos de prueba o con autorización.
- Para integración con un SIEM, adaptar la salida a JSON y enviar eventos.
- Considerar añadir tests unitarios para parsers (por ejemplo, parseo de `secedit`).

## Extensiones sugeridas
- Integración con VirusTotal API para enriquecer detecciones por hash.
- Añadir análisis estático de archivos (hashing y búsqueda de patrones).
- Implementar modo "daemon" para escaneo periódico y alertas.
