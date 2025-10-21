# Requiere: psutil, wmi, pywin32, python-nmap (opcional)
# Ejecutar como Administrador.

import subprocess
import os
import sys
import csv
import getpass
import psutil
import wmi
import winreg
from datetime import datetime, timedelta
import socket
import json
import re

# intenta importar python-nmap (wrapper)
try:
    import nmap
    NMAPPER_AVAILABLE = True
except Exception:
    NMAPPER_AVAILABLE = False

# ---------- Helpers ----------
def run_cmd(cmd, capture=True):
    """Ejecuta comando en shell, devuelve (returncode, stdout)."""
    try:
        proc = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        return proc.returncode, proc.stdout.strip()
    except Exception as e:
        return 1, f"ERROR: {e}"

def write_report_txt(path, blocks):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Informe de Auditoría PCI-DSS (generado: {datetime.now().isoformat()})\n")
        f.write("="*80 + "\n\n")
        for b in blocks:
            f.write("+--------------------------------------------------------------+\n")
            f.write(f"| Requisito: {b['requisito']}\n")
            f.write(f"| Resultado: {b['resultado']}\n")
            f.write("| Evidencia:\n")
            f.write(b['evidencia'] + "\n")
            f.write("+--------------------------------------------------------------+\n\n")

def write_report_csv(path, blocks):
    keys = ["requisito","resultado","evidencia"]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for b in blocks:
            writer.writerow({k: b[k] for k in keys})

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ---------- Environment info ----------
def get_windows_version():
    rc,out = run_cmd("ver")
    return out

def get_locale():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\International")
        val, _ = winreg.QueryValueEx(key, "LocaleName")
        winreg.CloseKey(key)
        return val
    except Exception:
        return "UNKNOWN"

# Deteccion de antivirus mediante WMI (root\SecurityCenter2) 
def detect_antivirus():
    evidence = []
    try:
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        avs = c.query("SELECT * FROM AntiVirusProduct")
        if not avs:
            return "No se detectaron productos antimalware registrados.", False
        for av in avs:
            st = getattr(av, "productState", None)
            evidence.append(f"{getattr(av,'displayName', 'N/A')} | exe: {getattr(av,'pathToSignedProductExe','N/A')} | state: {st}")
        return "\n".join(evidence), True
    except Exception as e:
        return f"Error detectando AV (WMI): {e}", False

#  Servicios
def check_services(services_list):
    found = []
    for svc in services_list:
        try:
            s = psutil.win_service_get(svc)
            info = s.as_dict()
            found.append(f"{svc} -> status: {info.get('status')} display_name: {info.get('display_name')}")
        except Exception:
            pass
    return found

def check_insecure_services():
    insecure = ["TlntSvr","Telnet","ftpsvc","FTP","RemoteRegistry","SNMP","WebClient"]
    running = []
    installed = []
    for svc in insecure:
        try:
            s = psutil.win_service_get(svc)
            info = s.as_dict()
            installed.append(f"{svc} ({info.get('display_name')})")
            if info.get('status') == 'running':
                running.append(f"{svc} ({info.get('display_name')})")
        except Exception:
            pass
    evidence = ""
    if not installed:
        evidence = "No se detectaron servicios inseguros instalados."
    else:
        evidence = "Servicios instalados: " + ", ".join(installed)
        if running:
            evidence += "\nServicios en ejecucion: " + ", ".join(running)
    return evidence, (len(running)==0)

#  Cuentas predeterminadas 
def check_default_accounts():
    defaults = ["Administrator","Administrador","Guest","Invitado","DefaultAccount","WDAGUtilityAccount"]
    evidence_lines = []
    rc,out = run_cmd("net user")
    if rc != 0:
        return "Error ejecutando 'net user': " + out, False
    users = []
    capture = False
    for line in out.splitlines():
        if re.search(r"---+", line):
            capture = True
            continue
        if capture:
            if line.strip()=="":
                continue
            if re.search(r"comando correctamente|command completed", line, re.IGNORECASE):
                break
            for token in line.split():
                users.append(token.strip())
    users_set = set(users)
    resultado = "Cumple"
    for d in defaults:
        if d in users_set:
            rc2, info = run_cmd(f'net user "{d}"')
            if rc2 != 0:
                evidence_lines.append(f"{d} -> existe pero fallo al consultar: {info}")
                resultado = "Cumple con observaciones"
            else:
                state = "no se pudo determinar"
                for l in info.splitlines():
                    if re.search(r"Account active|Cuenta activa|Cuenta habilitada|Active", l, re.IGNORECASE):
                        state = l.strip()
                        break
                rc3, out3 = run_cmd(f'net use \\\\localhost\\IPC$ \"\" /user:{d}')
                if rc3 == 0:
                    run_cmd('net use /delete \\\\localhost\\IPC$ >nul 2>&1')
                    evidence_lines.append(f"{d} -> Existe, {state}. ALERTA: permite acceso sin contraseña.")
                    resultado = "No cumple"
                else:
                    evidence_lines.append(f"{d} -> Existe, {state}. No permite acceso sin contraseña (prueba IPC$ fallida).")
                    if resultado != "No cumple":
                        resultado = "Cumple con observaciones"
    if not evidence_lines:
        return "No se encontraron cuentas predeterminadas en el sistema.", True
    return "\n".join(evidence_lines), (resultado=="Cumple")

#  Politicas de contraseñas (secedit export) 
def read_secpol():
    tmp = os.path.join(os.environ.get("TEMP","C:\\"),"secpol_export.inf")
    rc,out = run_cmd(f'secedit /export /cfg "{tmp}"')
    if rc != 0:
        return None, f"Error exportando secedit: {out}"
    try:
        with open(tmp, "r", encoding="utf-16", errors="ignore") as f:
            data = f.read()
    except Exception:
        with open(tmp, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
    try:
        os.remove(tmp)
    except Exception:
        pass
    return data, None

def parse_min_password_length(secpol_text):
    m = re.search(r"MinimumPasswordLength\s*=\s*(\d+)", secpol_text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

def parse_max_password_age(secpol_text):
    m = re.search(r"MaximumPasswordAge\s*=\s*(\d+)", secpol_text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

# ---------- Usuarios inactivos (>90d) ----------
def users_last_logon_check(threshold_days=90):
    rc,out = run_cmd("net user")
    if rc != 0:
        return "Error listando usuarios: " + out, False
    users = []
    capture = False
    for line in out.splitlines():
        if re.search(r"---+", line):
            capture = True
            continue
        if capture:
            if line.strip()=="":
                continue
            if re.search(r"comando correctamente|command completed", line, re.IGNORECASE):
                break
            for token in line.split():
                users.append(token.strip())
    evidence = []
    any_inactive = False
    today = datetime.now().date()
    for u in users:
        rc2, info = run_cmd(f'net user "{u}"')
        if rc2 != 0:
            continue
        last = None
        for l in info.splitlines():
            if re.search(r"Last logon|Last logon time|Último inicio|Last logon date|Last logon time", l, re.IGNORECASE):
                toks = l.split()
                for t in toks:
                    if re.search(r"\d{1,2}/\d{1,2}/\d{2,4}", t) or re.search(r"\d{4}-\d{2}-\d{2}", t):
                        for fmt in ("%m/%d/%Y","%d/%m/%Y","%m/%d/%y","%d/%m/%y","%Y-%m-%d"):
                            try:
                                d = datetime.strptime(t, fmt).date()
                                last = d
                                break
                            except Exception:
                                pass
                        if last:
                            break
                if last:
                    break
            if re.search(r"\bNever\b|\bNunca\b", l, re.IGNORECASE):
                last = None
                break
        if last is None:
            evidence.append(f"[{u}] No activity recorded / never logged on or unable to parse.")
            continue
        days = (today - last).days
        if days > threshold_days:
            any_inactive = True
            evidence.append(f"[{u}] Last logon: {last} ({days} days) -> INACTIVO (> {threshold_days}d)")
        else:
            evidence.append(f"[{u}] Last logon: {last} ({days} days) -> OK")
    return "\n".join(evidence), not any_inactive

# Protector de pantalla / timeout via registro (HKCU)
def check_screensaver_requirements():
    evidence = []
    ok_secure = False
    ok_timeout = False
    keys_to_check = [
        (winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"),
        (winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop")
    ]
    secure_val = None
    timeout_val = None
    for hive, sub in keys_to_check:
        try:
            k = winreg.OpenKey(hive, sub)
            try:
                sv, _ = winreg.QueryValueEx(k, "ScreenSaverIsSecure")
                secure_val = sv
            except Exception:
                pass
            try:
                tv, _ = winreg.QueryValueEx(k, "ScreenSaveTimeOut")
                timeout_val = int(tv)
            except Exception:
                pass
            winreg.CloseKey(k)
        except Exception:
            pass
    if secure_val is None:
        evidence.append("ScreenSaverIsSecure: no definido")
    else:
        evidence.append(f"ScreenSaverIsSecure: {secure_val}")
        if str(secure_val) == "1":
            ok_secure = True
    if timeout_val is None:
        evidence.append("ScreenSaveTimeOut: no definido")
    else:
        evidence.append(f"ScreenSaveTimeOut: {timeout_val} segundos")
        if timeout_val <= 900:
            ok_timeout = True
    final_ok = ok_secure and ok_timeout
    return "\n".join(evidence), final_ok

# EventLog y agentes SIEM/FIEM
def check_eventlog_and_agents():
    evidence = []
    try:
        ev = psutil.win_service_get("eventlog").as_dict()
        evidence.append(f"EventLog -> status: {ev.get('status')}")
        ev_ok = (ev.get('status') == 'running')
    except Exception:
        evidence.append("EventLog -> No se pudo consultar (servicio no encontrado o permisos).")
        ev_ok = False
    agents = ["WazuhSvc","mmaagent","splunkd","nxlog","winlogbeat","qradar-agent","ossec"]
    found_agents = []
    for a in agents:
        try:
            s = psutil.win_service_get(a)
            st = s.as_dict()
            if st.get("status") == "running":
                found_agents.append(f"{a} (running)")
            else:
                found_agents.append(f"{a} (installed:{st.get('status')})")
        except Exception:
            pass
    if found_agents:
        evidence.append("Agentes detectados: " + ", ".join(found_agents))
    else:
        evidence.append("No se detectaron agentes SIEM/FIM conocidos por nombre.")
    return "\n".join(evidence), (ev_ok and any("running" in x for x in found_agents))

# Candidatos para FIM (File Integrity Monitoring)
def check_fim_candidates():
    prots = [p.name().lower() for p in psutil.process_iter()]
    matches = []
    for name in ("ossec","wazuh","tripwire","qualys","fim"):
        for p in prots:
            if name in p:
                matches.append(p)
    evidence = ""
    if matches:
        evidence = "Procesos FIM detectados: " + ", ".join(set(matches))
        return evidence, True
    common_paths = [
        r"C:\Program Files\Wazuh",
        r"C:\Program Files (x86)\Wazuh",
        r"C:\ossec.conf",
        r"C:\tw.cfg"
    ]
    found = []
    for p in common_paths:
        if os.path.exists(p):
            found.append(p)
    if found:
        evidence = "Archivos o carpetas FIM detectadas: " + ", ".join(found)
        return evidence, True
    return "No se detectaron evidencias directas de soluciones FIM (procesos/archivos comunes).", False

# Sicronizacion horaria
def check_time_sync():
    rc,out = run_cmd("w32tm /query /status")
    if rc != 0:
        return f"w32tm no devolvió información: {out}", False
    src = None
    for line in out.splitlines():
        if line.strip().lower().startswith("source"):
            src = line.split(":",1)[1].strip()
            break
    if not src:
        return "No se detectó origen NTP en w32tm.", False
    if "Local CMOS Clock" in src:
        return f"Origen detectado: {src} (NO recomendado: reloj local).", False
    return f"Origen detectado: {src}", True

#  NMAP scan (python-nmap) 
def get_primary_ipv4_addresses():
    ips = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip and not ip.startswith("127."):
                    ips.append(ip)
    # uniq preserving order
    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq

def scan_with_nmap(targets=None, ports="1-1024", arguments="-sS -Pn --host-timeout 30s"):
    """
    Escanea targets (lista de IPs/hosts) con nmap usando python-nmap.
    Retorna (evidencia_texto, success_bool).
    """
    if not NMAPPER_AVAILABLE:
        return "python-nmap no está instalado en el entorno (pip install python-nmap) o no disponible.", False
    scanner = nmap.PortScanner(nmap_search_path=(
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe"
    ))
    evidence_lines = []
    any_open = False
    for t in targets:
        try:
            
            try:
                res = scanner.scan(hosts=t, ports=ports, arguments=arguments)
            except nmap.PortScannerError as e:
                return f"Error al ejecutar nmap: {e}. Asegurate que nmap esté instalado y en PATH.", False
            except Exception as e:
                return f"Error inesperado en nmap: {e}", False
            
            if t in scanner.all_hosts():
                st = scanner[t].state()
                evidence_lines.append(f"Host {t}: state={st}")
                for proto in scanner[t].all_protocols():
                    lports = scanner[t][proto].keys()
                    open_ports = [p for p in lports if scanner[t][proto][p]['state']=='open']
                    if open_ports:
                        any_open = True
                        evidence_lines.append(f"  Proto {proto} - puertos abiertos: {', '.join(map(str,open_ports))}")
                    else:
                        evidence_lines.append(f"  Proto {proto} - sin puertos abiertos en el rango solicitado.")
            else:
                evidence_lines.append(f"Host {t}: sin respuesta o no listable.")
        except Exception as ex:
            evidence_lines.append(f"Error escaneando {t}: {ex}")
    evtxt = "\n".join(evidence_lines) if evidence_lines else "No se obtuvo resultado de nmap."
    return evtxt, (not any_open)

# Main auditor 
def main():
    if os.name != "nt":
        print("Este script está diseñado para Windows.")
        sys.exit(1)
    if not is_admin():
        print("Advertencia: ejecutar como Administrador para obtener resultados completos.")
    blocks = []

    # Header 
    blocks.append({
        "requisito": "header",
        "resultado": "info",
        "evidencia": f"Equipo: {socket.gethostname()} | Usuario: {getpass.getuser()} | Windows: {get_windows_version()} | Locale: {get_locale()}"
    })

    # 2.2.2 cuentas predeterminadas
    ev, ok = check_default_accounts()
    blocks.append({"requisito":"2.2.2 – Cuentas predeterminadas del proveedor","resultado":("Cumple" if ok else "No cumple / Observaciones"),"evidencia":ev})

    # 2.2.3 separacion de funciones principales
    critical = ["NTDS","W3SVC","MSSQLSERVER","MySQL","Apache2.4","httpd","Docker","MicrosoftFTPSVC","ftpsvc","DNS","vmms"]
    found = check_services(critical)
    res = "Cumple"
    if len([f for f in found if "status: running" in f.lower() or "running" in f.lower()]) > 1:
        res = "No cumple"
    evtxt = "Funciones críticas encontradas:\n" + ("\n".join(found) if found else "No se detectaron servicios críticos de la lista.")
    blocks.append({"requisito":"2.2.3 – Separacion de funciones principales","resultado":res,"evidencia":evtxt})

    # 2.2.4/2.2.5 servicios inseguros
    ev, ok = check_insecure_services()
    blocks.append({"requisito":"2.2.4/2.2.5 – Servicios y protocolos inseguros","resultado":("Cumple" if ok else "No cumple"),"evidencia":ev})

    # 5.2.1 antivirus
    ev, ok_av = detect_antivirus()
    blocks.append({"requisito":"5.2.1 – Solucion antimalware instalada","resultado":("Cumple" if ok_av else "No cumple"),"evidencia":ev})

    # 8.2.6 usuarios inactivos >90 días
    ev, ok_users = users_last_logon_check(90)
    blocks.append({"requisito":"8.2.6 – Cuentas inactivas por mas de 90 dias","resultado":("Cumple" if ok_users else "No cumple"),"evidencia":ev})

    # 8.2.8 Protector de pantalla / reautenticacion
    ev, ok_ss = check_screensaver_requirements()
    blocks.append({"requisito":"8.2.8 – Reautenticacion tras 15 min","resultado":("Cumple" if ok_ss else "No cumple"),"evidencia":ev})

    # 8.3.6 & 8.3.9 Politicas de contraseñas
    secpol_text, err = read_secpol()
    if secpol_text is None:
        blocks.append({"requisito":"8.3.6 – Longitud minima de contraseña","resultado":"No se pudo evaluar","evidencia":err})
        blocks.append({"requisito":"8.3.9 – Expiracion maxima de contrasena","resultado":"No se pudo evaluar","evidencia":err})
    else:
        minlen = parse_min_password_length(secpol_text)
        if minlen is None:
            blocks.append({"requisito":"8.3.6 – Longitud minima de contraseña","resultado":"No cumple","evidencia":"No se encontró MinimumPasswordLength en la política."})
        else:
            blocks.append({"requisito":"8.3.6 – Longitud minima de contraseña","resultado":("Cumple" if minlen>=12 else "No cumple"),"evidencia":f"MinimumPasswordLength = {minlen}"})
        maxage = parse_max_password_age(secpol_text)
        if maxage is None:
            blocks.append({"requisito":"8.3.9 – Expiracion maxima de contrasena","resultado":"No cumple","evidencia":"No se encontró MaximumPasswordAge en la política."})
        else:
            blocks.append({"requisito":"8.3.9 – Expiracion maxima de contrasena","resultado":("Cumple" if maxage<=90 else "No cumple"),"evidencia":f"MaximumPasswordAge = {maxage}"})

    # 8.3.4 lockout threshold/duration
    rc,out = run_cmd("net accounts")
    if rc==0:
        thr=None
        dur=None
        for l in out.splitlines():
            if re.search(r"Lockout threshold|Lockout", l, re.IGNORECASE) and "=" in l:
                m = re.search(r"(\d+)", l)
                if m:
                    thr = int(m.group(1))
            if re.search(r"Lockout duration|Duration|dura", l, re.IGNORECASE) and "=" in l:
                m = re.search(r"(\d+)", l)
                if m:
                    dur = int(m.group(1))
        evidence = f"net accounts output excerpt:\n{out}\nParsed threshold={thr} duration={dur}"
        ok_thr = thr is not None and thr<=10
        ok_dur = dur is not None and dur>=30
        blocks.append({"requisito":"8.3.4 – Limite y duracion de bloqueo tras intentos fallidos","resultado":("Cumple" if (ok_thr and ok_dur) else "No cumple"),"evidencia":evidence})
    else:
        blocks.append({"requisito":"8.3.4 – Limite y duracion de bloqueo tras intentos fallidos","resultado":"No se pudo evaluar","evidencia":out})

    # 10.2.1 y 10.3.2 logs y agentes SIEM
    ev, ok_logs = check_eventlog_and_agents()
    blocks.append({"requisito":"10.2.1/10.3.2 – Registros y agentes SIEM","resultado":("Cumple" if ok_logs else "No cumple"),"evidencia":ev})

    # 10.3.4 FIM
    ev, ok_fim = check_fim_candidates()
    blocks.append({"requisito":"10.3.4 – Monitoreo de integridad (FIM)","resultado":("Cumple" if ok_fim else "No cumple"),"evidencia":ev})

    # 10.6.1 time sync
    ev, ok_time = check_time_sync()
    blocks.append({"requisito":"10.6.1 – Sincronizacion de hora con origen confiable","resultado":("Cumple" if ok_time else "No cumple"),"evidencia":ev})

    # Escaneo de puertos con nmap (python-nmap)
    # Determinar targets: localhost + IPs principales de interfaces
    targets = ["127.0.0.1"]
    primary_ips = get_primary_ipv4_addresses()
    for ip in primary_ips:
        if ip not in targets:
            targets.append(ip)
    # escaneamos 1-1024 (se puede modificar)
    if not NMAPPER_AVAILABLE:
        nmap_evidence = "python-nmap (biblioteca) no está instalada. Instalar con: pip install python-nmap. Además, requiere el binario nmap en PATH."
        nmap_ok = False
    else:
        nmap_evidence, nmap_ok = scan_with_nmap(targets=targets, ports="1-1024")
    blocks.append({"requisito":"NMAP – Escaneo de puertos (1-1024)","resultado":("Cumple (no se detectaron puertos abiertos en rango)" if nmap_ok else "Observado / No cumple"),"evidencia":f"Targets: {', '.join(targets)}\n{nmap_evidence}"})

    # Guardar Reportes
    fecha_tag = datetime.now().strftime("%Y-%m-%d_%H-%M")
    host = socket.gethostname()
    rpt = f"Auditoria_PCI_DSS_{host}_{fecha_tag}.txt"
    csvf = f"Auditoria_PCI_DSS_{host}_{fecha_tag}.csv"
    write_report_txt(rpt, blocks)
    write_report_csv(csvf, blocks)

    print("Auditoría finalizada.")
    print(f"Informe TXT: {os.path.abspath(rpt)}")
    print(f"Informe CSV: {os.path.abspath(csvf)}")

if __name__ == "__main__":
    main()
