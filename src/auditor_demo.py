import wmi
import psutil

def detectar_antivirus():
    try:
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        avs = c.query("SELECT * FROM AntiVirusProduct")
        if not avs:
            return "No se detectaron productos antimalware registrados."
        resultado = [av.displayName for av in avs]
        return "\n".join(resultado)
    except Exception as e:
        return f"Error detectando antivirus: {e}"

def servicios_inseguros():
    inseguros = ["Telnet", "FTP", "RemoteRegistry"]
    encontrados = []
    for s in inseguros:
        try:
            svc = psutil.win_service_get(s)
            info = svc.as_dict()
            encontrados.append(f"{s} ({info['status']})")
        except Exception:
            pass
    return encontrados if encontrados else ["No se encontraron servicios inseguros."]

if __name__ == "__main__":
    print("Antivirus detectados:")
    print(detectar_antivirus())
    print("\nServicios inseguros:")
    print(servicios_inseguros())
