#!/usr/bin/env python3
"""
PortSentry - Escáner de puertos con detección de servicios y análisis de riesgo
Autor: Tu nombre
Descripción: Herramienta educativa para reconocimiento de redes en entornos controlados
"""

import socket
import argparse
import json
import csv
import sys
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Base de conocimiento de servicios ────────────────────────────────────────

SERVICE_DB = {
    21:   {"name": "FTP",        "riesgo": "ALTO",   "nota": "Credenciales en texto plano, posible anon login"},
    22:   {"name": "SSH",        "riesgo": "MEDIO",  "nota": "Verificar versión vulnerable, fuerza bruta posible"},
    23:   {"name": "Telnet",     "riesgo": "CRÍTICO","nota": "Protocolo obsoleto, tráfico sin cifrar"},
    25:   {"name": "SMTP",       "riesgo": "MEDIO",  "nota": "Posible open relay o enumeración de usuarios"},
    53:   {"name": "DNS",        "riesgo": "MEDIO",  "nota": "Verificar transferencia de zona (AXFR)"},
    80:   {"name": "HTTP",       "riesgo": "MEDIO",  "nota": "Sin cifrado, verificar versión del servidor web"},
    110:  {"name": "POP3",       "riesgo": "ALTO",   "nota": "Credenciales en texto plano"},
    111:  {"name": "RPCBind",    "riesgo": "ALTO",   "nota": "Puede exponer servicios NFS/NIS"},
    135:  {"name": "MSRPC",      "riesgo": "ALTO",   "nota": "Vector común en entornos Windows"},
    139:  {"name": "NetBIOS",    "riesgo": "ALTO",   "nota": "Enumeración SMB, posible EternalBlue"},
    143:  {"name": "IMAP",       "riesgo": "MEDIO",  "nota": "Credenciales en texto plano si no hay TLS"},
    443:  {"name": "HTTPS",      "riesgo": "BAJO",   "nota": "Verificar certificado y versión TLS"},
    445:  {"name": "SMB",        "riesgo": "CRÍTICO","nota": "EternalBlue (MS17-010), enumeración de shares"},
    993:  {"name": "IMAPS",      "riesgo": "BAJO",   "nota": "IMAP cifrado, verificar certificado"},
    995:  {"name": "POP3S",      "riesgo": "BAJO",   "nota": "POP3 cifrado"},
    1433: {"name": "MSSQL",      "riesgo": "ALTO",   "nota": "Base de datos expuesta, credenciales por defecto"},
    1521: {"name": "Oracle DB",  "riesgo": "ALTO",   "nota": "Base de datos expuesta"},
    2049: {"name": "NFS",        "riesgo": "ALTO",   "nota": "Posible acceso a sistema de ficheros remoto"},
    3306: {"name": "MySQL",      "riesgo": "ALTO",   "nota": "Base de datos expuesta, acceso sin auth posible"},
    3389: {"name": "RDP",        "riesgo": "ALTO",   "nota": "BlueKeep (CVE-2019-0708), fuerza bruta"},
    4444: {"name": "Metasploit", "riesgo": "CRÍTICO","nota": "Puerto típico de reverse shell / C2"},
    5432: {"name": "PostgreSQL", "riesgo": "ALTO",   "nota": "Base de datos expuesta"},
    5900: {"name": "VNC",        "riesgo": "ALTO",   "nota": "Control remoto, auth débil frecuente"},
    6379: {"name": "Redis",      "riesgo": "CRÍTICO","nota": "Frecuentemente sin autenticación"},
    8080: {"name": "HTTP-Alt",   "riesgo": "MEDIO",  "nota": "Servidor web alternativo o proxy"},
    8443: {"name": "HTTPS-Alt",  "riesgo": "MEDIO",  "nota": "Panel de administración frecuente"},
    9200: {"name": "Elasticsearch","riesgo":"CRÍTICO","nota": "API sin auth expuesta, fuga masiva de datos"},
    27017:{"name": "MongoDB",    "riesgo": "CRÍTICO","nota": "Base de datos sin auth por defecto"},
}

RIESGO_ORDEN = {"CRÍTICO": 4, "ALTO": 3, "MEDIO": 2, "BAJO": 1, "INFO": 0}
RIESGO_COLOR = {
    "CRÍTICO": "\033[91m",  # Rojo
    "ALTO":    "\033[93m",  # Amarillo
    "MEDIO":   "\033[94m",  # Azul
    "BAJO":    "\033[92m",  # Verde
    "INFO":    "\033[97m",  # Blanco
}
RESET = "\033[0m"
BOLD  = "\033[1m"

# ─── Funciones de escaneo ─────────────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Intenta obtener el banner del servicio."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                return banner[:120] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""

def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> dict | None:
    """Escanea un puerto individual. Devuelve dict si está abierto, None si cerrado."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                info = SERVICE_DB.get(port, {"name": "Desconocido", "riesgo": "INFO", "nota": "Servicio no catalogado"})
                banner = grab_banner(ip, port, timeout) if grab_banners else ""
                try:
                    service_name = socket.getservbyport(port)
                except Exception:
                    service_name = info["name"]
                return {
                    "puerto": port,
                    "estado": "ABIERTO",
                    "servicio": service_name,
                    "riesgo": info["riesgo"],
                    "nota": info["nota"],
                    "banner": banner,
                }
    except Exception:
        pass
    return None

def validar_objetivo(objetivo: str) -> str:
    """Valida que el objetivo sea una IP o hostname válido."""
    try:
        ipaddress.ip_address(objetivo)
        return objetivo
    except ValueError:
        try:
            return socket.gethostbyname(objetivo)
        except socket.gaierror:
            print(f"\n[!] No se puede resolver el objetivo: {objetivo}")
            sys.exit(1)

def parsear_puertos(spec: str) -> list[int]:
    """Convierte '22,80,100-200' en lista de enteros."""
    puertos = []
    for parte in spec.split(","):
        parte = parte.strip()
        if "-" in parte:
            ini, fin = parte.split("-", 1)
            puertos.extend(range(int(ini), int(fin) + 1))
        else:
            puertos.append(int(parte))
    return sorted(set(puertos))

# ─── Salida en pantalla ───────────────────────────────────────────────────────

def imprimir_banner():
    print(f"""
{BOLD}╔═══════════════════════════════════════════════════╗
║           juangrasantiago  -  Port Scanner        ║
║      Escaneo de puertos realizado con éxito       ║
╚═══════════════════════════════════════════════════╝{RESET}
""")

def imprimir_resultado(resultado: dict):
    color = RIESGO_COLOR.get(resultado["riesgo"], RESET)
    riesgo_fmt = f"{color}{resultado['riesgo']:8}{RESET}"
    print(f"  {BOLD}{resultado['puerto']:6}/tcp{RESET}  {resultado['estado']:8}  "
          f"{resultado['servicio']:15}  {riesgo_fmt}  {resultado['nota']}")
    if resultado.get("banner"):
        banner_limpio = resultado["banner"].replace("\n", " ").replace("\r", "")
        print(f"          {BOLD}Banner:{RESET} {banner_limpio[:100]}")

def imprimir_resumen(resultados: list[dict], ip: str, inicio: datetime, fin: datetime):
    duracion = (fin - inicio).total_seconds()
    conteo = {}
    for r in resultados:
        conteo[r["riesgo"]] = conteo.get(r["riesgo"], 0) + 1

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  Resumen del escaneo{RESET}")
    print(f"{'─'*60}")
    print(f"  Objetivo    : {ip}")
    print(f"  Inicio      : {inicio.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duración    : {duracion:.2f}s")
    print(f"  Puertos     : {len(resultados)} abiertos")
    print()
    for nivel in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]:
        if nivel in conteo:
            color = RIESGO_COLOR[nivel]
            print(f"  {color}{nivel:8}{RESET} : {conteo[nivel]} puerto(s)")
    print(f"{'─'*60}\n")

# ─── Exportación ─────────────────────────────────────────────────────────────

def exportar_json(resultados: list[dict], ip: str, fichero: str):
    datos = {
        "objetivo": ip,
        "fecha": datetime.now().isoformat(),
        "puertos_abiertos": len(resultados),
        "resultados": resultados,
    }
    with open(fichero, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    print(f"[+] Reporte JSON guardado en: {fichero}")

def exportar_csv(resultados: list[dict], fichero: str):
    campos = ["puerto", "estado", "servicio", "riesgo", "nota", "banner"]
    with open(fichero, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(resultados)
    print(f"[+] Reporte CSV guardado en:  {fichero}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PortSentry - Escáner de puertos educativo para pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python scanner.py 192.168.1.1
  python scanner.py 192.168.1.1 -p 1-1024
  python scanner.py 192.168.1.1 -p 22,80,443,3306 --banners
  python scanner.py scanme.nmap.org --top --json reporte.json
        """
    )
    parser.add_argument("objetivo", help="IP o hostname del objetivo")
    parser.add_argument("-p", "--puertos", default="1-1024",
                        help="Puertos a escanear. Ej: 22,80,100-200 (default: 1-1024)")
    parser.add_argument("--top", action="store_true",
                        help="Escanear solo los puertos más comunes (de SERVICE_DB)")
    parser.add_argument("--banners", action="store_true",
                        help="Intentar capturar banners de servicio")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Timeout por puerto en segundos (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Hilos concurrentes (default: 100)")
    parser.add_argument("--json", metavar="FICHERO",
                        help="Exportar reporte en formato JSON")
    parser.add_argument("--csv", metavar="FICHERO",
                        help="Exportar reporte en formato CSV")

    args = parser.parse_args()

    imprimir_banner()

    ip = validar_objetivo(args.objetivo)
    if ip != args.objetivo:
        print(f"[*] Resuelto: {args.objetivo} → {ip}")

    if args.top:
        puertos = sorted(SERVICE_DB.keys())
        print(f"[*] Modo --top: escaneando {len(puertos)} puertos conocidos")
    else:
        puertos = parsear_puertos(args.puertos)
        print(f"[*] Escaneando {len(puertos)} puertos en {ip} ...")

    print(f"[*] Timeout: {args.timeout}s  |  Workers: {args.workers}")
    if args.banners:
        print("[*] Captura de banners activada")
    print()
    print(f"  {'PUERTO':10} {'ESTADO':8}  {'SERVICIO':15}  {'RIESGO':8}  NOTA")
    print(f"  {'─'*10} {'─'*8}  {'─'*15}  {'─'*8}  {'─'*30}")

    inicio = datetime.now()
    resultados = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(scan_port, ip, p, args.timeout, args.banners): p
            for p in puertos
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                resultados.append(res)
                imprimir_resultado(res)

    fin = datetime.now()

    # Ordenar por nivel de riesgo descendente
    resultados.sort(key=lambda x: (RIESGO_ORDEN.get(x["riesgo"], 0), x["puerto"]), reverse=True)

    imprimir_resumen(resultados, ip, inicio, fin)

    if args.json:
        exportar_json(resultados, ip, args.json)
    if args.csv:
        exportar_csv(resultados, ip, args.csv)

    if not resultados:
        print("[!] No se encontraron puertos abiertos.")

if __name__ == "__main__":
    main()
