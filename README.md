# PortSentry 🔍

Escáner de puertos TCP con detección de servicios, análisis de riesgo y exportación de reportes. Desarrollado como proyecto de portafolio en ciberseguridad / hacking ético.

> ⚠️ **Uso exclusivo en entornos autorizados.** 

---

## Características

- ⚡ **Escaneo concurrente** con hilos configurables
- 🎯 **Detección de servicios** con base de conocimiento de 25+ puertos comunes
- 🚨 **Análisis de riesgo** en 5 niveles: CRÍTICO / ALTO / MEDIO / BAJO / INFO
- 🏷️ **Captura de banners** para fingerprinting de versiones
- 📊 **Exportación** a JSON y CSV para integrar con otras herramientas
- 🖥️ Salida coloreada en terminal

## Instalación

```bash
git clone https://github.com/tu-usuario/portsentry.git
cd portsentry
python scanner.py --help
```

No requiere dependencias externas. Solo Python 3.10+.

## Uso

```bash
# Escaneo básico (puertos 1-1024)
python scanner.py 192.168.1.1

# Solo puertos más conocidos (más rápido)
python scanner.py 192.168.1.1 --top

# Rango personalizado con captura de banners
python scanner.py 192.168.1.1 -p 1-65535 --banners

# Puertos específicos y exportar reporte
python scanner.py 192.168.1.1 -p 22,80,443,3306,8080 --json reporte.json --csv reporte.csv

# Ajustar velocidad (más workers = más rápido, más ruidoso)
python scanner.py 192.168.1.1 -w 200 -t 0.5
```

## Ejemplo de salida

```
╔═══════════════════════════════════════════════════╗
║           PortSentry v1.0  -  Port Scanner        ║
║      Escaneo de puertos realizado con éxito       ║
╚═══════════════════════════════════════════════════╝

[*] Escaneando 1024 puertos en 192.168.1.10 ...
[*] Timeout: 1.0s  |  Workers: 100

  PUERTO     ESTADO    SERVICIO         RIESGO    NOTA
  ---------- --------  ---------------  --------  ------------------------------
  445  /tcp  ABIERTO   smb              CRÍTICO   EternalBlue (MS17-010), enumeración de shares
  23   /tcp  ABIERTO   telnet           CRÍTICO   Protocolo obsoleto, tráfico sin cifrar
  21   /tcp  ABIERTO   ftp              ALTO      Credenciales en texto plano, posible anon login
  22   /tcp  ABIERTO   ssh              MEDIO     Verificar versión vulnerable, fuerza bruta posible
  80   /tcp  ABIERTO   http             MEDIO     Sin cifrado, verificar versión del servidor web

────────────────────────────────────────────────────────────
  Resumen del escaneo
────────────────────────────────────────────────────────────
  Objetivo    : 192.168.1.10
  Duración    : 3.41s
  Puertos     : 5 abiertos

  CRÍTICO  : 2 puerto(s)
  ALTO     : 1 puerto(s)
  MEDIO    : 2 puerto(s)
```

## Niveles de riesgo

| Nivel    | Descripción                                            |
|----------|--------------------------------------------------------|
| CRÍTICO  | Vulnerabilidad grave o servicio sin autenticación      |
| ALTO     | Protocolo inseguro o vector de ataque conocido         |
| MEDIO    | Requiere revisión, puede ser vector según configuración|
| BAJO     | Servicio generalmente seguro, verificar configuración  |
| INFO     | Servicio no catalogado, investigar manualmente         |

## Entornos de práctica recomendados

- [TryHackMe](https://tryhackme.com) — Máquinas vulnerables en la nube
- [HackTheBox](https://hackthebox.com) — CTFs y laboratorios
- [Metasploitable 2/3](https://sourceforge.net/projects/metasploitable/) — VM vulnerable local
- `scanme.nmap.org` — Host oficial de Nmap para pruebas

## Hoja de ruta

- [ ] Detección de OS (TTL fingerprinting)
- [ ] Soporte UDP
- [ ] Reporte HTML visual
- [ ] Integración con CVE database (API NVD)

## Contexto educativo

Este proyecto forma parte de mi preparación para la certificación **eJPT (Junior Penetration Tester)** y documenta el aprendizaje práctico de:
- Reconocimiento de redes y enumeración de servicios
- Programación en Python para ciberseguridad
- Metodología de análisis de riesgo

## Licencia

MIT — libre para uso educativo. El autor no se responsabiliza del uso indebido de esta herramienta.
