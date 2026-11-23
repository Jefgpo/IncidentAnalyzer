"""Reglas de host: escalamiento (PE-*), comandos/procesos (EX-*) y movimiento lateral (LM-*)."""
from __future__ import annotations

import base64
import re

import pandas as pd

from app.detection.base import Context, Finding, Rule, clusters, distinct_bursts, make_finding, uniq
from app.lang import tx

HOUR = pd.Timedelta(hours=1)

Text = str | tuple[str, str]  # texto neutro (nombre de herramienta) o par (español, inglés)


def _t(v: Text) -> str:
    return tx(*v) if isinstance(v, tuple) else v


def _unknown(es: str, en: str) -> str:
    return tx(es, en)


# ------------------------------------------------------------------------ escalamiento
def pe001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    adds = df[(df["sem"] == "group_add") | df["action"].fillna("").str.contains(
        r"add.*member|member.*added|agregad[oa].*grupo|añadid[oa].*grupo", case=False, regex=True)]
    hits = adds[adds["group"].map(ctx.in_priv_group).astype(bool)].copy()
    hits["member"] = hits["target_user"].fillna(hits["user"])
    out = []
    for (member,), part in clusters(hits, ["member"], pd.Timedelta(hours=24)):
        groups = uniq(part["group"])
        actors = uniq(part["user"])
        hosts = ", ".join(uniq(part["host"]))
        who = ", ".join(actors) or _unknown("actor no informado", "unreported actor")
        span = f"{part['ts'].min():%d/%m %H:%M}–{part['ts'].max():%d/%m %H:%M}"
        summary = tx(f"La cuenta «{member}» fue agregada a grupo(s) privilegiado(s) {', '.join(groups)} en "
                     f"{hosts} por {who} ({span}).",
                     f"Account “{member}” was added to privileged group(s) {', '.join(groups)} on "
                     f"{hosts} by {who} ({span}).")
        title = tx(f"Alta en grupo privilegiado: «{member}» → {', '.join(groups)}",
                   f"Added to privileged group: “{member}” → {', '.join(groups)}")
        f = make_finding("PE-001", part, title, summary,
                         ctx, entity_cols=("user", "host", "member"), related_cols=("group",),
                         metrics={"changes": len(part)}, confidence="alta",
                         fp_notes=[tx("Puede corresponder a un cambio aprobado; verificar ticket/aprobación.",
                                     "It may be an approved change; check the ticket/approval.")])
        f.entities.setdefault("user", [])
        for m in f.entities.pop("member", []):
            if m not in f.entities["user"]:
                f.entities["user"].append(m)
        out.append(f)
    return out


def pe002(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    hits = df[(df["sem"] == "special_priv") & df["user"].notna()]
    hits = hits[~hits["user"].str.lower().isin(ctx.privileged_baseline) & ~hits["user"].map(ctx.is_ignored).astype(bool)
                & ~hits["user"].str.endswith("$")]
    out = []
    for (user,), part in clusters(hits, ["user"], pd.Timedelta(hours=24)):
        privs = uniq(part["privileges"])
        hosts = ", ".join(uniq(part["host"]))
        priv_txt = "; ".join(privs)[:300] or tx("no informados", "not reported")
        summary = tx(f"Se asignaron privilegios especiales (4672) a «{user}», cuenta que no figura como privilegiada en "
                     f"la configuración ni recibió privilegios especiales durante el período base. Hosts: "
                     f"{hosts}. Privilegios: {priv_txt}.",
                     f"Special privileges (4672) were assigned to “{user}”, an account that is not configured as "
                     f"privileged and did not receive special privileges during the baseline period. Hosts: "
                     f"{hosts}. Privileges: {priv_txt}.")
        title = tx(f"Privilegios especiales a cuenta no administrativa: «{user}»",
                   f"Special privileges to non-admin account: “{user}”")
        out.append(make_finding("PE-002", part, title, summary,
                                ctx, entity_cols=("user", "host"), metrics={"events": len(part)}, confidence="media",
                                fp_notes=[tx("Una cuenta recién designada como administradora genera este evento "
                                             "legítimamente.",
                                             "An account newly designated as administrator legitimately produces "
                                             "this event.")]))
    return out


def pe003(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    hits = df[df["sem"].isin(["account_created", "account_changed"])].copy()
    hits["subject"] = hits["target_user"].fillna(hits["user"])
    out = []
    for (subject,), part in clusters(hits, ["subject"], pd.Timedelta(hours=24)):
        kinds_es = ", ".join(sorted({"creación" if s == "account_created" else "modificación" for s in part["sem"]}))
        kinds_en = " and ".join(sorted({"creation" if s == "account_created" else "change" for s in part["sem"]}))
        who = ", ".join(uniq(part["user"])) or _unknown("actor no informado", "unreported actor")
        hosts = ", ".join(uniq(part["host"]))
        when = f"{part['ts'].min():%d/%m %H:%M}"
        summary = tx(f"{kinds_es.capitalize()} de la cuenta «{subject}» registrada por {who} en {hosts} ({when}).",
                     f"Account “{subject}” {kinds_en} recorded by {who} on {hosts} ({when}).")
        f = make_finding("PE-003", part, tx(f"Creación/cambio de cuenta: «{subject}»", f"Account created/changed: “{subject}”"),
                         summary, ctx,
                         entity_cols=("user", "host"), metrics={"events": len(part)}, confidence="baja",
                         fp_notes=[tx("Las altas y cambios de cuentas suelen ser tareas rutinarias de IT; validar contra "
                                      "el proceso de alta de empleados.",
                                      "Account creation and changes are usually routine IT tasks; validate against "
                                      "the employee onboarding process.")])
        f.related["subject"] = [subject]
        out.append(f)
    return out


def pe004(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    pat = re.compile(r"\brunas(\.exe)?\s+/(user|u):|\bsudo\s+(-[a-z]+\s+)*(su|bash|sh|-i|-s)\b|\bsu\s+-\s*$|"
                     r"\bsudo\s+.*(passwd|visudo|chmod\s+[0-7]*s|/etc/shadow)", re.IGNORECASE)
    mask = ctx.cmd_text.str.contains(pat) | (df["sem"] == "explicit_creds")
    hits = df[mask]
    out = []
    for (host,), part in clusters(hits, ["host"], HOUR):
        users = ", ".join(uniq(part["user"]))
        summary = tx(f"Uso de credenciales alternativas (runas/sudo o evento 4648) en {host}: {len(part)} evento(s) "
                     f"por {users}.",
                     f"Use of alternate credentials (runas/sudo or event 4648) on {host}: {len(part)} event(s) "
                     f"by {users}.")
        out.append(make_finding("PE-004", part, tx(f"Uso anómalo de runas/sudo en {host}", f"Anomalous runas/sudo on {host}"),
                                summary, ctx,
                                metrics={"events": len(part)}, confidence="media",
                                fp_notes=[tx("Los administradores usan runas/sudo legítimamente.",
                                             "Administrators use runas/sudo legitimately.")]))
    return out


# ------------------------------------------------------------------------ comandos y procesos
def _decode_ps(cmd: str) -> str | None:
    m = re.search(r"-e(?:nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{16,})", cmd, re.IGNORECASE)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le", "ignore")
    except Exception:
        return None


def _pattern_rule(rule_id: str, patterns: list[tuple[str, Text]], title: Text, sem_values=(), service_pat=None,
                  confidence="alta", fp: Text = "", process_only=False):
    compiled = [(re.compile(rx, re.IGNORECASE), label) for rx, label in patterns]

    def fn(ctx: Context, p: dict) -> list[Finding]:
        df = ctx.df
        text = df["process"].fillna("").str.lower() if process_only and ctx.has("process") else ctx.cmd_text
        mask = pd.Series(False, index=df.index)
        labels: dict[int, list[str]] = {}
        for rx, label in compiled:
            m = text.str.contains(rx)
            for i in df.index[m]:
                labels.setdefault(i, []).append(_t(label))
            mask |= m
        if sem_values:
            m = df["sem"].isin(sem_values)
            for i in df.index[m]:
                labels.setdefault(i, []).append(tx("evento ", "event ") + f"{df.at[i, 'event_id'] or df.at[i, 'sem']}")
            mask |= m
        if service_pat is not None:
            m = df["service"].fillna("").str.contains(service_pat, case=False, regex=True)
            for i in df.index[m]:
                labels.setdefault(i, []).append(tx("servicio ", "service ") + f"{df.at[i, 'service']}")
            mask |= m
        hits = df[mask]
        out = []
        for (host,), part in clusters(hits, ["host"], HOUR):
            found = uniq(l for i in part.index for l in labels.get(i, []))
            cmds = uniq(part["command_line"])[:5]
            details = [f"{r.row_id}: {str(r.command_line or r.message or r.process)[:400]}" for r in part.itertuples()][:10]
            if rule_id == "EX-001":
                for r in part.itertuples():
                    dec = _decode_ps(str(r.command_line or ""))
                    if dec:
                        details.append(f"{r.row_id} " + tx("(decodificado Base64/UTF-16LE)", "(Base64/UTF-16LE decoded)")
                                       + f": {dec[:400]}")
            host_txt = host if isinstance(host, str) else tx("host no informado", "unreported host")
            who = ", ".join(uniq(part["user"])) or tx("usuario no informado", "unreported user")
            example = (cmds[0] if cmds else part.iloc[0]["message"] or "")[:180]
            summary = tx(f"{len(part)} evento(s) en {host_txt} por {who} coinciden con: {', '.join(found)}. "
                         f"Ejemplo: «{example}».",
                         f"{len(part)} event(s) on {host_txt} by {who} match: {', '.join(found)}. "
                         f"Example: “{example}”.")
            out.append(make_finding(rule_id, part, f"{_t(title)} " + tx("en", "on") + f" {host_txt}", summary, ctx,
                                    entity_cols=("user", "host", "hash"), related_cols=("process",),
                                    metrics={"events": len(part)}, confidence=confidence, details=details,
                                    fp_notes=[_t(fp)] if fp else []))
        return out

    return fn


EX001 = _pattern_rule("EX-001", [
    (r"(powershell|pwsh)[^\n]*\s-e(nc|ncodedcommand|c)?\s+[a-z0-9+/=]{16,}", ("PowerShell con comando codificado", "PowerShell with encoded command")),
    # el flag -EncodedCommand ya es indicador aunque el SIEM haya ocultado el payload ([REDACTED], <base64>)
    (r"(powershell|pwsh)[^\n]*\s-(enc|encodedcommand|ec)\s+\S+", ("PowerShell con -EncodedCommand", "PowerShell with -EncodedCommand")),
    (r"(powershell|pwsh)[^\n]*-w(indowstyle)?\s+hidden", ("PowerShell con ventana oculta", "PowerShell with hidden window")),
    (r"frombase64string", ("decodificación Base64 en línea", "inline Base64 decoding")),
    (r"\b(iex|invoke-expression)\b", "Invoke-Expression"),
], ("PowerShell codificado/oculto", "Encoded/hidden PowerShell"),
    fp=("Algunos agentes de gestión usan -EncodedCommand; validar el contenido decodificado.",
        "Some management agents use -EncodedCommand; validate the decoded content."))

EX002 = _pattern_rule("EX-002", [
    (r"certutil(\.exe)?\s+.*-(urlcache|verifyctl)", "certutil -urlcache"),
    (r"bitsadmin(\.exe)?\s+.*/transfer", "bitsadmin /transfer"),
    (r"start-bitstransfer", "Start-BitsTransfer"),
    (r"(invoke-webrequest|\biwr\b|downloadstring|downloadfile|net\.webclient)", ("descarga desde PowerShell", "download from PowerShell")),
    (r"\b(curl|wget)(\.exe)?\s+[^\n]*(\s-o\s|\s-O\b|--output|\s-T\s|--upload-file)", ("curl/wget con escritura/subida de archivo", "curl/wget writing/uploading a file")),
], ("Descarga/transferencia con utilidades del sistema", "Download/transfer with system utilities"),
    fp=("Scripts de despliegue legítimos pueden descargar instaladores; revisar el dominio de destino.",
        "Legitimate deployment scripts may download installers; review the destination domain."))

EX003 = _pattern_rule("EX-003", [
    (r"rundll32(\.exe)?\s+[^\n]*(comsvcs|javascript:|url\.dll|\\users\\public\\|\\temp\\|\\appdata\\)", ("rundll32 con argumentos sospechosos", "rundll32 with suspicious arguments")),
    (r"regsvr32(\.exe)?\s+[^\n]*(/i:http|scrobj)", "regsvr32 (Squiblydoo)"),
    (r"mshta(\.exe)?\s+[^\n]*(http|javascript|vbscript)", ("mshta remoto", "remote mshta")),
    (r"wmic(\.exe)?\s+[^\n]*(process\s+call\s+create|/node:)", ("WMIC ejecución de procesos", "WMIC process execution")),
    (r"certutil(\.exe)?\s+[^\n]*-decode", "certutil -decode"),
    (r"(msbuild|installutil|regasm|regsvcs)(\.exe)?\s+[^\n]*\\(users|temp|programdata)\\", ("proxy de ejecución .NET", ".NET execution proxy")),
], ("Uso de LOLBins para ejecución por proxy", "LOLBins used for proxy execution"),
    fp=("Herramientas de administración legítimas pueden invocar WMIC; validar contexto.",
        "Legitimate admin tools may invoke WMIC; validate the context."))

EX004 = _pattern_rule("EX-004", [
    (r"\\users\\public\\[^\\\s\"]+\.(exe|dll|scr|bat|ps1|vbs)", ("ejecutable en C:\\Users\\Public", "executable in C:\\Users\\Public")),
    # binarios en la raíz de ProgramData (el software legítimo usa subcarpetas propias)
    (r"\\programdata\\[^\\\s\";]+\.(exe|dll|scr|bat|ps1|vbs)", ("ejecutable en la raíz de C:\\ProgramData", "executable in the root of C:\\ProgramData")),
    (r"\\appdata\\local\\temp\\[^\\\s\"]+\.(exe|dll|scr|bat|ps1|vbs)", ("ejecutable en %TEMP%", "executable in %TEMP%")),
    (r"\\windows\\temp\\[^\\\s\"]+\.(exe|dll|scr|bat|ps1)", ("ejecutable en C:\\Windows\\Temp", "executable in C:\\Windows\\Temp")),
    (r"\\downloads\\[^\\\s\"]+\.(scr|bat|vbs|js|hta)", ("script en Descargas", "script in Downloads")),
    (r"(^|\s)/(tmp|dev/shm|var/tmp)/\S+", ("binario en /tmp", "binary in /tmp")),
], ("Ejecución desde ruta temporal/pública", "Execution from temp/public path"), process_only=True,
    fp=("Algunos instaladores se ejecutan desde %TEMP%; verificar hash y firma.",
        "Some installers run from %TEMP%; verify hash and signature."))

EX005 = _pattern_rule("EX-005", [
    (r"mimikatz|sekurlsa|lsadump|kerberos::|privilege::debug", "Mimikatz"),
    (r"comsvcs(\.dll)?[,\s]+.*minidump", ("MiniDump vía comsvcs.dll", "MiniDump via comsvcs.dll")),
    (r"procdump(64)?(\.exe)?\s+[^\n]*lsass", ("procdump sobre lsass", "procdump on lsass")),
    (r"lsass\.dmp", ("volcado de lsass", "lsass dump")),
    (r"ntdsutil[^\n]*(ifm|create\s+full)", "ntdsutil IFM (NTDS.dit)"),
    (r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)", ("volcado de colmenas SAM/SECURITY", "SAM/SECURITY hive dump")),
    (r"vssadmin[^\n]*create\s+shadow", ("copia de sombra (NTDS/SAM)", "shadow copy (NTDS/SAM)")),
], ("Volcado de credenciales", "Credential dumping"))

EX006 = _pattern_rule("EX-006", [
    (r"set-mppreference[^\n]*-disable", "Set-MpPreference -Disable*"),
    (r"add-mppreference[^\n]*-exclusion", ("exclusión de Defender", "Defender exclusion")),
    (r"\bsc(\.exe)?\s+(stop|config|delete)\s+(windefend|sense|wdboot|wdfilter)", ("detención de Defender", "Defender stopped")),
    (r"netsh[^\n]*advfirewall[^\n]*state\s+off", ("firewall deshabilitado", "firewall disabled")),
    (r"auditpol[^\n]*/(clear|remove)", ("auditoría deshabilitada", "auditing disabled")),
    (r"uninstall-windowsfeature[^\n]*defender", ("desinstalación de Defender", "Defender uninstalled")),
], ("Desactivación de defensas", "Defense impairment"))

EX007 = _pattern_rule("EX-007", [
    (r"wevtutil(\.exe)?\s+(cl|clear-log)\b", "wevtutil cl"),
    (r"clear-eventlog|remove-eventlog", "Clear-EventLog"),
    (r"\b(rm|shred)\s+[^\n]*/var/log/", ("borrado de /var/log", "/var/log deletion")),
], ("Borrado de registros", "Log clearing"), sem_values=("log_cleared",))

EX008 = _pattern_rule("EX-008", [
    (r"schtasks(\.exe)?\s+[^\n]*/create", ("tarea programada creada", "scheduled task created")),
    (r"reg(\.exe)?\s+add\s+[^\n]*\\currentversion\\run", ("clave Run", "Run key")),
    (r"new-service|\bsc(\.exe)?\s+create\b", ("servicio nuevo", "new service")),
    (r"new-scheduledtask|register-scheduledtask", "Register-ScheduledTask"),
], ("Mecanismo de persistencia", "Persistence mechanism"), sem_values=("service_installed", "task_created"),
    fp=("Software legítimo instala servicios y tareas; contrastar con el inventario.",
        "Legitimate software installs services and tasks; cross-check with the inventory."))

EX009 = _pattern_rule("EX-009", [
    (r"\b(7z|7za|rar|winrar)(\.exe)?\s+a\b[^\n]*(-p|\\users\\public|\\temp\\)", ("compresión con contraseña/ruta pública", "password/public-path archive")),
    (r"\btar(\.exe)?\s+[^\n]*-[a-z]*c[a-z]*\s[^\n]*\\(temp|users\\public|programdata)\\", ("tar a ruta temporal/pública", "tar to temp/public path")),
    (r"compress-archive[^\n]*\\(users\\public|temp)", ("Compress-Archive a ruta pública", "Compress-Archive to public path")),
    (r"\b(curl|wget)(\.exe)?\s+[^\n]*(-T\s|--upload-file|-F\s+\S*@)", ("subida de archivo con curl", "file upload with curl")),
    (r"invoke-restmethod[^\n]*-infile", "Invoke-RestMethod -InFile"),
    (r"\brclone(\.exe)?\s+(copy|sync)", "rclone"),
    (r"\bmega(cmd|-put)", "MEGAcmd"),
], ("Compresión/exfiltración por línea de comando", "Command-line archiving/exfiltration"))


EX010 = _pattern_rule("EX-010", [
    (r"\bnet1?(\.exe)?\s+(view|group|localgroup|user|share|session|accounts)\b", "net view/group/user"),
    (r"\bwhoami(\.exe)?\b", "whoami"),
    (r"\bnltest(\.exe)?\b|\bdsquery\b|\badfind(\.exe)?\b", ("enumeración de dominio (nltest/dsquery/AdFind)", "domain enumeration (nltest/dsquery/AdFind)")),
    (r"get-localgroupmember|get-smbshare|get-aduser|get-adcomputer|get-adgroupmember|get-netsession",
     ("enumeración con PowerShell", "PowerShell enumeration")),
    (r"\bquser\b|\bquery\s+(user|session)\b", ("sesiones activas (quser)", "active sessions (quser)")),
], ("Reconocimiento del entorno", "Environment discovery"), confidence="media",
    fp=("Los administradores usan estos comandos a diario; cobran relevancia junto a otras fases del ataque.",
        "Administrators use these commands daily; they matter alongside other attack phases."))

EX011 = _pattern_rule("EX-011", [
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "vssadmin delete shadows"),
    (r"wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy[^\n]*(delete|remove)", ("borrado de shadow copies vía WMI", "shadow copy deletion via WMI")),
    (r"bcdedit[^\n]*recoveryenabled\s+no|bcdedit[^\n]*bootstatuspolicy\s+ignoreallfailures", ("recuperación de arranque deshabilitada", "boot recovery disabled")),
    (r"wbadmin[^\n]*delete\s+(catalog|systemstatebackup|backup)", ("borrado de backups (wbadmin)", "backup deletion (wbadmin)")),
], ("Eliminación de copias de recuperación", "Recovery copies deleted"))


# ------------------------------------------------------------------------ movimiento lateral
def lm001(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    oks = df[(df["sem"] == "auth_ok") & df["user"].notna() & df["host"].notna()]
    if ctx.has("logon_type"):
        oks = oks[oks["logon_type"].isin(ctx.remote_types)]
    oks = oks[~oks["user"].map(ctx.is_ignored).astype(bool)]
    window = pd.Timedelta(minutes=p["window_minutes"])
    k = int(p["min_distinct_hosts"])
    out = []
    for user, g in oks.groupby("user", sort=False):
        g = g.sort_values("ts")
        for a, b in distinct_bursts(g["ts"].values, list(g["host"]), window, k):
            part = g.iloc[a:b + 1]
            hosts = uniq(part["host"])
            span = f"{part['ts'].min():%d/%m %H:%M}–{part['ts'].max():%H:%M}"
            srcs = ", ".join(uniq(part["src_ip"])) or tx("origen no informado", "unreported source")
            summary = tx(f"La cuenta «{user}» se autenticó por red/RDP en {len(hosts)} hosts distintos ({', '.join(hosts)}) "
                         f"en menos de {p['window_minutes']} minutos ({span}), desde {srcs}.",
                         f"Account “{user}” authenticated over the network/RDP to {len(hosts)} distinct hosts "
                         f"({', '.join(hosts)}) within {p['window_minutes']} minutes ({span}), from {srcs}.")
            out.append(make_finding("LM-001", part, tx(f"Autenticación en {len(hosts)} hosts en poco tiempo: «{user}»",
                                                       f"Authentication to {len(hosts)} hosts in a short time: “{user}”"),
                                    summary, ctx, metrics={"distinct_hosts": len(hosts)}, auth_success=True,
                                    confidence="media",
                                    fp_notes=[tx("Cuentas de administración y escáneres de inventario acceden a muchos "
                                                 "hosts legítimamente.",
                                                 "Admin accounts and inventory scanners access many hosts legitimately.")]))
    return out


def lm002(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    oks = df[(df["sem"] == "auth_ok") & df["user"].notna() & df["host"].notna() & df["logon_type"].notna()]
    remote = oks[(oks["logon_type"] == "10") | ((oks["logon_type"] == "3") & oks["host"].map(ctx.is_critical).astype(bool))]
    if ctx.baseline_end is None:
        # sin línea base (archivo de pocas horas): se informa todo RDP / logon de red a host crítico
        seen: set = set()
        new = remote
    else:
        base = oks[~ctx.after_baseline(oks["ts"])]
        seen = set(zip(base["user"], base["host"], base["logon_type"]))
        new = remote[ctx.after_baseline(remote["ts"])]
    new = new[pd.Series([(u, h, t) not in seen for u, h, t in zip(new["user"], new["host"], new["logon_type"])],
                         index=new.index, dtype=bool)]
    new = new[~new["user"].map(ctx.is_ignored).astype(bool)]
    out = []
    for (user,), part in clusters(new, ["user"], pd.Timedelta(hours=2)):
        pairs = uniq(f"{h} (" + tx("tipo", "type") + f" {t})" for h, t in zip(part["host"], part["logon_type"]))
        srcs = ", ".join(uniq(part["src_ip"])) or tx("origen no informado", "unreported source")
        summary = tx(f"«{user}» realizó logons remotos (RDP o de red a hosts críticos) hacia {', '.join(pairs)} desde "
                     f"{srcs}"
                     + ("; esa combinación cuenta→host→tipo no se observó durante el período base." if ctx.baseline_end
                        is not None else "; el archivo no cubre días suficientes para una línea base, por lo que se "
                        "informan todos los logons remotos a hosts críticos."),
                     f"“{user}” made remote logons (RDP or network to critical hosts) to {', '.join(pairs)} from "
                     f"{srcs}"
                     + ("; that account→host→type combination was not seen during the baseline period." if ctx.baseline_end
                        is not None else "; the file does not cover enough days for a baseline, so all remote logons "
                        "to critical hosts are reported."))
        title = tx(f"Logon remoto nuevo: «{user}» → {', '.join(uniq(part['host']))}",
                   f"New remote logon: “{user}” → {', '.join(uniq(part['host']))}")
        out.append(make_finding("LM-002", part, title, summary,
                                ctx, metrics={"logons": len(part)}, auth_success=True, confidence="media",
                                fp_notes=[tx("Un acceso nuevo pero legítimo (soporte, nuevo rol) produce el mismo patrón.",
                                             "New but legitimate access (support, new role) produces the same pattern.")]))
    return out


LM003 = _pattern_rule("LM-003", [
    (r"\b(psexec|paexec)(64)?(\.exe)?\b", "PsExec/PAExec"),
    (r"psexesvc", ("servicio PSEXESVC", "PSEXESVC service")),
    (r"wmic(\.exe)?\s+[^\n]*/node:", ("WMIC remoto (/node)", "remote WMIC (/node)")),
    (r"invoke-command[^\n]*-computername|enter-pssession|new-pssession|\bwinrs(\.exe)?\b", "WinRM/PowerShell Remoting"),
    (r"invoke-wmimethod[^\n]*-computername|invoke-cimmethod[^\n]*-computername", ("WMI remoto (PowerShell)", "remote WMI (PowerShell)")),
], ("Herramientas de ejecución remota", "Remote execution tools"), service_pat=r"psexesvc|paexec|remcom",
    fp=("Equipos de IT usan PsExec/WinRM para soporte; validar con el área.",
        "IT teams use PsExec/WinRM for support; validate with them."))


def lm004(ctx: Context, p: dict) -> list[Finding]:
    df = ctx.df
    share_rx = r"\\(admin\$|[a-z]\$)(\\|$)|^(admin\$|[a-z]\$)$"
    m_share = df["share"].fillna("").str.contains(share_rx, case=False, regex=True)
    m_cmd = df["command_line"].fillna("").str.contains(r"\\\\[\w.-]+\\(admin\$|[a-z]\$)", case=False, regex=True)
    hits = df[m_share | m_cmd]
    out = []
    for (user,), part in clusters(hits, ["user"], HOUR):
        shares = uniq(part["share"]) or [tx("(en línea de comando)", "(in command line)")]
        hosts = ", ".join(uniq(part["host"]))
        srcs = ", ".join(uniq(part["src_ip"])) or tx("origen no informado", "unreported source")
        summary = tx(f"«{user}» accedió a recursos administrativos {', '.join(shares)} en {hosts} desde {srcs}.",
                     f"“{user}” accessed administrative shares {', '.join(shares)} on {hosts} from {srcs}.")
        out.append(make_finding("LM-004", part, tx(f"Acceso a admin shares: «{user}»", f"Admin share access: “{user}”"),
                                summary, ctx,
                                metrics={"events": len(part)}, confidence="media",
                                fp_notes=[tx("Herramientas de despliegue (SCCM, GPO) usan ADMIN$ legítimamente.",
                                             "Deployment tools (SCCM, GPO) use ADMIN$ legitimately.")]))
    return out


RULES = [
    Rule("PE-001", "Alta en grupo privilegiado", "Added to privileged group", "privesc", "privilege_escalation",
         [("T1098", "Account Manipulation"), ("T1078.002", "Valid Accounts: Domain Accounts")],
         "Una cuenta es agregada a un grupo privilegiado (Administrators, Domain Admins, …).",
         "An account is added to a privileged group.", ["timestamp", "group", "event_id|action"], pe001),
    Rule("PE-002", "Privilegios especiales a cuenta no admin", "Special privileges to non-admin", "privesc",
         "privilege_escalation", [("T1078.002", "Valid Accounts: Domain Accounts"), ("T1134", "Access Token Manipulation")],
         "Evento 4672 para una cuenta sin privilegios en la línea base ni en la configuración.",
         "Event 4672 for an account not privileged in the baseline/config.", ["timestamp", "user", "event_id"], pe002),
    Rule("PE-003", "Creación o cambio de cuenta", "Account created or changed", "privesc", "persistence",
         [("T1136.001", "Create Account: Local Account"), ("T1098", "Account Manipulation")],
         "Creación (4720) o modificación (4722/4724/4738) de cuentas.", "Account creation/modification events.",
         ["timestamp", "event_id"], pe003),
    Rule("PE-004", "runas / sudo anómalo", "Anomalous runas/sudo", "privesc", "privilege_escalation",
         [("T1548", "Abuse Elevation Control Mechanism"), ("T1134.002", "Create Process with Token")],
         "Uso de runas /user, sudo a shell o evento 4648 (credenciales explícitas).",
         "runas /user, sudo to shell or event 4648.", ["timestamp", "command_line|process|event_id"], pe004),
    Rule("EX-001", "PowerShell codificado u oculto", "Encoded/hidden PowerShell", "execution", "execution",
         [("T1059.001", "Command and Scripting Interpreter: PowerShell"), ("T1027", "Obfuscated Files or Information")],
         "PowerShell con -EncodedCommand, ventana oculta, FromBase64String o IEX.",
         "PowerShell with -EncodedCommand, hidden window, FromBase64String or IEX.",
         ["timestamp", "command_line"], EX001),
    Rule("EX-002", "Descarga con utilidades del sistema", "Download via system utilities", "execution",
         "command_and_control", [("T1105", "Ingress Tool Transfer")],
         "certutil -urlcache, bitsadmin, Invoke-WebRequest, curl/wget escribiendo o subiendo archivos.",
         "certutil, bitsadmin, IWR, curl/wget writing or uploading files.", ["timestamp", "command_line"], EX002),
    Rule("EX-003", "LOLBins (ejecución por proxy)", "LOLBins proxy execution", "execution", "defense_evasion",
         [("T1218", "System Binary Proxy Execution"), ("T1047", "Windows Management Instrumentation")],
         "rundll32/regsvr32/mshta/WMIC/certutil usados con argumentos típicos de abuso.",
         "rundll32/regsvr32/mshta/WMIC/certutil with abuse arguments.", ["timestamp", "command_line"], EX003),
    Rule("EX-004", "Ejecución desde rutas temporales", "Execution from temp paths", "execution", "execution",
         [("T1204.002", "User Execution: Malicious File"), ("T1036", "Masquerading")],
         "Binarios o scripts ejecutados desde C:\\Users\\Public, %TEMP%, C:\\Windows\\Temp o /tmp.",
         "Binaries/scripts executed from public/temp paths.", ["timestamp", "command_line|process"], EX004),
    Rule("EX-005", "Volcado de credenciales", "Credential dumping", "execution", "credential_access",
         [("T1003.001", "OS Credential Dumping: LSASS Memory"), ("T1003.003", "OS Credential Dumping: NTDS")],
         "Mimikatz, MiniDump de lsass, procdump, ntdsutil IFM, reg save de SAM/SECURITY.",
         "Mimikatz, lsass MiniDump, procdump, ntdsutil, reg save SAM.", ["timestamp", "command_line|process"], EX005),
    Rule("EX-006", "Desactivación de defensas", "Defense impairment", "execution", "defense_evasion",
         [("T1562.001", "Impair Defenses: Disable or Modify Tools")],
         "Deshabilitación de Defender, firewall o auditoría.", "Disabling Defender, firewall or auditing.",
         ["timestamp", "command_line"], EX006),
    Rule("EX-007", "Borrado de registros", "Log clearing", "execution", "defense_evasion",
         [("T1070.001", "Indicator Removal: Clear Windows Event Logs")],
         "wevtutil cl, Clear-EventLog o eventos 1102/104.", "wevtutil cl, Clear-EventLog or events 1102/104.",
         ["timestamp", "command_line|event_id"], EX007),
    Rule("EX-008", "Persistencia", "Persistence mechanism", "execution", "persistence",
         [("T1053.005", "Scheduled Task/Job: Scheduled Task"), ("T1543.003", "Create or Modify System Process: Windows Service")],
         "Tareas programadas, servicios nuevos (7045/4697) o claves Run.", "Scheduled tasks, new services or Run keys.",
         ["timestamp", "command_line|event_id"], EX008),
    Rule("EX-009", "Compresión/exfiltración", "Archive/exfiltration", "collection", "exfiltration",
         [("T1560.001", "Archive Collected Data: Archive via Utility"), ("T1048", "Exfiltration Over Alternative Protocol")],
         "Compresión con contraseña o en rutas públicas y subida de archivos (curl -T, rclone…).",
         "Password-protected archives and file uploads.", ["timestamp", "command_line"], EX009),
    Rule("EX-010", "Reconocimiento del entorno", "Discovery", "execution", "discovery",
         [("T1087", "Account Discovery"), ("T1069", "Permission Groups Discovery"),
          ("T1135", "Network Share Discovery"), ("T1033", "System Owner/User Discovery")],
         "Comandos de enumeración: net view/group/user, whoami, nltest, Get-LocalGroupMember, Get-SmbShare.",
         "Enumeration commands: net, whoami, nltest, Get-LocalGroupMember, Get-SmbShare.",
         ["timestamp", "command_line|message"], EX010),
    Rule("EX-011", "Eliminación de copias de recuperación", "Inhibit system recovery", "execution", "impact",
         [("T1490", "Inhibit System Recovery")],
         "Borrado de shadow copies (vssadmin, WMI), backups (wbadmin) o desactivación de la recuperación (bcdedit).",
         "Deleting shadow copies/backups or disabling recovery; typical ransomware precursor.",
         ["timestamp", "command_line|message"], EX011),
    Rule("LM-001", "Autenticación en múltiples hosts", "Authentication to many hosts", "lateral", "lateral_movement",
         [("T1021", "Remote Services")],
         "Misma cuenta autenticando por red/RDP en ≥ K hosts distintos dentro de una ventana corta.",
         "Same account authenticating to ≥K hosts in a short window.",
         ["timestamp", "user", "host", "auth", "logon_type"], lm001),
    Rule("LM-002", "Logon remoto nuevo (RDP/red a crítico)", "New remote logon", "lateral", "lateral_movement",
         [("T1021.001", "Remote Services: Remote Desktop Protocol")],
         "RDP (tipo 10) o logon de red a host crítico en una combinación cuenta→host no vista en el período base.",
         "RDP or network logon to a critical host in an account→host pair unseen in the baseline.",
         ["timestamp", "user", "host", "logon_type", "auth"], lm002),
    Rule("LM-003", "PsExec / WMI / WinRM remoto", "PsExec/WMI/WinRM remote execution", "lateral", "lateral_movement",
         [("T1569.002", "System Services: Service Execution"), ("T1047", "Windows Management Instrumentation"),
          ("T1021.006", "Remote Services: Windows Remote Management")],
         "PsExec/PSEXESVC, WMIC /node, Invoke-Command/Enter-PSSession, winrs.",
         "PsExec/PSEXESVC, WMIC /node, PowerShell Remoting, winrs.", ["timestamp", "command_line|service"], LM003),
    Rule("LM-004", "Acceso a admin shares", "Admin share access", "lateral", "lateral_movement",
         [("T1021.002", "Remote Services: SMB/Windows Admin Shares")],
         "Acceso a ADMIN$ o C$ (eventos 5140/5145 o rutas \\\\host\\C$ en comandos).",
         "Access to ADMIN$/C$ shares.", ["timestamp", "share|command_line"], lm004),
]
