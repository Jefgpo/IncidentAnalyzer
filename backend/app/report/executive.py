"""Informe EJECUTIVO: lenguaje de negocio, sin jerga técnica.

Pensado para la dirección: qué pasó, qué tan grave es, qué puede afectar al negocio y qué
decisiones hay que tomar. Todo se deriva de los incidentes del motor (no inventa hechos);
el detalle técnico y la evidencia quedan en el informe técnico. Se genera en español o inglés.
"""
from __future__ import annotations

from datetime import datetime

import pandas as pd

from app.lang import current, tx, using
from app.report.builder import _Ids, _fmt, _list, _p, _table

# Fases del ataque explicadas sin tecnicismos (en el orden en que ocurrieron)
PLAIN_PHASE = {
    "credential_access": ("intentó adivinar o robar contraseñas", "tried to guess or steal passwords"),
    "initial_access": ("logró entrar usando una cuenta válida de la empresa", "got in using a valid company account"),
    "execution": ("ejecutó programas propios en equipos de la empresa", "ran its own programs on company computers"),
    "persistence": ("dejó instalado un acceso oculto para poder volver a entrar",
                    "left a hidden way in so it could come back"),
    "privilege_escalation": ("obtuvo permisos de administrador", "obtained administrator permissions"),
    "defense_evasion": ("intentó desactivar protecciones o borrar sus rastros",
                        "tried to switch off protections or erase its tracks"),
    "discovery": ("exploró la red para conocer usuarios, permisos y carpetas compartidas",
                  "explored the network to learn about users, permissions and shared folders"),
    "lateral_movement": ("se desplazó desde el primer equipo hacia otros servidores",
                         "moved from the first computer to other servers"),
    "collection": ("reunió archivos de la empresa", "gathered company files"),
    "command_and_control": ("se comunicó con servidores externos que controla",
                            "communicated with external servers it controls"),
    "exfiltration": ("envió información de la empresa hacia afuera", "sent company information outside"),
    "impact": ("borró las copias de recuperación de los equipos, un paso típico antes de un secuestro de datos (ransomware)",
               "deleted the computers' recovery copies, a typical step before data is held hostage (ransomware)"),
}
WEB_ENTRY = ("aprovechó una debilidad de una aplicación web publicada en Internet para dar órdenes al servidor",
             "exploited a weakness in a web application published on the Internet to give orders to the server")

# Niveles: (color, acción) en español e inglés. Las claves son los valores internos de criticidad.
URGENCY = {
    "Crítico": (("Rojo", "Actuar de inmediato (hoy)"), ("Red", "Act immediately (today)")),
    "Alto": (("Naranja", "Actuar en las próximas 24–48 horas"), ("Orange", "Act within the next 24–48 hours")),
    "Medio": (("Amarillo", "Planificar acciones esta semana"), ("Yellow", "Plan actions this week")),
    "Bajo": (("Verde", "Revisar en la operación habitual"), ("Green", "Review in normal operations")),
}
LEVEL_EN = {"Crítico": "critical", "Alto": "high", "Medio": "medium", "Bajo": "low"}

GLOSSARY = {
    "es": {
        "ransomware": "Programa malicioso que cifra (bloquea) los archivos de la empresa y pide un rescate para devolverlos.",
        "contraseña": "Ataques de contraseña: el atacante prueba muchas contraseñas hasta acertar una.",
        "MFA": "Verificación en dos pasos (MFA): además de la contraseña se pide un código del celular; frena la mayoría de los robos de cuentas.",
        "web shell": "Puerta trasera en un sitio web: un archivo malicioso que permite al atacante dar órdenes al servidor desde Internet.",
        "exfiltración": "Exfiltración: envío no autorizado de información de la empresa hacia afuera.",
        "copias": "Copias de recuperación (respaldos): versiones guardadas de los archivos que permiten restaurarlos tras un incidente.",
        "administrador": "Permisos de administrador: el nivel de acceso más alto, permite controlar equipos y cuentas.",
    },
    "en": {
        "ransomware": "Ransomware: malicious software that encrypts (locks) the company's files and demands a ransom to return them.",
        "password": "Password attacks: the attacker tries many passwords until one works.",
        "MFA": "Two-step verification (MFA): besides the password, a code from the phone is required; it stops most account takeovers.",
        "web shell": "Web shell: a back door on a website, a malicious file that lets the attacker give orders to the server from the Internet.",
        "exfiltration": "Exfiltration: unauthorized sending of company information outside.",
        "recovery copies": "Recovery copies (backups): saved versions of the files that allow restoring them after an incident.",
        "administrator": "Administrator permissions: the highest access level, allowing control over computers and accounts.",
    },
}


def _color(sev: str) -> str:
    return URGENCY[sev][1 if current() == "en" else 0][0]


def _action(sev: str) -> str:
    return URGENCY[sev][1 if current() == "en" else 0][1]


def _level(sev: str) -> str:
    """Nivel en minúsculas para el texto corrido («nivel alto» / «high level»)."""
    return LEVEL_EN[sev] if current() == "en" else sev.lower()


def _risk(level: str) -> str:
    """Valor de la columna «Nivel de riesgo» de la matriz de impacto."""
    return tx(level, {"Alto": "High", "Medio": "Medium", "Bajo": "Low"}[level])


def host_role(host: str) -> str:
    h = host.upper()
    if h.startswith("DC"):
        return tx(f"el controlador de dominio {host} (gestiona usuarios y contraseñas de toda la red)",
                  f"the domain controller {host} (manages users and passwords for the whole network)")
    if h.startswith("FS") or "FILE" in h:
        return tx(f"el servidor de archivos {host}", f"the file server {host}")
    if h.startswith(("DB", "SQL")) or "SQL" in h:
        return tx(f"el servidor de base de datos {host}", f"the database server {host}")
    if h.startswith("WEB"):
        return tx(f"el servidor web {host} (expuesto a Internet)", f"the web server {host} (exposed to the Internet)")
    if h.startswith("APP"):
        return tx(f"el servidor de aplicaciones {host}", f"the application server {host}")
    if h.startswith(("WS", "PC", "NB", "LT")):
        return tx(f"la computadora de un empleado ({host})", f"an employee's computer ({host})")
    if "SRV" in h:
        return tx(f"el servidor {host}", f"the server {host}")
    return tx(f"el equipo {host}", f"the computer {host}")


def account_label(user: str) -> str:
    """Nombre de cuenta entendible para negocio."""
    u = user.lower()
    if "apppool" in u or u.startswith(("iusr", "www-data", "apache", "nginx")):
        return tx("la cuenta de servicio del sitio web", "the website's service account")
    if u.startswith("svc") or u.endswith("svc") or u.endswith("$"):
        return tx(f"la cuenta de servicio «{user}» (usada por un sistema, no por una persona)",
                  f"the service account “{user}” (used by a system, not a person)")
    if "admin" in u:
        return tx(f"la cuenta de administración «{user}»", f"the administration account “{user}”")
    return tx(f"la cuenta del usuario «{user}»", f"the account of user “{user}”")


def plain_steps(inc: dict, findings: list[dict]) -> list[str]:
    web = any(f["category"] == "web" for f in findings)
    steps = []
    if web:
        steps.append(tx(*WEB_ENTRY))
    for p in inc["phases"]:
        if web and p["tactic"] == "initial_access":
            continue
        if p["tactic"] in PLAIN_PHASE:
            steps.append(tx(*PLAIN_PHASE[p["tactic"]]))
    return steps


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + tx(" y ", " and ") + items[-1]


def business_title(inc: dict, findings: list[dict]) -> str:
    tactics = {p["tactic"] for p in inc["phases"]}
    cats = {f["category"] for f in findings}
    rules = {f["rule_id"] for f in findings}
    if "impact" in tactics:
        return tx("Posible preparación de un secuestro de datos (ransomware)", "Possible preparation of a ransomware attack")
    if "web" in cats:
        return tx("Intrusión a través de una aplicación web publicada en Internet",
                  "Intrusion through a web application published on the Internet")
    if "exfiltration" in tactics and "lateral_movement" not in tactics:
        return tx("Posible robo de información de la empresa", "Possible theft of company information")
    if "lateral_movement" in tactics and ({"privilege_escalation", "execution"} & tactics):
        return tx("Acceso no autorizado a servidores internos con una cuenta de la empresa",
                  "Unauthorized access to internal servers with a company account")
    if "BF-002" in rules or "BF-003" in rules:
        ok = any(f.get("auth_success") for f in findings)
        return (tx("Robo de la contraseña de una cuenta de la empresa", "Password theft of a company account") if ok else
                tx("Intentos de adivinar contraseñas (sin acceso confirmado)", "Password-guessing attempts (no confirmed access)"))
    if "persistence" in tactics:
        return tx("Instalación de un acceso oculto en un servidor", "Hidden access installed on a server")
    if "LOG-003" in rules:
        return tx("Uso indebido de una cuenta de sistema y ataques de contraseña contra un servidor",
                  "Misuse of a system account and password attacks against a server")
    if "BF-001" in rules:
        return tx("Intentos de adivinar contraseñas contra cuentas de la empresa",
                  "Password-guessing attempts against company accounts")
    return tx("Actividad sospechosa en cuentas o equipos de la empresa", "Suspicious activity on company accounts or computers")


def _when(inc: dict) -> str:
    a, b = pd.Timestamp(inc["start"]), pd.Timestamp(inc["end"])
    if a.date() == b.date():
        return tx(f"el {a:%d/%m/%Y} entre las {a:%H:%M} y las {b:%H:%M}", f"on {a:%d/%m/%Y} between {a:%H:%M} and {b:%H:%M}")
    return tx(f"entre el {a:%d/%m/%Y %H:%M} y el {b:%d/%m/%Y %H:%M}", f"between {a:%d/%m/%Y %H:%M} and {b:%d/%m/%Y %H:%M}")


def impact_matrix(incidents: list[dict], by_id: dict) -> list[list[str]]:
    tactics = {p["tactic"] for i in incidents for p in i["phases"]}
    cats = {by_id[f]["category"] for i in incidents for f in i["finding_ids"]}
    success = any(by_id[f].get("auth_success") for i in incidents for f in i["finding_ids"])
    worst = min((i["severity"] for i in incidents), key=["Crítico", "Alto", "Medio", "Bajo"].index, default="Bajo")
    rows = []

    def row(area, level, why):
        rows.append([tx(*area), _risk(level), tx(*why)])

    info = ("Información de la empresa", "Company information")
    if {"exfiltration", "collection"} & tactics:
        row(info, "Alto", ("Hay registros de archivos reunidos y/o enviados hacia afuera.",
                           "There are records of files gathered and/or sent outside."))
    elif success or "initial_access" in tactics:
        row(info, "Medio", ("Un atacante tuvo acceso a cuentas internas; no se observó envío de datos.",
                            "An attacker had access to internal accounts; no data sending was observed."))
    else:
        row(info, "Bajo", ("No se observó acceso a información.", "No access to information was observed."))
    ops = ("Continuidad de la operación", "Business continuity")
    if "impact" in tactics:
        row(ops, "Alto", ("Se borraron copias de recuperación: un cifrado posterior podría detener la operación.",
                          "Recovery copies were deleted: a later encryption could stop operations."))
    elif {"persistence", "privilege_escalation", "defense_evasion"} & tactics:
        row(ops, "Medio", ("El atacante obtuvo control o dejó accesos ocultos que podrían usarse para dañar sistemas.",
                           "The attacker gained control or left hidden access that could be used to damage systems."))
    else:
        row(ops, "Bajo", ("No se observaron acciones que afecten la operación.", "No actions affecting operations were observed."))
    accounts = ("Cuentas y permisos", "Accounts and permissions")
    if "privilege_escalation" in tactics or (success and "lateral_movement" in tactics):
        row(accounts, "Alto", ("Cuentas de la empresa fueron usadas por terceros, incluso con permisos elevados.",
                               "Company accounts were used by third parties, even with elevated permissions."))
    elif success or "credential_access" in tactics:
        row(accounts, "Medio", ("Hubo intentos de robo de contraseñas" + (" y al menos una cuenta fue comprometida." if success else "."),
                                "There were password theft attempts" + (" and at least one account was compromised." if success else ".")))
    else:
        row(accounts, "Bajo", ("Sin evidencia de cuentas comprometidas.", "No evidence of compromised accounts."))
    legal = ("Cumplimiento legal", "Legal compliance")
    if "exfiltration" in tactics:
        row(legal, "Alto", ("Si los datos enviados incluyen datos personales, puede existir obligación de notificar "
                            "(Ley 25.326 de Protección de Datos Personales en Argentina, o la norma que aplique). Debe evaluarlo el área legal.",
                            "If the data sent includes personal data, there may be a duty to notify (e.g. GDPR or the "
                            "applicable data protection law). The legal team must assess it."))
    elif "collection" in tactics:
        row(legal, "Medio", ("Hubo acceso masivo a archivos; el área legal debe evaluar si incluían datos personales.",
                             "There was mass access to files; the legal team must assess whether they included personal data."))
    else:
        row(legal, "Bajo", ("Sin evidencia de exposición de datos personales.", "No evidence of personal data exposure."))
    rep = ("Reputación", "Reputation")
    if "exfiltration" in tactics or "web" in cats:
        row(rep, "Alto", ("Una fuga de información o un sitio web comprometido pueden afectar la confianza de clientes.",
                          "An information leak or a compromised website can affect customer trust."))
    elif worst in ("Crítico", "Alto"):
        row(rep, "Medio", ("El incidente no es visible desde afuera, pero su escalada podría serlo.",
                           "The incident is not visible from outside, but its escalation could be."))
    else:
        row(rep, "Bajo", ("Sin impacto visible hacia clientes.", "No impact visible to customers."))
    return rows


def recommendations(incidents: list[dict], by_id: dict) -> dict[str, list[str]]:
    tactics = {p["tactic"] for i in incidents for p in i["phases"]}
    cats = {by_id[f]["category"] for i in incidents for f in i["finding_ids"]}
    users = sorted({u for i in incidents for u in i["entities"]["user"]})
    hosts = sorted({h for i in incidents for h in i["entities"]["host"]})
    now, soon, later = [], [], []
    now.append(tx("Activar al equipo de respuesta a incidentes y conservar los registros y equipos afectados sin modificarlos (son evidencia).",
                  "Activate the incident response team and preserve the affected logs and computers unchanged (they are evidence)."))
    if users:
        more = tx(" y otras", " and others") if len(users) > 6 else ""
        now.append(tx(f"Cambiar las contraseñas de las cuentas involucradas ({_join(users[:6])}{more}) y cerrar todas sus sesiones abiertas.",
                      f"Change the passwords of the accounts involved ({_join(users[:6])}{more}) and close all their open sessions."))
    if hosts:
        more = tx(" y otros", " and others") if len(hosts) > 6 else ""
        now.append(tx(f"Aislar de la red, hasta revisarlos, los equipos comprometidos ({_join(hosts[:6])}{more}).",
                      f"Isolate the compromised computers from the network until they are reviewed ({_join(hosts[:6])}{more})."))
    if "impact" in tactics:
        now.append(tx("Verificar hoy que existan copias de seguridad fuera de línea y que puedan restaurarse.",
                      "Verify today that offline backups exist and can be restored."))
    if "exfiltration" in tactics or "command_and_control" in tactics:
        now.append(tx("Bloquear las direcciones de Internet a las que se enviaron datos o con las que se comunicó el atacante.",
                      "Block the Internet addresses data was sent to or the attacker communicated with."))
    if "web" in cats:
        now.append(tx("Retirar el archivo malicioso de la aplicación web o sacarla de línea hasta corregir la vulnerabilidad.",
                      "Remove the malicious file from the web application or take it offline until the vulnerability is fixed."))
    soon.append(tx("Exigir verificación en dos pasos (MFA) para el acceso remoto, el correo y las cuentas con permisos de administrador.",
                   "Require two-step verification (MFA) for remote access, email and accounts with administrator permissions."))
    if "privilege_escalation" in tactics or "lateral_movement" in tactics:
        soon.append(tx("Revisar quién tiene permisos de administrador y quitar los que no sean imprescindibles.",
                       "Review who has administrator permissions and remove those that are not essential."))
    if "web" in cats:
        soon.append(tx("Corregir y actualizar la aplicación web afectada y revisar el resto de los sitios publicados.",
                       "Fix and update the affected web application and review the rest of the published sites."))
    soon.append(tx("Encargar un análisis forense de los equipos comprometidos para confirmar el alcance real (qué datos se vieron afectados).",
                   "Commission a forensic analysis of the compromised computers to confirm the real scope (which data was affected)."))
    soon.append(tx("Asegurar un monitoreo continuo de alertas de seguridad (24×7) para detectar estos patrones a tiempo.",
                   "Ensure continuous monitoring of security alerts (24×7) to detect these patterns in time."))
    later.append(tx("Formalizar un plan de respuesta a incidentes con roles, contactos y criterios de comunicación.",
                    "Formalize an incident response plan with roles, contacts and communication criteria."))
    later.append(tx("Probar periódicamente la restauración de copias de seguridad y mantener una copia aislada de la red.",
                    "Test backup restoration regularly and keep a copy isolated from the network."))
    later.append(tx("Capacitar al personal en contraseñas seguras y en la detección de engaños (phishing).",
                    "Train staff on strong passwords and on spotting scams (phishing)."))
    later.append(tx("Separar la red en zonas para que un equipo comprometido no pueda llegar a los servidores críticos.",
                    "Split the network into zones so a compromised computer cannot reach critical servers."))
    decisions = [tx("Autorizar el aislamiento temporal de los equipos y servicios afectados, aunque implique interrupciones.",
                    "Authorize the temporary isolation of the affected computers and services, even if it causes interruptions.")]
    if {"exfiltration", "collection"} & tactics:
        decisions.append(tx("Evaluar con el área legal si corresponde notificar a la autoridad de protección de datos (AAIP) "
                            "y a las personas afectadas.",
                            "Assess with the legal team whether the data protection authority and the affected people "
                            "must be notified."))
    decisions.append(tx("Aprobar el presupuesto para el análisis forense y las mejoras de seguridad propuestas.",
                        "Approve the budget for the forensic analysis and the proposed security improvements."))
    if "exfiltration" in tactics or "web" in cats:
        decisions.append(tx("Definir si se informará a clientes o socios y quién será el vocero.",
                            "Decide whether customers or partners will be informed and who will be the spokesperson."))
    return {"now": now, "soon": soon, "later": later, "decisions": decisions}


def build_executive_report(session, client: str, analyst: str, lang: str = "es") -> dict:
    with using(lang):
        return _build_executive_report(session, client, analyst, lang)


def _affected(systems: list[str]) -> str:
    if current() == "en":
        return f"It affected {_join(systems)}. "
    return f"Afectó {_join([('al ' + x[3:]) if x.startswith('el ') else ('a ' + x) for x in systems])}. "


def _build_executive_report(session, client: str, analyst: str, lang: str) -> dict:
    a, q = session.analysis_in(lang), session.quality
    ids = _Ids()
    by_id = {f["id"]: f for f in a["findings"]}
    incidents = a["incidents"]
    sections = []
    n = len(incidents)
    sev = {s: sum(1 for i in incidents if i["severity"] == s) for s in URGENCY}
    users = sorted({u for i in incidents for u in i["entities"]["user"]})
    hosts = sorted({h for i in incidents for h in i["entities"]["host"]})
    d0, d1 = _fmt(q.get("date_min")), _fmt(q.get("date_max"))
    period = tx(f"del {d0} al {d1}", f"from {d0} to {d1}")

    # 1. En resumen ---------------------------------------------------------------
    blocks = []
    what = tx("¿Qué pasó?", "What happened?")
    if n:
        worst = next(s for s in URGENCY if sev[s])
        color, action = _color(worst), _action(worst)
        counts = _join([tx(f"{sev[s]} de nivel {_level(s)}", f"{sev[s]} {_level(s)}") for s in URGENCY if sev[s]])
        blocks.append(_p(ids("E"), tx(
            f"Analizamos los registros de actividad de los sistemas de {client} {period}. Encontramos {n} "
            f"{'incidente' if n == 1 else 'incidentes'} de seguridad que requieren atención: {counts}. "
            f"El nivel de riesgo general es {worst.upper()} (semáforo {color.lower()}): {action.lower()}.",
            f"We analyzed the activity logs of {client}'s systems {period}. We found {n} security "
            f"{'incident' if n == 1 else 'incidents'} that require attention: {counts}. "
            f"The overall risk level is {LEVEL_EN[worst].upper()} ({color.lower()} light): {action.lower()}."),
            kind="inferencia", title=what))
        blocks.append(_list(ids("E"), [tx(f"{business_title(i, [by_id[f] for f in i['finding_ids']])} – nivel {_level(i['severity'])}.",
                                          f"{business_title(i, [by_id[f] for f in i['finding_ids']])} – {_level(i['severity'])} level.")
                                       for i in incidents], kind="hecho_observado",
                            title=tx("Los incidentes en una línea", "The incidents in one line")))
        blocks.append(_p(ids("E"), tx(
            f"Se vieron involucradas {len(users)} cuenta(s) de usuario y {len(hosts)} equipo(s) o servidor(es). "
            "Los registros no permiten confirmar si el atacante sigue dentro: hasta verificarlo, debe considerarse que la "
            "amenaza está activa.",
            f"{len(users)} user account(s) and {len(hosts)} computer(s) or server(s) were involved. "
            "The logs cannot confirm whether the attacker is still inside: until verified, the threat must be "
            "considered active."), kind="inferencia", title=tx("¿Sigue habiendo riesgo?", "Is there still a risk?")))
        blocks.append(_list(ids("E"), recommendations(incidents, by_id)["decisions"], kind="recomendacion",
                            title=tx("¿Qué necesitamos que decida la dirección?", "What do we need management to decide?")))
    else:
        blocks.append(_p(ids("E"), tx(
            f"Analizamos los registros de actividad de los sistemas de {client} {period} y no encontramos incidentes de "
            "seguridad que requieran acción. Se detallan observaciones menores en el informe técnico.",
            f"We analyzed the activity logs of {client}'s systems {period} and found no security incidents that "
            "require action. Minor observations are detailed in the technical report."), kind="inferencia", title=what))
    sections.append({"id": "ej_resumen", "number": "1", "title": tx("En resumen", "In summary"), "blocks": blocks})

    # 2. Cifras clave ---------------------------------------------------------------
    total = f"{q['total_rows']:,}".replace(",", ".") if current() == "es" else f"{q['total_rows']:,}"
    rows = [[tx("Período analizado", "Period analyzed"), f"{d0} → {d1}"],
            [tx("Registros revisados", "Records reviewed"), total],
            [tx("Incidentes encontrados", "Incidents found"), str(n)],
            [tx("Incidentes críticos o altos", "Critical or high incidents"), str(sev["Crítico"] + sev["Alto"])],
            [tx("Cuentas de usuario involucradas", "User accounts involved"), str(len(users))],
            [tx("Equipos y servidores involucrados", "Computers and servers involved"), str(len(hosts))]]
    sections.append({"id": "ej_cifras", "number": "2", "title": tx("Cifras clave", "Key figures"),
                     "blocks": [_table(ids("T"), [tx("Indicador", "Indicator"), tx("Valor", "Value")], rows,
                                       kind="hecho_observado")]})

    # 3. Qué ocurrió -------------------------------------------------------------------
    blocks = []
    for i in incidents:
        fs = [by_id[f] for f in i["finding_ids"]]
        steps = plain_steps(i, fs)
        systems = [host_role(h) for h in i["entities"]["host"][:4]]
        color, action = _color(i["severity"]), _action(i["severity"])
        attacker = tx(f"{_when(i).capitalize()}, un atacante ", f"{_when(i)[0].upper() + _when(i)[1:]}, an attacker ")
        text = (attacker + (_join(steps) or tx("realizó actividad sospechosa", "carried out suspicious activity")) + ". "
                + (_affected(systems) if systems else "")
                + (tx("Se usó ", "It used ") + _join([account_label(u) for u in i["entities"]["user"][:4]]) + ". "
                   if i["entities"]["user"] else ""))
        blocks.append(_p(ids("E"), text, kind="hecho_observado",
                         title=tx(f"{i['id']} · {business_title(i, fs)} — nivel {_level(i['severity'])} ({color.lower()})",
                                  f"{i['id']} · {business_title(i, fs)} — {_level(i['severity'])} level ({color.lower()})")))
        blocks.append(_p(ids("E"), tx("Urgencia: ", "Urgency: ") + f"{action}.", kind="recomendacion"))
    if not incidents:
        blocks.append(_p(ids("E"), tx("No se identificaron incidentes.", "No incidents were identified."), kind="info"))
    sections.append({"id": "ej_incidentes", "number": "3", "title": tx("Qué ocurrió, explicado sin tecnicismos",
                                                                       "What happened, explained without jargon"),
                     "blocks": blocks})

    # 4. Impacto para el negocio -----------------------------------------------------------
    blocks = [_p(ids("E"), tx("Evaluamos qué podría verse afectado según lo que muestran los registros. «Alto» significa que hay "
                              "evidencia directa del riesgo; «Medio», que existe la posibilidad; «Bajo», que no se observó.",
                              "We assessed what could be affected based on what the logs show. “High” means there is "
                              "direct evidence of the risk; “Medium”, that it is possible; “Low”, that it was not observed."),
                 kind="info"),
              _table(ids("T"), [tx("Área del negocio", "Business area"), tx("Nivel de riesgo", "Risk level"),
                                tx("Por qué", "Why")], impact_matrix(incidents, by_id), kind="inferencia")]
    sections.append({"id": "ej_impacto", "number": "4", "title": tx("Qué puede afectar al negocio", "What may affect the business"),
                     "blocks": blocks})

    # 5. Semáforo de urgencia -----------------------------------------------------------------
    rows = [[i["id"], business_title(i, [by_id[f] for f in i["finding_ids"]]),
             tx(i["severity"], LEVEL_EN[i["severity"]].capitalize()), _action(i["severity"])] for i in incidents]
    sections.append({"id": "ej_semaforo", "number": "5", "title": tx("Prioridad de atención", "Attention priority"), "blocks": [
        _p(ids("E"), tx("Rojo: actuar hoy · Naranja: 24–48 horas · Amarillo: esta semana · Verde: operación habitual.",
                        "Red: act today · Orange: 24–48 hours · Yellow: this week · Green: normal operations."), kind="info"),
        _table(ids("T"), [tx("Incidente", "Incident"), tx("Qué es", "What it is"), tx("Nivel de riesgo", "Risk level"),
                          tx("Cuándo actuar", "When to act")], rows, kind="inferencia")]})

    # 6. Qué recomendamos -------------------------------------------------------------------------
    rec = recommendations(incidents, by_id) if incidents else {"now": [], "soon": [], "later": [], "decisions": []}
    blocks = [_list(ids("E"), rec["now"] or [tx("Sin acciones urgentes.", "No urgent actions.")], kind="recomendacion",
                    title=tx("Ahora (próximas 24 horas)", "Now (next 24 hours)")),
              _list(ids("E"), rec["soon"], kind="recomendacion", title=tx("Próximos 30 días", "Next 30 days")),
              _list(ids("E"), rec["later"], kind="recomendacion", title=tx("Mediano plazo (prevención)", "Medium term (prevention)"))]
    sections.append({"id": "ej_acciones", "number": "6", "title": tx("Qué recomendamos hacer", "What we recommend"),
                     "blocks": blocks})

    # 7. Glosario --------------------------------------------------------------------------------
    corpus = " ".join(b.get("text") or " ".join(b.get("items") or []) for s in sections for b in s["blocks"]).lower()
    terms = [v for k, v in GLOSSARY[current()].items() if k.lower() in corpus]
    blocks = [_list(ids("E"), terms or [tx("Sin términos técnicos relevantes.", "No relevant technical terms.")], kind="info"),
              _p(ids("E"), tx("El detalle técnico, la evidencia de cada hallazgo (con las filas exactas de los registros) y la "
                              "metodología están en el Informe técnico que acompaña a este documento.",
                              "The technical detail, the evidence for each finding (with the exact log rows) and the "
                              "methodology are in the Technical report that accompanies this document."), kind="info")]
    sections.append({"id": "ej_glosario", "number": "7", "title": tx("Glosario y próximos pasos", "Glossary and next steps"),
                     "blocks": blocks})

    return {
        "meta": {"kind": "ejecutivo", "title": tx("Informe ejecutivo de incidente de seguridad", "Executive security incident report"),
                 "client": client, "analyst": analyst, "lang": lang,
                 "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                 "version": session.report_versions.get("ejecutivo", 0) + 1,
                 "classification": tx("CONFIDENCIAL", "CONFIDENTIAL"),
                 "source_file": session.filename, "ai_used": False, "ai_model": None},
        "sections": sections,
        "ai_review": [],
    }
