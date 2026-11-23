"""Textos de referencia determinísticos (plantillas) por regla y táctica.

Se usan cuando no hay IA o como base editable. Solo describen la técnica y acciones
genéricas; los datos concretos (cuentas, hosts, filas) salen siempre del motor.
"""

RULE_EXPLAIN = {
    "BF-001": "Un adversario intenta adivinar la contraseña de una cuenta concreta probando muchas combinaciones en poco tiempo. "
              "Cada intento genera un evento de autenticación fallida (4625/4771 o resultado «fallido»). La técnica se vuelve crítica si "
              "la racha termina en un inicio de sesión exitoso.",
    "BF-002": "En el password spraying el atacante prueba unas pocas contraseñas comunes contra muchas cuentas desde el mismo origen, "
              "para evitar los bloqueos por cuenta. El indicador es una IP con fallos repartidos entre numerosos usuarios distintos.",
    "BF-003": "Un inicio de sesión exitoso inmediatamente posterior a una racha de fallos desde el mismo origen sugiere que la "
              "credencial fue adivinada. Es el punto en que un intento de fuerza bruta pasa a ser un posible acceso válido (T1078).",
    "LOG-001": "Los accesos exitosos desde IPs externas con geolocalización fuera de los países habituales del cliente, o desde IPs "
               "nunca vistas para la cuenta, son un indicador clásico de uso de credenciales robadas a través de servicios remotos (VPN).",
    "LOG-002": "Los inicios de sesión interactivos o remotos fuera del horario laboral del cliente pueden indicar uso ilegítimo de una "
               "cuenta, aunque también son frecuentes en guardias y teletrabajo; por eso tienen peso bajo salvo que se correlacionen.",
    "LOG-003": "Las cuentas de servicio están pensadas para procesos automáticos (logon tipo 4/5). Un logon interactivo (2) o por "
               "RDP (10) con una cuenta de servicio indica que alguien usa sus credenciales manualmente.",
    "LOG-004": "Dos accesos exitosos de la misma cuenta desde ubicaciones cuya distancia exige una velocidad físicamente imposible "
               "indican que al menos uno de ellos no corresponde al usuario legítimo (o que la geolocalización es imprecisa).",
    "LOG-005": "Sesiones simultáneas de una misma cuenta desde IPs externas distintas sugieren credenciales compartidas o robadas.",
    "PE-001": "Agregar una cuenta a grupos como Administrators o Domain Admins otorga control total sobre el equipo o el dominio. "
              "Es un paso típico para consolidar el acceso tras comprometer una cuenta (T1098).",
    "PE-002": "El evento 4672 registra la asignación de privilegios especiales (SeDebug, SeTcb, SeImpersonate…) al iniciar sesión. "
              "Que aparezca para una cuenta que no los tenía en la línea base indica un cambio de privilegios.",
    "PE-003": "La creación o modificación de cuentas puede usarse para persistir en el entorno; en la mayoría de los casos es "
              "actividad administrativa rutinaria y debe contrastarse con el proceso de altas.",
    "PE-004": "El uso de credenciales alternativas (runas, sudo, 4648) permite ejecutar procesos con otro contexto de seguridad.",
    "EX-001": "PowerShell con -EncodedCommand y ventana oculta es una forma común de ocultar el script ejecutado. El contenido "
              "codificado en Base64 (UTF-16LE) puede decodificarse para conocer la acción real.",
    "EX-002": "Herramientas legítimas del sistema (certutil, bitsadmin, Invoke-WebRequest, curl) se abusan para descargar "
              "herramientas del atacante evitando controles (Ingress Tool Transfer, T1105).",
    "EX-003": "Los LOLBins son binarios firmados de Windows usados para ejecutar código por proxy (rundll32, regsvr32, mshta, WMIC), "
              "lo que dificulta su detección por listas blancas.",
    "EX-004": "La ejecución de binarios desde rutas escribibles por cualquier usuario (C:\\Users\\Public, %TEMP%) es característica "
              "de cargas maliciosas descargadas en el momento.",
    "EX-005": "El volcado de memoria de LSASS (p. ej. con comsvcs.dll MiniDump) o de la base NTDS permite extraer hashes y tickets de "
              "otras cuentas, habilitando escalamiento y movimiento lateral (T1003).",
    "EX-006": "Deshabilitar la protección en tiempo real de Defender, el firewall o la auditoría reduce la visibilidad defensiva "
              "y suele preceder a acciones más ruidosas (T1562.001).",
    "EX-007": "Borrar los registros de eventos (wevtutil cl, evento 1102) busca eliminar rastros; implica que la telemetría local "
              "posterior puede estar incompleta (T1070.001).",
    "EX-008": "Las tareas programadas, servicios nuevos o claves Run permiten que el atacante recupere la ejecución tras reinicios "
              "o cierres de sesión (persistencia).",
    "EX-009": "Comprimir datos con contraseña y subirlos con curl u otras utilidades a dominios externos es un patrón de "
              "recolección y exfiltración de información (T1560, T1048).",
    "LM-001": "Una misma cuenta autenticándose por red o RDP en varios hosts en minutos indica desplazamiento del atacante dentro "
              "de la red usando credenciales válidas (T1021).",
    "LM-002": "Un logon RDP o de red hacia un servidor crítico en una combinación cuenta→host nunca vista en la línea base es un "
              "indicador de movimiento lateral o de acceso no habitual.",
    "LM-003": "PsExec (servicio PSEXESVC), WMIC /node y WinRM permiten ejecutar comandos en equipos remotos; son herramientas de "
              "administración frecuentemente abusadas para movimiento lateral.",
    "LM-004": "Los recursos administrativos ocultos (ADMIN$, C$) permiten copiar y ejecutar binarios en equipos remotos vía SMB.",
    "EX-010": "Comandos de reconocimiento (net view, whoami, Get-LocalGroupMember, Get-SmbShare…) permiten al atacante "
              "conocer cuentas, grupos privilegiados y recursos compartidos antes de moverse o robar datos (Discovery).",
    "EX-011": "Borrar las shadow copies o los backups impide recuperar archivos y es el paso previo típico al cifrado "
              "por ransomware (T1490). Requiere privilegios administrativos en el equipo.",
    "C2-001": "Un intérprete de comandos (PowerShell, cmd, mshta…) que se conecta directamente a una IP pública suele "
              "indicar descarga de herramientas o un canal de comando y control; el software legítimo rara vez lo hace.",
    "WEB-001": "Una web shell es un script subido al servidor web que ejecuta comandos del sistema a través de parámetros "
               "HTTP (p. ej. ?cmd=whoami). Si además hay procesos de shell lanzados por la identidad del pool de la "
               "aplicación (IIS APPPOOL, www-data), la ejecución fue efectiva (T1190, T1505.003).",
    "COL-001": "El acceso secuencial a muchos archivos distintos de un recurso compartido en pocos minutos es característico "
               "de la recolección de datos antes de exfiltrarlos o cifrarlos (T1039).",
    "EXF-001": "Un host que envía cientos de MB a un único destino externo en poco tiempo es compatible con exfiltración; "
               "el volumen y la repetición (sesiones de subida) refuerzan la sospecha (T1048).",
    "AN-001": "Pico estadístico del volumen de eventos frente a la misma hora de otros días. Es contexto, no prueba de incidente.",
    "AN-002": "Entidad (usuario, host o IP) que aparece por primera vez después del período base. Puede ser legítima (altas nuevas).",
    "AN-003": "Evento o proceso de muy baja frecuencia no cubierto por reglas. Útil para revisión manual.",
}

TACTIC_IMPACT = {
    "credential_access": "Exposición de credenciales: el atacante puede obtener contraseñas o hashes válidos y reutilizarlos en otros sistemas.",
    "initial_access": "Acceso no autorizado a la red corporativa con una identidad válida, difícil de distinguir del usuario legítimo.",
    "execution": "Ejecución de código arbitrario en equipos del cliente, con capacidad de instalar herramientas adicionales.",
    "persistence": "Permanencia del atacante tras reinicios o cambios de contraseña si no se eliminan los mecanismos creados.",
    "privilege_escalation": "Control administrativo sobre equipos o el dominio, lo que habilita modificar cualquier recurso o cuenta.",
    "defense_evasion": "Pérdida de visibilidad y de protección (antivirus deshabilitado, registros borrados), que limita la investigación.",
    "lateral_movement": "Propagación a servidores críticos, ampliando el alcance del compromiso a datos y servicios centrales.",
    "command_and_control": "Comunicación con infraestructura externa del atacante para descargar herramientas o recibir órdenes.",
    "exfiltration": "Posible fuga de información sensible (datos comprimidos y enviados a un destino externo), con impacto legal y reputacional (p. ej. RGPD).",
    "collection": "Recolección de información del cliente en preparación para su extracción.",
    "discovery": "Conocimiento del entorno (cuentas, grupos y recursos) que facilita los siguientes pasos del atacante.",
    "impact": "Riesgo de pérdida de disponibilidad: sin copias de recuperación, un cifrado posterior impediría restaurar "
              "los datos.",
}

# Acciones por regla: (bloque, prioridad, texto). Bloques: investigar | contener | remediar
RULE_ACTIONS = {
    "BF-001": [("investigar", 2, "Verificar con el titular de la cuenta {users} si reconoce los intentos y revisar el origen {ips}."),
               ("contener", 2, "Bloquear la IP de origen {ips} en el perímetro/VPN si es externa.")],
    "BF-002": [("contener", 1, "Bloquear la IP {ips} en el firewall/VPN y revisar si otras IPs del mismo rango repiten el patrón."),
               ("investigar", 2, "Revisar si alguna de las cuentas atacadas registró un acceso exitoso posterior desde esa IP.")],
    "BF-003": [("contener", 1, "Restablecer la contraseña de {users}, revocar sesiones/tokens activos y forzar MFA."),
               ("investigar", 1, "Reconstruir toda la actividad de {users} desde el primer acceso exitoso desde {ips}.")],
    "LOG-001": [("contener", 1, "Cerrar las sesiones VPN activas de {users} desde {ips} y restringir el acceso VPN por geolocalización."),
                ("investigar", 2, "Confirmar con el usuario si viajó o usó una VPN comercial.")],
    "LOG-002": [("investigar", 3, "Confirmar con {users} si la actividad fuera de horario fue legítima.")],
    "LOG-003": [("contener", 1, "Rotar la contraseña de la cuenta de servicio {users} y denegarle el logon interactivo/RDP por GPO."),
                ("investigar", 2, "Identificar a la persona que usó la cuenta de servicio desde {ips} y con qué fin.")],
    "LOG-004": [("investigar", 1, "Determinar cuál de los accesos de {users} es legítimo y tratar el otro como compromiso.")],
    "LOG-005": [("contener", 1, "Invalidar todas las sesiones de {users} y forzar re-autenticación con MFA.")],
    "PE-001": [("contener", 1, "Retirar a {users} de los grupos privilegiados agregados sin autorización."),
               ("investigar", 1, "Auditar todas las acciones realizadas con privilegios elevados por {users} en {hosts}.")],
    "PE-002": [("investigar", 2, "Revisar por qué {users} obtuvo privilegios especiales en {hosts}.")],
    "PE-003": [("investigar", 3, "Validar las altas/cambios de cuentas contra tickets aprobados.")],
    "PE-004": [("investigar", 2, "Revisar el uso de credenciales alternativas en {hosts}.")],
    "EX-001": [("investigar", 1, "Decodificar y analizar el comando PowerShell ejecutado en {hosts}; buscar el script descargado."),
               ("remediar", 2, "Habilitar Script Block Logging y modo Constrained Language para PowerShell.")],
    "EX-002": [("contener", 1, "Bloquear los dominios/URLs de descarga identificados en el proxy y DNS."),
               ("investigar", 1, "Obtener y analizar en sandbox los archivos descargados en {hosts}.")],
    "EX-003": [("remediar", 2, "Restringir LOLBins (rundll32, WMIC, mshta) con reglas ASR/AppLocker.")],
    "EX-004": [("contener", 1, "Aislar {hosts} de la red (EDR) y preservar una imagen forense antes de limpiar."),
               ("investigar", 1, "Buscar los hashes de los binarios en el resto del parque y en fuentes de inteligencia.")],
    "EX-005": [("contener", 1, "Considerar comprometidas todas las credenciales que tuvieron sesión en {hosts}: rotarlas, incluida krbtgt si hubo acceso al DC."),
               ("remediar", 1, "Habilitar Credential Guard / LSA Protection (RunAsPPL) en estaciones y servidores.")],
    "EX-006": [("contener", 1, "Restaurar la protección de Defender y el firewall en {hosts} y verificar por consola central."),
               ("remediar", 2, "Activar Tamper Protection para impedir cambios locales de la configuración de Defender.")],
    "EX-007": [("investigar", 1, "Recuperar los registros borrados de {hosts} desde el SIEM/reenvío centralizado."),
               ("remediar", 2, "Asegurar el reenvío de eventos en tiempo real y alertar sobre el evento 1102.")],
    "EX-008": [("contener", 1, "Eliminar las tareas programadas y servicios creados por el atacante en {hosts}."),
               ("investigar", 2, "Inventariar otros mecanismos de persistencia (Run keys, WMI subscriptions) en los hosts afectados.")],
    "EX-009": [("investigar", 1, "Determinar qué datos se comprimieron y enviaron; evaluar obligación de notificación (RGPD art. 33, 72 h)."),
               ("contener", 1, "Bloquear los dominios de exfiltración identificados.")],
    "LM-001": [("investigar", 1, "Revisar cada host al que accedió {users} ({hosts}) en busca de actividad adicional.")],
    "LM-002": [("contener", 2, "Restringir RDP hacia servidores solo desde jump hosts autorizados.")],
    "LM-003": [("contener", 1, "Bloquear PsExec/WMI remoto desde estaciones de trabajo y eliminar el servicio PSEXESVC en {hosts}.")],
    "EX-010": [("investigar", 2, "Revisar qué información obtuvo el atacante con los comandos de reconocimiento en {hosts}.")],
    "EX-011": [("contener", 1, "Aislar {hosts} de inmediato: el borrado de shadow copies suele preceder al cifrado."),
               ("remediar", 1, "Verificar que existan backups fuera de línea/inmutables y probar su restauración.")],
    "C2-001": [("contener", 1, "Bloquear las IPs de destino en firewall/proxy y aislar {hosts}."),
               ("investigar", 1, "Identificar qué se descargó o envió en las conexiones salientes desde {hosts}.")],
    "WEB-001": [("contener", 1, "Retirar el script malicioso de {hosts}, bloquear la IP {ips} en el WAF y aislar el servidor."),
                ("investigar", 1, "Revisar cómo se subió el archivo (vulnerabilidad de carga) y qué comandos se ejecutaron."),
                ("remediar", 1, "Corregir la vulnerabilidad de carga de archivos e impedir la ejecución de scripts en /uploads.")],
    "COL-001": [("investigar", 1, "Inventariar los archivos accedidos por {users} y evaluar su sensibilidad."),
                ("contener", 2, "Restringir temporalmente los permisos de {users} sobre el recurso compartido.")],
    "EXF-001": [("contener", 1, "Bloquear el destino de la transferencia en el proxy y aislar {hosts}."),
                ("investigar", 1, "Determinar qué datos salieron (tamaño, horario) y evaluar notificación (RGPD/Ley 25.326).")],
    "LM-004": [("remediar", 2, "Limitar el acceso a ADMIN$/C$ a cuentas de administración dedicadas (tiering).")],
}

GENERAL_RECOMMENDATIONS = {
    "bruteforce": "Exigir MFA en VPN y servicios expuestos; aplicar bloqueo progresivo y detección de password spraying.",
    "suspicious_logon": "Aplicar acceso condicional por geolocalización y dispositivo; prohibir el logon interactivo de cuentas de servicio (usar gMSA).",
    "privesc": "Implementar un modelo de administración por niveles (tiering), PAM/JIT para grupos privilegiados y alertas sobre cambios en grupos críticos.",
    "execution": "Desplegar EDR con reglas ASR, registrar PowerShell (Script Block Logging) y limitar LOLBins con AppLocker/WDAC.",
    "lateral": "Segmentar la red, restringir RDP/SMB/WinRM entre estaciones y servidores y usar LAPS para contraseñas locales.",
    "collection": "Aplicar DLP y alertas de volumen saliente, y auditar los accesos masivos a recursos compartidos sensibles.",
    "web": "Mantener las aplicaciones web actualizadas, usar WAF y deshabilitar la ejecución de scripts en directorios de carga.",
    "anomaly": "Mantener líneas base de comportamiento por usuario/host para reducir falsos positivos en futuras investigaciones.",
}

GENERIC_RECOMMENDATIONS = [
    "Centralizar y retener los registros (Security, Sysmon, VPN) al menos 12 meses, con reenvío en tiempo real para evitar pérdidas por borrado local.",
    "Sincronizar la hora (NTP) y exportar los timestamps con zona horaria explícita para facilitar la correlación.",
    "Formalizar un procedimiento de respuesta a incidentes con roles, contactos y criterios de notificación (RGPD / NIS2).",
    "Realizar ejercicios periódicos de concienciación sobre phishing y higiene de contraseñas.",
]


# ---------------------------------------------------------------------- acceso según el idioma activo
def _localized(name: str):
    from app.lang import current
    if current() == "en":
        from app.report import knowledge_en
        return getattr(knowledge_en, name)
    return globals()[name]


def rule_explain() -> dict[str, str]:
    return _localized("RULE_EXPLAIN")


def tactic_impact() -> dict[str, str]:
    return _localized("TACTIC_IMPACT")


def rule_actions() -> dict[str, list[tuple[str, int, str]]]:
    return _localized("RULE_ACTIONS")


def general_recommendations() -> dict[str, str]:
    return _localized("GENERAL_RECOMMENDATIONS")


def generic_recommendations() -> list[str]:
    return _localized("GENERIC_RECOMMENDATIONS")
