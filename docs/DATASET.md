# Dataset de ejemplo – SINTÉTICO

`sample_data/SINTETICO_logs_cliente.xlsx` se genera con `python sample_data/generate_synthetic.py` (semilla fija, reproducible). **Todos los datos son ficticios**: empresa «Fjordvik AB», IPs externas en rangos de documentación (RFC 5737: `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) y dominios con TLD reservado `.example`.

## Esquema

| Hoja | Filas | Formato de fecha | Columnas |
|---|---|---|---|
| `LEEME_SINTETICO` | 4 | — | Aviso de dataset sintético (la app la excluye por no tener fecha) |
| `Security` | 1.076 | texto `dd/mm/aaaa HH:MM:SS`, hora local de Estocolmo | Fecha/Hora, EventID, Equipo, Cuenta, Cuenta destino, IP Origen, Tipo de inicio de sesión, Resultado, Grupo, Privilegios, Nombre de recurso compartido, Nombre de servicio, Mensaje |
| `Sysmon_Procesos` | 2.098 | fecha nativa de Excel, hora local | TimeCreated, Computer, User, Image, ParentImage, CommandLine, SHA256 |
| `VPN` | 72 | ISO-8601 en UTC (`…Z`) | timestamp, username, src_ip, country, city, latitude, longitude, status, assigned_ip |

Rango: 19/10/2026 01:03 → 25/10/2026 11:31 (Europe/Stockholm; incluye el cambio de horario del 25/10). EventIDs presentes: 4624, 4625, 4634, 4672, 4720, 4728, 4732, 5140, 7045, 1102. 41 usuarios, 43 hosts.

Los encabezados mezclan español e inglés a propósito para probar el mapeo automático.

## Escenario

**Tráfico benigno de fondo**: logons de jornada (tipo 2) y accesos de red a `SRV-FS01`/`SRV-APP01`, 1–2 fallos ocasionales por error de tipeo seguidos de éxito, backups nocturnos de `svc_backup` (logon tipo 5), PowerShell administrativo no codificado y `curl` de healthcheck de `it.admin`, RDP diario de `it.admin` a `SRV-APP01`, alta de un empleado nuevo (`n.ekstrom`) en un grupo **no** privilegiado, teletrabajo por VPN desde Suecia (incluido uno fuera de horario, `k.nilsson`).

**Incidente A (vie 23/10, madrugada)** – `m.lindqvist`:
1. Password spraying desde `203.0.113.45` (BR) contra ~25 cuentas por VPN.
2. Fuerza bruta (18 fallos) y acceso VPN exitoso a las 02:41; viaje imposible respecto del logon legítimo desde Estocolmo de la noche anterior.
3. RDP a `WS-017`, PowerShell `-W Hidden -Enc`, `certutil -urlcache` → `C:\Users\Public\svc.exe`.
4. Volcado de LSASS con `comsvcs.dll MiniDump`.
5. Alta en *Administrators* y *Domain Admins*; privilegios especiales (4672).
6. Desactivación de Defender, tarea programada de persistencia.
7. Movimiento lateral a `SRV-FS01`, `SRV-SQL01`, `SRV-DC01` (logon tipo 3, `ADMIN$`, PsExec/PSEXESVC, `wmic /node`).
8. Compresión con contraseña y `curl -T` a `files.transfer-drop.example`; borrado del log Security (1102).
9. A la mañana, sesiones simultáneas desde BR y SE.

**Incidente B (sáb 24/10)** – fuerza bruta **fallida** desde `198.51.100.77` contra `svc_sql` y `administrator` en `SRV-APP01`, y dos horas después un logon RDP de la cuenta de servicio `svc_sql` desde `WS-031`. No comparte entidades con A.

**Calidad de datos**: 9 filas con fecha inválida o vacía, una celda `=HYPERLINK(...)` y una celda con `<script>`.

## Resultado esperado del análisis

2 incidentes candidatos independientes (INC-01 Crítico, INC-02 Alto), 2 hallazgos aislados de baja criticidad (teletrabajo fuera de horario y alta de empleado nuevo) y 3 anomalías sin relación con los incidentes.
