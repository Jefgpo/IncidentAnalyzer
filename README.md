# IncidentAnalyzer

Aplicación web para analistas SOC de nivel 2: carga un **.xlsx exportado de un SIEM**, normaliza los eventos, ejecuta **34 reglas determinísticas mapeadas a MITRE ATT&CK**, correlaciona los hallazgos en **incidentes candidatos** (y concluye si hay uno o varios), clasifica el riesgo con un esquema reproducible, genera **dos informes editables** (uno **ejecutivo** para la dirección y uno **técnico** detallado) y los exporta a **PDF profesional**. La IA es opcional: **apoya la redacción, no decide**.

> No se integra con Microsoft Sentinel ni con ningún SIEM: trabaja solo con el archivo cargado. Interfaz en español e inglés.

---

## Inicio rápido

### Requisitos

| Para… | Necesitás | Cómo verificarlo |
|---|---|---|
| Opción 1 (recomendada) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) abierto | `docker --version` |
| Opciones 2 y 3 | [Python 3.11+](https://www.python.org/downloads/) y [Node.js 20+](https://nodejs.org/) | `python --version` · `node --version` |

Ninguna clave es obligatoria: sin claves funciona todo menos la redacción con IA y la reputación de IPs.

### Opción 1 · Docker (un solo comando)

```bash
docker compose up --build
```

Abrí <http://localhost:8080> y usá **«Probar con el dataset de ejemplo»** o arrastrá tu .xlsx. Para detenerlo: `docker compose down`.

### Opción 2 · Script de desarrollo (sin Docker)

Prepara todo la primera vez (entorno de Python, dependencias, `.env`) y levanta backend y frontend juntos:

```powershell
.\run.ps1          # Windows (PowerShell)
```

```bash
./run.sh           # Linux / macOS / Git Bash
```

Se abre <http://localhost:5173>. Con `.\run.ps1 -Test` o `./run.sh test` se corren todos los tests.

### Opción 3 · Paso a paso

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt      # Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m uvicorn app.main:app --port 8000 --reload
```

En otra terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend en <http://localhost:5173> (Vite redirige `/api` al backend en el puerto 8000).

### Claves opcionales

Copiá `.env.example` a `.env` (los scripts lo hacen solos) y completá lo que quieras usar:

| Variable | Para qué | Dónde se obtiene |
|---|---|---|
| `AI_API_KEY` | Redacción del informe técnico y chat con IA (Claude) | <https://console.anthropic.com/> |
| `ABUSEIPDB_API_KEY` | Reputación de IPs públicas | <https://www.abuseipdb.com/account/api> (gratis) |

Con Docker, después de editar `.env` reiniciá con `docker compose up -d --force-recreate`.

## Tus sesiones se guardan

Podés recargar la página, cerrar el navegador o reiniciar el servidor sin perder el trabajo:

- **Navegador:** guarda solo el identificador de la sesión y el paso en el que estabas; al volver, la app retoma desde ahí.
- **Servidor:** con `SESSION_STORE=disk` (el valor por defecto) guarda la sesión **cifrada** (Fernet: AES más HMAC) en disco. Se guardan las hojas leídas, los eventos, el análisis y los informes, pero nunca el archivo original. En Docker se usa el volumen `sessions`.
- **Vencimiento:** la sesión se borra sola tras `SESSION_TTL_HOURS` horas sin uso (24 por defecto); el plazo se renueva con cada acción. «Borrar ahora», al pie de la página, la elimina al instante, incluido el archivo.
- **Clave de cifrado:** definí `SESSION_ENCRYPTION_KEY` para que la clave no quede junto a los datos. Si no la definís, se genera una dentro del directorio de sesiones. Para generarla:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- **Sin disco:** con `SESSION_STORE=memory` nada toca el disco y la sesión se pierde al reiniciar el servidor.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| `docker compose` dice *cannot connect to the Docker daemon* / *dockerDesktopLinuxEngine* | Docker Desktop no está abierto | Abrí Docker Desktop, esperá a que diga *Engine running* y repetí. |
| *port is already allocated* / la página no carga en 8080 o 5173 | Otro programa usa el puerto | Cerralo, o cambiá el puerto en `docker-compose.yml` (`"127.0.0.1:9090:8080"`). |
| `npm` o `node` «no se reconoce» en Windows | Node se instaló pero la terminal es anterior | Abrí una terminal nueva (el script `run.ps1` lo resuelve solo). |
| `run.ps1` «no se puede cargar porque la ejecución de scripts está deshabilitada» | Política de PowerShell | `Set-ExecutionPolicy -Scope Process Bypass` y volvé a ejecutarlo. |
| «No se pudo contactar al backend» en la interfaz | El backend no está corriendo | En modo desarrollo, verificá la terminal del backend (puerto 8000). |
| «IA deshabilitada» | Falta `AI_API_KEY` | Completala en `.env` y reiniciá. Todo lo demás funciona sin ella. |
| «La sesión anterior venció o fue borrada» | Pasaron más de `SESSION_TTL_HOURS` sin uso, o cambió la clave de cifrado | Volvé a cargar el archivo. |
| El mapeo no reconoce una columna | Nombre de columna no previsto | Elegila a mano en la pantalla de mapeo (o agregá el sinónimo en `backend/app/config/synonyms.yaml`). |
| Las horas aparecen corridas | Zona horaria incorrecta | Elegí la zona de los logs en la barra inferior de la carga (por defecto Buenos Aires). |

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q      # Linux/macOS: .venv/bin/python
cd frontend && npm test && npm run build
```

`pytest` cubre la carga (sinónimos, zonas horarias, DST, filas inválidas, inyección de fórmulas), cada regla del motor contra filas exactas del dataset, **casos benignos que no deben disparar** (typos, backups nocturnos, administración legítima, alta de empleado), la correlación en incidentes independientes, el puntaje reproducible, el validador de IA (con un modelo simulado, sin red), la persistencia cifrada de sesiones, los dos informes y los PDF. Los tests del frontend incluyen chequeos automáticos de accesibilidad (axe). El workflow de GitHub Actions (`.github/workflows/ci.yml`) corre todo esto en cada push y construye la imagen Docker.

## Idioma (español / English)

El selector **ES / EN** de la barra superior cambia toda la aplicación, no solo los menús:

- **Interfaz**: todos los textos, avisos y mensajes de error del backend (se envía `Accept-Language`).
- **Análisis**: hallazgos, incidentes, conclusión, factores de puntaje e IoCs. El motor es determinístico, así que la versión en inglés tiene exactamente los mismos hallazgos, IDs, filas y puntajes; solo cambian los textos. Se calcula una vez y queda en caché.
- **Informes y PDF**: se generan en el idioma activo al pulsar «Generar»; si cambiás de idioma después, la app ofrece regenerarlos. La IA (si está habilitada) redacta en el idioma del informe.

Los datos del cliente (mensajes y comandos de los logs) se muestran siempre tal como vienen en el Excel.

## Accesibilidad

Pensada para usarse con teclado y lector de pantalla: enlace «Saltar al contenido», foco visible, diálogos accesibles (foco atrapado, Escape para cerrar, el foco vuelve al origen), tablas desplazables navegables con teclado, gráficos con alternativa «Ver como tabla», mapa de calor y grafo de movimiento lateral operables con Tab/Enter, contraste AA en modo claro y oscuro, texto mínimo de 12 px y respeto de «reducir movimiento» del sistema. Los tests de frontend (`npm test`) corren axe sobre los componentes clave.

## Informes: ejecutivo y técnico

Con un clic se generan **dos informes** a partir del mismo análisis. Cada uno se edita por bloque y se exporta a su propio PDF, con versión independiente.

| | Informe ejecutivo | Informe técnico |
|---|---|---|
| **Para quién** | Dirección y áreas de negocio | Equipo de seguridad y TI |
| **Lenguaje** | Sin tecnicismos: «robo de contraseña», «posible robo de información», «secuestro de datos» | Técnico: reglas, MITRE ATT&CK, EventIDs, IoCs |
| **Extensión** | ~5 páginas | ~20–30 páginas |
| **Contenido** | En resumen (qué pasó, si sigue habiendo riesgo y qué decidir) · cifras clave · cada incidente contado en lenguaje de negocio · impacto en información, operación, cuentas, cumplimiento legal y reputación · semáforo de urgencia · acciones a 24 h, 30 días y mediano plazo · glosario | Resumen · alcance y metodología · hallazgos · explicación técnica · evidencia literal con ID de fila y Log ID · línea de tiempo y cadena de ataque · criticidad justificada · impacto · plan investigar/contener/remediar · recomendaciones · limitaciones · anexos (puntaje, IoCs, reglas, mapeo MITRE ATT&CK, reputación de IPs) |
| **IA** | No | Opcional, con validación de cada afirmación |

El ejecutivo no inventa nada: traduce a lenguaje de negocio los mismos incidentes que el motor correlacionó. Cuando el análisis no permite confirmar algo (por ejemplo, si el atacante sigue dentro), lo dice.

## Reputación de IPs (AbuseIPDB)

Después del análisis, la pestaña **Analizar → Reputación de IPs** consulta las IPs **públicas** del archivo en AbuseIPDB y muestra:

- Las IPs con mala reputación y las sospechosas.
- Una tabla por IP con el veredicto, la confianza de abuso, el país, el proveedor, el enlace a AbuseIPDB y los hallazgos o incidentes donde aparece. Desde ahí se abren los eventos crudos de esa IP.
- Un resumen en el informe técnico y su **Anexo E**.

**Cada usuario usa su propia API key.** Hay dos formas:

1. **Fija**: definir `ABUSEIPDB_API_KEY` en `.env`. La clave gratuita (1.000 consultas por día) se obtiene en <https://www.abuseipdb.com/account/api>.
2. **Por sesión**: pegarla en la pantalla. Se usa solo durante esa consulta y no se guarda, no se registra en logs ni se devuelve al navegador.

Detalles:

- **Qué se consulta**: solo IPs globalmente enrutables. Las privadas, de loopback y los rangos de documentación no se envían. Esto incluye las del dataset sintético, que usa rangos de documentación: con él no hay IPs para consultar. Solo viaja la dirección IP, nunca otros datos del archivo.
- **Orden**: primero las IPs de incidentes, luego las de otros hallazgos y luego por frecuencia. Se consultan hasta `INTEL_MAX_IPS`, ajustable en pantalla.
- **Velocidad**: la consulta es casi inmediata y corre en segundo plano, con progreso en pantalla. Los resultados se cachean en memoria 24 h para no gastar cuota.
- **Errores**: una clave inválida se informa en pantalla. Un HTTP 429 se reintenta respetando `Retry-After`; con la cuota diaria agotada, la consulta se detiene con un aviso.
- **Umbrales** (en `rules.yaml → threat_intel`): maliciosa con *abuseConfidenceScore* ≥ 50; sospechosa con ≥ 25.
- **Alcance**: la reputación externa es contexto y no modifica la criticidad del motor determinístico.

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `AI_API_KEY` | *(vacía)* | Clave del proveedor de IA (hoy Anthropic/Claude, obtenela en <https://console.anthropic.com/>). Sin ella la IA queda deshabilitada y todo lo demás funciona. Nunca se hardcodea. Se acepta `ANTHROPIC_API_KEY` como alias. |
| `AI_MODEL` | `claude-opus-5-5` | Modelo para redacción y chat (alias: `ANTHROPIC_MODEL`). |
| `AI_MAX_EVIDENCE_ROWS` | `12` | Filas de evidencia por hallazgo enviadas a la IA (muestra representativa). |
| `ABUSEIPDB_API_KEY` | *(vacía)* | Clave propia de AbuseIPDB para la reputación de IPs (opcional). |
| `INTEL_MAX_IPS` | `25` | IPs públicas consultadas por defecto. |
| `INTEL_CACHE_TTL_S` | `86400` | Caché en memoria de resultados de reputación. |
| `MAX_UPLOAD_MB` | `25` | Tamaño máximo del .xlsx. |
| `MAX_ROWS` | `500000` | Filas máximas por libro. |
| `SESSION_STORE` | `disk` | `disk`: sesiones cifradas en disco (sobreviven a recargas y reinicios). `memory`: nada toca el disco. |
| `SESSION_TTL_HOURS` | `24` | Horas sin uso antes de borrar la sesión (vencimiento deslizante). |
| `SESSION_ENCRYPTION_KEY` | *(generada)* | Clave Fernet para cifrar las sesiones; definila para que no quede junto a los datos. |
| `SESSION_DIR` | `backend/.sessions` (Docker: `/data/sessions`) | Directorio de las sesiones cifradas. |
| `CORS_ORIGINS` | `http://localhost:5173,…` | Orígenes permitidos (CORS restringido). |

Los umbrales de detección, el horario laboral, los grupos privilegiados, los patrones de cuentas de servicio y de hosts críticos, y el esquema de puntaje están en [`backend/app/config/rules.yaml`](backend/app/config/rules.yaml) (se relee en cada análisis). Los sinónimos de columnas están en [`synonyms.yaml`](backend/app/config/synonyms.yaml) y el mapeo EventID → semántica en [`event_semantics.yaml`](backend/app/config/event_semantics.yaml).

---

## Flujo de uso

1. **Cargar** – drag & drop del .xlsx; se listan las hojas, se elige cuáles incluir (o se unen) y se corrige el mapeo automático de columnas. Se elige la zona horaria asumida (default `America/Argentina/Buenos_Aires`; el dataset de ejemplo propone `Europe/Stockholm`). Se muestra el reporte de calidad (filas inválidas, posibles fórmulas) y la tabla paginada de eventos con búsqueda, filtros y orden. Cada fila tiene un ID estable `Hoja!fila_excel`.
2. **Analizar** – conclusión de correlación (uno / varios incidentes y por qué), incidentes con cadena de ataque y línea de tiempo, hallazgos con factores de puntaje, estado de cada regla (incluidas las *no evaluables*), IoCs y metodología.
3. **Dashboard** – KPIs, criticidad, categorías, eventos por hora con picos, top IP/usuarios/hosts, mapa de calor día×hora y grafo de movimiento lateral. Los filtros globales afectan a todos los widgets; un clic en un gráfico filtra o abre los eventos crudos.
4. **Informe** – generación determinística de los informes ejecutivo y técnico, selector para alternar entre ambos, vista previa, edición por bloque, redacción opcional con IA sobre el técnico (validada) y chat sobre los datos.
5. **Exportar** – un PDF por informe (ejecutivo y técnico) con portada, índice, numeración, versión y clasificación «Confidencial»; CSV de IoCs; borrado de los datos de la sesión.

## Arquitectura

```
frontend/  React 18 + Vite + TypeScript + Tailwind v4 + Recharts + Zustand
backend/   FastAPI + pandas + openpyxl
  app/ingest/       lectura segura, mapeo por sinónimos/contenido, normalización, sanitización
  app/detection/    Context, Rule, Finding + reglas (auth, host, anomaly) + engine
  app/correlation/  grafo de hallazgos → incidentes, kill chain, conclusión uno/varios
  app/scoring/      puntaje 0–100 reproducible y bandas
  app/iocs/         extracción de IoCs desde la evidencia de incidentes
  app/analytics/    filtros, búsqueda y agregados del dashboard (reutilizados en el PDF)
  app/report/       informes determinísticos: técnico (builder.py) y ejecutivo (executive.py)
  app/ai/           cliente Claude, esquemas JSON, validador posterior
  app/intel/        reputación de IPs públicas (AbuseIPDB) en segundo plano
  app/pdf/          ReportLab + gráficos matplotlib
sample_data/        generador y dataset SINTÉTICO
docs/               DEMO.md, ARQUITECTURA.md, DATASET.md
```

Decisiones de stack (detalle en [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md)):

- **ReportLab + matplotlib** en lugar de WeasyPrint: WeasyPrint requiere GTK/Pango nativo en Windows. ReportLab es Python puro y soporta índice, encabezados/pies y «Página X de Y». Los gráficos del PDF se dibujan en el servidor con **los mismos agregados** que usa el dashboard.
- **Sesiones en memoria**: el archivo nunca se escribe a disco; las sesiones expiran por inactividad y se pueden borrar desde la UI (`DELETE /api/sessions/{id}`).
- **Un contenedor**: el frontend compilado se sirve desde FastAPI, en el mismo origen y con CSP estricta.

## Catálogo de reglas de detección

| ID | Regla | Categoría | MITRE ATT&CK | Campos requeridos |
|---|---|---|---|---|
| BF-001 | Fuerza bruta por cuenta (≥10 fallos en 10 min) | Fuerza bruta | T1110.001 | timestamp, user, EventID o resultado |
| BF-002 | Password spraying (1 IP → ≥10 usuarios en 30 min) | Fuerza bruta | T1110.003 | + src_ip |
| BF-003 | Éxito tras racha de fallos (≥5 en 30 min) | Fuerza bruta | T1110, T1078 | timestamp, user, auth |
| LOG-001 | Logon desde IP externa con país no habitual o IP nunca vista | Logon sospechoso | T1078, T1133 | + src_ip |
| LOG-002 | Logon interactivo/remoto fuera de horario (TZ del cliente) | Logon sospechoso | T1078 | + logon_type o src_ip |
| LOG-003 | Cuenta de servicio con logon interactivo/RDP | Logon sospechoso | T1078.002 | + logon_type |
| LOG-004 | Viaje imposible (> 900 km/h) | Logon sospechoso | T1078 | + lat/lon |
| LOG-005 | Sesiones simultáneas desde IPs externas distintas | Logon sospechoso | T1078 | + src_ip |
| PE-001 | Alta en grupo privilegiado (4728/4732/4756) | Escalamiento | T1098, T1078.002 | timestamp, group, EventID o acción |
| PE-002 | Privilegios especiales (4672) a cuenta no admin | Escalamiento | T1078.002, T1134 | timestamp, user, EventID |
| PE-003 | Creación/cambio de cuenta (4720/4722/4724/4738) | Escalamiento | T1136.001, T1098 | timestamp, EventID |
| PE-004 | runas / sudo anómalo / 4648 | Escalamiento | T1548, T1134.002 | línea de comando, proceso o EventID |
| EX-001 | PowerShell codificado/oculto (decodifica el Base64) | Comandos/procesos | T1059.001, T1027 | command_line |
| EX-002 | Descargas con certutil/bitsadmin/IWR/curl/wget | Comandos/procesos | T1105 | command_line |
| EX-003 | LOLBins (rundll32, regsvr32, mshta, WMIC) | Comandos/procesos | T1218, T1047 | command_line |
| EX-004 | Ejecución desde rutas temporales/públicas | Comandos/procesos | T1204.002, T1036 | process o command_line |
| EX-005 | Volcado de credenciales (LSASS, NTDS, SAM) | Comandos/procesos | T1003.001, T1003.003 | process o command_line |
| EX-006 | Desactivación de defensas | Comandos/procesos | T1562.001 | command_line |
| EX-007 | Borrado de registros (wevtutil, 1102/104) | Comandos/procesos | T1070.001 | command_line o EventID |
| EX-008 | Persistencia (schtasks, 7045/4697, Run keys) | Comandos/procesos | T1053.005, T1543.003 | command_line o EventID |
| EX-009 | Compresión con contraseña / a rutas temporales (7z, rar, tar) | Recolección y exfiltración | T1560.001, T1048 | command_line |
| EX-010 | Reconocimiento (net view/group, whoami, nltest, Get-LocalGroupMember, Get-SmbShare) | Comandos/procesos | T1087, T1069, T1135, T1033 | command_line o descripción |
| EX-011 | Borrado de shadow copies / backups (vssadmin, wbadmin, bcdedit) | Comandos/procesos | T1490 | command_line o descripción |
| C2-001 | Intérprete de scripts/LOLBin con conexión directa a IP pública | Comandos/procesos | T1071.001, T1059.001 | dst_ip, EventID o fuente |
| WEB-001 | Web shell: URI con `?cmd=` o shell lanzada por la identidad del servidor web | Ataques a servicios web | T1190, T1505.003 | command_line/URI |
| COL-001 | Acceso a ≥10 archivos distintos en 10 min (4663/5145) | Recolección y exfiltración | T1039, T1005 | user, EventID |
| EXF-001 | ≥ 50 MB enviados a un destino externo en 60 min (proxy/firewall) | Recolección y exfiltración | T1048, T1041 | bytes enviados |
| LM-001 | Misma cuenta en ≥3 hosts en 30 min (logon tipo 3/10) | Movimiento lateral | T1021 | user, host, auth, logon_type |
| LM-002 | RDP o logon de red a host crítico no visto en línea base | Movimiento lateral | T1021.001 | + logon_type |
| LM-003 | PsExec / WMIC remoto / WinRM | Movimiento lateral | T1569.002, T1047, T1021.006 | command_line o servicio |
| LM-004 | Acceso a ADMIN$ / C$ | Movimiento lateral | T1021.002 | share o command_line |
| AN-001 | Pico de volumen por hora (z-score) | Anomalía | — | timestamp |
| AN-002 | Usuario/host/IP visto por primera vez tras el período base | Anomalía | — | user, host o src_ip |
| AN-003 | EventID/proceso de muy baja frecuencia no cubierto | Anomalía | — | EventID o proceso |

Si al Excel le faltan los campos que una regla necesita, la regla se marca **«no evaluable por falta de datos»** y el informe lo declara en *Limitaciones*; nunca se asume.

## Puntaje de riesgo

`puntaje = base(regla) + éxito(+20, solo autenticación) + cuenta privilegiada(+15) + host crítico(+10) + volumen(0–10) + correlación(+5 por táctica adicional, máx. 15)`, tope 100. Bandas: **Crítico ≥ 80**, **Alto 60–79**, **Medio 40–59**, **Bajo < 40**. Las anomalías nunca superan Medio. Un incidente toma el mayor puntaje de sus hallazgos + 2 por táctica adicional. Cada hallazgo muestra su tabla de factores en la UI y en el informe (Anexo A).

## IA integrada (apoya, no decide)

- Recibe **solo** los hallazgos detectados por el motor, una muestra representativa de sus filas de evidencia y agregados; nunca el Excel completo.
- Prompt de sistema estricto: usar únicamente la evidencia, declarar cuando no hay evidencia, no inferir actores/malware/intenciones, citar siempre los IDs de fila.
- Salida JSON estructurada; **validación posterior**: cada afirmación debe citar filas existentes que pertenezcan a la evidencia de los hallazgos citados, y toda IP/hash/usuario/host mencionado debe aparecer en esas filas. Lo que no cumple se descarta y se lista como «requiere revisión» (UI y PDF).
- Los textos de IA se rotulan como tales en la UI y en el PDF y son editables.
- Modelo `claude-opus-5-5`, esfuerzo `medium`, con el *fallback* del lado del servidor habilitado (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`) para que una negativa del clasificador se reintente en otro modelo.

## Seguridad y privacidad

- Procesamiento local. El archivo original nunca se guarda; la sesión de trabajo se guarda cifrada (o solo en memoria con `SESSION_STORE=memory`), vence sola y puede borrarse al instante.
- Los logs del servidor registran solo conteos, IDs y tiempos, nunca contenido de celdas.
- Validación de extensión, firma ZIP, estructura de libro, macros (rechazadas), tamaño y cantidad de filas.
- Celdas con posibles fórmulas (`= + - @`) se detectan, se reportan y se neutralizan al exportar CSV; React escapa todo el contenido (sin `dangerouslySetInnerHTML`) y el PDF escapa el markup.
- CORS restringido a los orígenes configurados; CSP estricta en el frontend servido; contenedor sin root, de solo lectura y publicado solo en `127.0.0.1`.

## Supuestos (requerimientos ambiguos)

- Zona horaria por defecto `America/Argentina/Buenos_Aires` (editable en la carga y en `rules.yaml`); el horario laboral y el mapa de calor usan la zona elegida al confirmar el mapeo. Los timestamps con zona explícita (p. ej. `Z`) se respetan. Fechas ambiguas `dd/mm` vs `mm/dd`: día primero por defecto, configurable en la UI. Horas ambiguas por el cambio de horario se interpretan como horario estándar y se marcan.
- Horario laboral L–V 07:00–20:00; países habituales: `SE`; redes internas RFC 1918.
- Cuentas de servicio: `svc*`, `*svc`, `sa_*`, `srv_*`, `*$`, pools de IIS. Hosts críticos: `DC*`, `*SRV*`, `WEB*`, `DB*`, `SQL*`, `APP*`, `FS*`. Grupos privilegiados: Administrators, Domain/Enterprise/Schema Admins, Account/Backup/Server Operators, DnsAdmins (y equivalentes en español).
- Período base = primera mitad del rango temporal del archivo (para «visto por primera vez» y «logon remoto nuevo»), solo si el archivo cubre ≥ 48 h. En exports de pocas horas no hay línea base: LOG-001 informa todo logon exitoso desde IP pública (excluibles con `external_ip_allowlist`) y LM-002 todo RDP/logon de red a un host crítico.
- Campos embebidos: si el export trae una columna «Destination» mixta (host, `IP:puerto`, ruta UNC), se separa en IP/puerto/host/recurso; el tipo de logon (`LogonType=10`), el host origen (`source=APP-SRV01`) y los bytes enviados (`bytes_out=…`) se extraen de la descripción o el comando cuando no tienen columna propia.
- Correlación: un servidor crítico compartido por sí solo no une incidentes (es un destino común de muchos actores); hace falta una cuenta, IP o hash en común, o un pivote explícito (PsExec/WMIC/WinRM apuntando a ese host). Ese vínculo débil se informa como hipótesis a validar.
- Un grupo de hallazgos correlacionados es *incidente candidato* si tiene ≥ 2 hallazgos o uno solo de criticidad Media o superior; el resto se informa como *hallazgo aislado* (probable falso positivo).
- Los IoCs se extraen solo de la evidencia de incidentes candidatos; los hashes de binarios en `C:\Windows` o `Program Files` no se listan.
- La UI tiene selector ES/EN; **el informe se genera en español** porque los textos del motor (resúmenes de hallazgos) están en español.
- El dataset de ejemplo es **sintético** (ver [docs/DATASET.md](docs/DATASET.md)).

## Limitaciones conocidas

- La correlación es por entidades compartidas y proximidad temporal: no detecta relaciones que no dejen rastro común en los logs (p. ej. un atacante que cambia de cuenta e IP sin pivote visible).
- Las líneas base son cortas cuando el export abarca pocos días; aumenta la probabilidad de anomalías falsas.
- La geolocalización se toma tal como viene en el Excel.
- Archivos muy grandes (cientos de miles de filas) funcionan pero el análisis puede tardar decenas de segundos; no hay procesamiento en streaming.
- El informe no reemplaza un análisis forense de los hosts.
