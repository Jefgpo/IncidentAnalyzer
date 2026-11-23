# Arquitectura

```
Navegador (React)                      FastAPI (memoria del proceso)
┌───────────────────────┐   /api/*    ┌──────────────────────────────────────────────┐
│ Cargar → Analizar →   │ ──────────▶ │ ingest: reader → mapper → normalizer          │
│ Dashboard → Informe → │             │            ↓ eventos canónicos (row_id)       │
│ Exportar              │ ◀────────── │ detection: 34 reglas → hallazgos              │
└───────────────────────┘    JSON/PDF │ correlation → incidentes + conclusión          │
                                      │ scoring → criticidad reproducible               │
                                      │ iocs → indicadores con filas                    │
                                      │ analytics → dashboard / filtros                 │
                                      │ report → informe por bloques                    │
                                      │ ai (opcional) → Claude + validador              │
                                      │ pdf → ReportLab + matplotlib                    │
                                      └──────────────────────────────────────────────┘
```

## Flujo de datos

1. **Lectura** (`ingest/reader.py`): el .xlsx se valida (extensión, firma ZIP, estructura, sin macros, tamaño, filas) y se lee en memoria con `openpyxl`.
2. **Mapeo** (`ingest/mapper.py`): encabezados normalizados (sin tildes, minúsculas) contra sinónimos ES/EN (`config/synonyms.yaml`), similitud difusa y heurística por contenido (fechas, IPs). El analista corrige en la UI.
3. **Normalización** (`ingest/normalizer.py`): cada hoja seleccionada se proyecta al esquema canónico (todos los campos opcionales), con `row_id = Hoja!fila_excel`. Los timestamps se parsean (nativo Excel, serial, epoch, ISO con/sin zona, `dd/mm/aaaa`) y se localizan en la zona del cliente; las filas inválidas se conservan con `issues`. Se deriva una semántica (`auth_ok`, `auth_fail`, `group_add`, …) desde EventID o desde la columna de resultado.
4. **Detección** (`detection/`): `Context` ofrece utilidades comunes (IP interna/externa, cuenta de servicio/privilegiada en el tiempo, host crítico, horario, período base). Cada `Rule` declara campos requeridos; si faltan, queda *no evaluable*. Cada `Finding` guarda las filas exactas, entidades vinculantes y relacionadas, métricas, notas de falso positivo y detalle técnico (p. ej. PowerShell decodificado).
5. **Correlación** (`correlation/correlator.py`): grafo de hallazgos no anómalos; arista si comparten usuario/host/IP/hash a ≤ 24 h (las entidades presentes en > 30 % de todos los eventos no vinculan). Componentes conexos → incidentes; las anomalías se adjuntan como contexto. Para cada incidente: fases MITRE en orden temporal, línea de tiempo de filas, vínculos con filas de soporte y puntaje. La conclusión «uno/varios» lista los vínculos y la ausencia de entidades comunes.
6. **Informe** (`report/builder.py`): bloques tipados con `origin` (determinista/ia/editado) y `kind` (hecho observado/inferencia/hipótesis/recomendación). Las tablas de evidencia reproducen celdas literales.
7. **IA** (`ai/`): contexto acotado → Claude con salida JSON → `Validator` (filas existentes, pertenencia a la evidencia, entidades presentes) → fusión en el informe; lo rechazado queda en `ai_review`.
8. **PDF** (`pdf/`): portada, índice (`TableOfContents` + `multiBuild`), encabezado/pie con clasificación y «Página X de Y», tablas con anchos adaptativos y gráficos matplotlib calculados con `analytics/dashboard.py`.

## API

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/health` | Estado y si la IA está habilitada |
| GET | `/api/rules` | Catálogo de reglas y metodología |
| POST | `/api/upload` · `/api/upload/sample` | Carga del .xlsx (o del dataset sintético) |
| POST | `/api/sessions/{id}/mapping` | Confirma mapeo y zona horaria → calidad de datos |
| GET | `/api/sessions/{id}/events` | Eventos paginados (`q`, `sort`, `order`, filtros, `finding`, `incident`, `rows`) |
| POST/GET | `/api/sessions/{id}/analyze` · `/analysis` | Ejecuta / obtiene el análisis |
| GET | `/api/sessions/{id}/dashboard` | Agregados con filtros globales |
| POST/GET | `/api/sessions/{id}/report/generate` · `/report` | Informe determinístico |
| PUT | `/api/sessions/{id}/report/blocks/{block}` · `/report/meta` | Edición manual |
| POST | `/api/sessions/{id}/report/ai` · `/ai/chat` | Redacción y chat con IA (validados) |
| POST | `/api/sessions/{id}/export/pdf` | PDF |
| GET | `/api/sessions/{id}/export/iocs.csv` | IoCs en CSV (fórmulas neutralizadas) |
| GET | `/api/intel/status` | Proveedores de reputación configurados por variable de entorno |
| POST/GET/DELETE | `/api/sessions/{id}/intel` | Inicia / consulta el progreso / detiene la reputación de IPs |
| GET | `/api/sessions/{id}/intel/candidates` | IPs públicas candidatas y las omitidas con su motivo |
| DELETE | `/api/sessions/{id}` | Borra todos los datos de la sesión |

Documentación interactiva en `/api/docs`.
