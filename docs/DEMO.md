# Guion de demo (5 minutos)

**Preparación**: `docker compose up --build` y abrir <http://localhost:8080> (o modo dev en <http://localhost:5173>). Opcional: `.env` con `AI_API_KEY` para mostrar la IA.

---

### 0:00 – 0:30 · Contexto
> «Soy el nuevo analista SOC N2 de una consultora en Estocolmo. Un cliente nos entregó un Excel exportado de su SIEM y quiere saber si hubo un incidente. Esta herramienta trabaja solo con ese archivo, localmente, y cada conclusión queda atada a filas concretas del Excel.»

### 0:30 – 1:15 · Carga y calidad de datos
1. Clic en **«Cargar dataset de ejemplo (SINTÉTICO)»** (o arrastrar el .xlsx).
2. Mostrar las 4 hojas: la hoja `LEEME` queda excluida por no tener fecha.
3. Mostrar el **mapeo automático** (encabezados mezclados ES/EN) y cambiar uno a mano para enseñar que es editable.
4. Zona horaria: con el dataset de ejemplo se propone `Europe/Stockholm` (así se generó); para archivos propios el valor por defecto es `America/Argentina/Buenos_Aires` → **Confirmar**.
5. Señalar el reporte de calidad: **9 fechas inválidas reportadas, no descartadas**, **1 posible fórmula** detectada; abrir una fila para ver la fila original del Excel.

### 1:15 – 2:30 · Análisis y correlación
1. **Ejecutar análisis** (~2 s, sin IA).
2. Leer la **conclusión**: *2 incidentes candidatos independientes* y por qué (no comparten usuarios, hosts, IPs ni hashes; 30 h de separación).
3. Abrir **INC-01**: cadena de ataque en orden temporal (spraying → acceso VPN → ejecución → volcado de LSASS → Domain Admins → movimiento lateral → exfiltración → borrado de logs).
4. Abrir el hallazgo **EX-001**: mostrar el PowerShell **decodificado** y la tabla de **factores del puntaje**; clic en «Ver filas de evidencia».
5. Pestaña **Reglas**: todas evaluables; explicar que si falta un campo la regla queda «no evaluable» y el informe lo dice.
6. Mencionar los **hallazgos aislados** (teletrabajo fuera de horario, alta de empleado): se reportan como probables falsos positivos, no se inflan.

### 2:30 – 3:30 · Dashboard
1. KPIs y gráfico por criticidad → clic en **Crítico** (todos los widgets se filtran).
2. Línea de tiempo: el pico de las 02h del viernes (AN-001); clic en un punto → eventos crudos de esa hora.
3. **Mapa de calor**: actividad nocturna marcada con evidencia.
4. **Grafo de movimiento lateral**: WS-017 → SRV-FS01 / SRV-SQL01 / SRV-DC01; clic en una arista → filas.

### 3:30 – 4:30 · Informes
1. **Generar los informes**: se crean el ejecutivo y el técnico a la vez.
2. **Ejecutivo** (para la dirección): mostrar «En resumen» (qué pasó, si sigue habiendo riesgo y qué decidir), la matriz de impacto en el negocio y el semáforo de urgencia. Todo en lenguaje de negocio.
3. **Técnico**: alternar con el selector. Mostrar las etiquetas *Hecho observado / Inferencia / Hipótesis*, la evidencia literal con ID de fila y el anexo MITRE ATT&CK.
4. Editar un párrafo → queda marcado **«Editado por analista»**.
5. *(Con clave de Anthropic)* **Redactar con IA** sobre el técnico: los bloques aparecen como **«Generado por IA»** y se listan las afirmaciones descartadas por la validación.

### 4:30 – 5:00 · Exportación y cierre
1. **Descargar los dos PDF**: el ejecutivo (~5 páginas) y el técnico, con portada «CONFIDENCIAL», índice, gráficos, evidencia literal, «Página X de Y» y versión.
2. **Borrar datos de la sesión**.
> «Resumen: detección determinística y trazable, IA solo como redactora validada, y un informe listo para el cliente.»
