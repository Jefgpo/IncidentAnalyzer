#!/usr/bin/env bash
# IncidentAnalyzer - arranque en modo desarrollo (Linux / macOS / Git Bash)
#
#   ./run.sh          prepara el entorno la primera vez y levanta backend + frontend
#   ./run.sh test     corre los tests del backend y del frontend
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Falta '$1'. $2" >&2; exit 1; }; }
PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || { echo "Falta Python 3.11+: https://www.python.org/downloads/" >&2; exit 1; }
need npm "Instalá Node.js 20+ desde https://nodejs.org/"

if [ -d "$ROOT/backend/.venv/Scripts" ]; then PY="$ROOT/backend/.venv/Scripts/python"; else PY="$ROOT/backend/.venv/bin/python"; fi
if [ ! -x "$PY" ] && [ ! -x "$PY.exe" ]; then
  echo "Creando entorno virtual de Python e instalando dependencias..."
  "$PYTHON" -m venv "$ROOT/backend/.venv"
  if [ -d "$ROOT/backend/.venv/Scripts" ]; then PY="$ROOT/backend/.venv/Scripts/python"; else PY="$ROOT/backend/.venv/bin/python"; fi
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet -r "$ROOT/backend/requirements-dev.txt"
fi
[ -d "$ROOT/frontend/node_modules" ] || (cd "$ROOT/frontend" && npm install --no-audit --no-fund)
if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "Se creó .env a partir de .env.example (las claves de IA y AbuseIPDB son opcionales)."
fi

if [ "${1:-}" = "test" ]; then
  (cd "$ROOT/backend" && "$PY" -m pytest -q)
  (cd "$ROOT/frontend" && npm test && npm run build)
  exit 0
fi

echo "Levantando backend (puerto 8000) y frontend (puerto 5173). Ctrl+C para detener."
(cd "$ROOT/backend" && "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload) &
BACKEND=$!
trap 'kill $BACKEND 2>/dev/null || true' EXIT INT TERM
cd "$ROOT/frontend" && npm run dev
