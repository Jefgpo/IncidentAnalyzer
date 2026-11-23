from __future__ import annotations

import os
import sys
import tempfile
import warnings
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[2]
# Las sesiones de los tests se guardan cifradas en un directorio temporal (nunca en el repo)
os.environ.setdefault("SESSION_STORE", "disk")
os.environ["SESSION_DIR"] = tempfile.mkdtemp(prefix="soc-test-sessions-")
sys.path.insert(0, str(ROOT / "backend"))
warnings.filterwarnings("ignore", category=UserWarning)

from app.detection.engine import run_analysis  # noqa: E402
from app.ingest.mapper import suggest_mapping  # noqa: E402
from app.ingest.normalizer import build_events  # noqa: E402
from app.ingest.reader import read_workbook  # noqa: E402

SAMPLE = ROOT / "sample_data" / "SINTETICO_logs_cliente.xlsx"
TZ = "Europe/Stockholm"


@pytest.fixture(scope="session")
def sample_bytes() -> bytes:
    if not SAMPLE.exists():
        import subprocess
        subprocess.run([sys.executable, str(ROOT / "sample_data" / "generate_synthetic.py")], check=True)
    return SAMPLE.read_bytes()


def auto_events(sheets: dict[str, pd.DataFrame]):
    sels = []
    for name, df in sheets.items():
        mapping, _ = suggest_mapping(df)
        if "timestamp" in mapping:
            sels.append({"name": name, "mapping": mapping})
    return build_events(sheets, sels, TZ)


@pytest.fixture(scope="session")
def sample_events(sample_bytes):
    return auto_events(read_workbook(sample_bytes))


@pytest.fixture(scope="session")
def analysis(sample_events):
    events, _ = sample_events
    return run_analysis(events)


def make_events(rows: list[dict]):
    """Construye eventos a partir de filas sintéticas mínimas (para casos benignos/unitarios)."""
    df = pd.DataFrame(rows)
    mapping = {c: c for c in df.columns}
    return build_events({"T": df}, [{"name": "T", "mapping": mapping}], TZ)[0]
