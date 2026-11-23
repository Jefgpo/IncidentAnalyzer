"""Lectura segura del .xlsx en memoria (nunca se escribe a disco)."""
from __future__ import annotations

import io
import zipfile

import pandas as pd

from app import settings

XLSX_MAGIC = b"PK\x03\x04"


class UploadError(ValueError):
    """Error de validación del archivo subido (se muestra al usuario)."""


def validate_upload(filename: str, data: bytes) -> None:
    if not filename.lower().endswith(".xlsx"):
        raise UploadError("Solo se aceptan archivos .xlsx (Excel 2007+).")
    size_mb = len(data) / (1024 * 1024)
    if size_mb > settings.MAX_UPLOAD_MB:
        raise UploadError(f"El archivo pesa {size_mb:.1f} MB; el máximo permitido es {settings.MAX_UPLOAD_MB:.0f} MB.")
    if not data.startswith(XLSX_MAGIC):
        raise UploadError("El contenido no corresponde a un .xlsx válido (firma ZIP ausente).")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "[Content_Types].xml" not in names or not any(n.startswith("xl/") for n in names):
                raise UploadError("El ZIP no contiene la estructura de un libro de Excel.")
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                raise UploadError("El libro contiene macros (VBA); no se procesa por seguridad.")
            # Protección básica contra "zip bombs"
            total = sum(i.file_size for i in zf.infolist())
            if total > 40 * len(data) and total > 300 * 1024 * 1024:
                raise UploadError("El archivo descomprimido es anormalmente grande.")
    except zipfile.BadZipFile as exc:
        raise UploadError("El archivo está dañado o no es un .xlsx.") from exc


def read_workbook(data: bytes) -> dict[str, pd.DataFrame]:
    """Devuelve {hoja: DataFrame} con todas las celdas como objetos (sin inferir tipos agresivamente)."""
    try:
        sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, engine="openpyxl", dtype=object)
    except Exception as exc:  # openpyxl lanza tipos variados
        raise UploadError("No se pudo leer el libro de Excel.") from exc
    out: dict[str, pd.DataFrame] = {}
    total_rows = 0
    for name, df in sheets.items():
        df = df.dropna(how="all")
        df.columns = [str(c).strip() if not str(c).startswith("Unnamed:") else f"Columna_{i + 1}"
                      for i, c in enumerate(df.columns)]
        total_rows += len(df)
        out[str(name)] = df
    if total_rows > settings.MAX_ROWS:
        raise UploadError(f"El libro tiene {total_rows} filas; el máximo es {settings.MAX_ROWS}.")
    if not out:
        raise UploadError("El libro no contiene hojas con datos.")
    return out
