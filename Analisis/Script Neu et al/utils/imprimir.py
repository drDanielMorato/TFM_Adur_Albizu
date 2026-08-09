from __future__ import annotations
from procesado import Candidato

def imprimir_resultado(sospechosos: list[Candidato], ruta_archivo_resultado: str) -> None:
    """Imprime las conversaciones sospechosas en el archivo ruta_archivo_resultado"""

    with open(ruta_archivo_resultado, "w", encoding="utf-8", buffering=1024 * 1024) as f:
        for candidato in sospechosos:             
            f.write((f"{str(candidato)}\n")) 