from __future__ import annotations
from config import COL_START_TIME, PATRON_TCP, VENTANA_REORDENADO
from typing import Iterator
import heapq
import mmap
import os


def localizar_archivo_tcp(ruta_directorio: str) -> str:
    """Devuelve el único archivo TCP cuyo nombre contiene PATRON_TCP."""
    archivos_tcp = []

    for nombre in os.listdir(ruta_directorio):
        ruta = os.path.join(ruta_directorio, nombre)
        if os.path.isfile(ruta) and PATRON_TCP in nombre:
            archivos_tcp.append(ruta)

    if len(archivos_tcp) != 1:
        raise RuntimeError(
            f"Se esperaba un único archivo con '{PATRON_TCP}' en "
            f"{ruta_directorio}, encontrados: {archivos_tcp}"
        )

    return archivos_tcp[0]


def leer_registros_flujo_tcp_ordenados(
    ruta_archivo: str,
    ventana: float = VENTANA_REORDENADO,
) -> Iterator[tuple[float, list[bytes]]]:
    """Lee registros TCP y los emite ordenados mediante un buffer con watermark."""
    buffer: list[tuple[float, int, list[bytes]]] = []
    maximo_timestamp = float("-inf")
    ultimo_emitido = float("-inf")

    with open(ruta_archivo, "rb") as archivo:
        with mmap.mmap(archivo.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            orden = 0
            while True:
                registro_flujo = mm.readline()
                if not registro_flujo:
                    break

                columnas = registro_flujo.split()
                try:
                    timestamp = float(columnas[COL_START_TIME])
                except (IndexError, ValueError) as error:
                    raise RuntimeError(
                        f"ERROR: {error} | linea: {registro_flujo[:80]}"
                    ) from error

                if timestamp < ultimo_emitido:
                    raise ValueError(
                        f"Desorden temporal superior a {ventana} segundos: "
                        f"{timestamp} < {ultimo_emitido}"
                    )

                maximo_timestamp = max(maximo_timestamp, timestamp)
                heapq.heappush(buffer, (timestamp, orden, columnas))
                orden += 1

                marca_de_agua = maximo_timestamp - ventana
                while buffer and buffer[0][0] <= marca_de_agua:
                    timestamp_emitido, _, columnas_emitidas = heapq.heappop(buffer)
                    ultimo_emitido = timestamp_emitido
                    yield timestamp_emitido, columnas_emitidas

            while buffer:
                timestamp_emitido, _, columnas_emitidas = heapq.heappop(buffer)
                ultimo_emitido = timestamp_emitido
                yield timestamp_emitido, columnas_emitidas
