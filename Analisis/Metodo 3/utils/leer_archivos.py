from __future__ import annotations
from config import PATRON_TCP, PATRON_UDP, VENTANA_REORDENADO
from typing import Iterator
import heapq
import mmap
import os

def localizar_archivos_flujos(ruta_directorio: str) -> tuple[str, str]:
    """
    Busca en ruta_directorio el archivo de flujos TCP y el de flujos UDP, identificados
    porque su nombre contiene PATRON_TCP y PATRON_UDP respectivamente.
    Devuelve la pareja de rutas (archivo TCP, archivo UDP).
    """
    archivos_tcp = []
    archivos_udp = []

    for nombre in os.listdir(ruta_directorio):
        ruta = os.path.join(ruta_directorio, nombre)
        if not os.path.isfile(ruta):
            continue
        if PATRON_TCP in nombre:
            archivos_tcp.append(ruta)
        elif PATRON_UDP in nombre:
            archivos_udp.append(ruta)

    if len(archivos_tcp) != 1:
        raise RuntimeError(f"Se esperaba un único archivo con '{PATRON_TCP}' en {ruta_directorio}, encontrados: {archivos_tcp}")
    if len(archivos_udp) != 1:
        raise RuntimeError(f"Se esperaba un único archivo con '{PATRON_UDP}' en {ruta_directorio}, encontrados: {archivos_udp}")

    return archivos_tcp[0], archivos_udp[0]

def localizar_archivos_flujos_opcionales(ruta_directorio: str) -> tuple[str | None, str | None]:
    """
    Igual que localizar_archivos_flujos, pero permite que falte TCP o UDP.
    """
    archivos_tcp = []
    archivos_udp = []

    for nombre in os.listdir(ruta_directorio):
        ruta = os.path.join(ruta_directorio, nombre)
        if not os.path.isfile(ruta):
            continue
        if PATRON_TCP in nombre:
            archivos_tcp.append(ruta)
        elif PATRON_UDP in nombre:
            archivos_udp.append(ruta)

    if len(archivos_tcp) > 1:
        raise RuntimeError(f"Se esperaba como mucho un archivo con '{PATRON_TCP}' en {ruta_directorio}, encontrados: {archivos_tcp}")
    if len(archivos_udp) > 1:
        raise RuntimeError(f"Se esperaba como mucho un archivo con '{PATRON_UDP}' en {ruta_directorio}, encontrados: {archivos_udp}")

    archivo_tcp = archivos_tcp[0] if archivos_tcp else None
    archivo_udp = archivos_udp[0] if archivos_udp else None
    return archivo_tcp, archivo_udp

def leer_registros_flujo_ordenados(
    ruta_archivo: str,
    columna_timestamp: int,
    ventana: float = VENTANA_REORDENADO,
) -> Iterator[tuple[float, list[bytes]]]:
    """
    Lee el archivo de registros de flujo y los va devolviendo troceados en columnas y ordenados
    por el timestamp de la columna columna_timestamp, porque el archivo de entrada no está
    ordenado. Para ello emplea un buffer con marca de agua (watermark):
        1. Llega un registro de flujo.
        2. Se guarda en el heap.
        3. Se calcula:
            marca_de_agua = mayor_timestamp_visto - ventana
        4. Se emiten los registros de flujo más antiguos que la marca de agua.
        5. Los demás permanecen esperando.
    """

    buffer: list[tuple[float, int, list[bytes]]] = [] # registros de flujo que todavía no se pueden emitir, como tuplas (timestamp, orden, columnas) para mantener el orden de llegada en caso de timestamps iguales
    maximo_timestamp = float("-inf") # timestamp más grande visto hasta ahora, con el que se calcula la marca de agua
    ultimo_emitido = float("-inf") # timestamp del último registro de flujo que ya salió de la función

    with open(ruta_archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            orden = 0
            while True:
                registroFlujo = mm.readline()
                if not registroFlujo:        # fin del archivo
                    break

                cols = registroFlujo.split()
                try:
                    timestamp = float(cols[columna_timestamp])
                except (IndexError, ValueError) as e:
                    raise RuntimeError(f"  ERROR: {e} | línea: {registroFlujo[:80]}")

                if timestamp < ultimo_emitido:
                    raise ValueError(
                        f"Desorden temporal superior a {ventana} segundos: "
                        f"{timestamp} < {ultimo_emitido}"
                    )

                maximo_timestamp = max(maximo_timestamp, timestamp)
                heapq.heappush(buffer, (timestamp, orden, cols)) #heapq mantiene el buffer ordenado por timestamp y luego por orden de llegada
                orden += 1

                marca_de_agua = maximo_timestamp - ventana
                while buffer and buffer[0][0] <= marca_de_agua: #estos registros de flujo ya no pueden ser adelantados por ninguno posterior
                    timestamp_emitido, _, cols_emitidas = heapq.heappop(buffer)
                    ultimo_emitido = timestamp_emitido
                    yield timestamp_emitido, cols_emitidas

            while buffer:
                #Al acabar el archivo ya no puede llegar nada anterior, así que se vacía el buffer en orden
                timestamp_emitido, _, cols_emitidas = heapq.heappop(buffer)
                yield timestamp_emitido, cols_emitidas

def obtener_lista_archivos_pcap (directorio : str) -> list[str] :
    # Devuelve las rutas de los archivos pcap a analizar
    return [
        f for f in os.listdir(directorio)
        if os.path.isfile(os.path.join(directorio, f))
    ]
