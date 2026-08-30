from __future__ import annotations
import gzip
import heapq
import io
import os
import socket
import struct
from typing import Iterable, Iterator

import dpkt

from config import PACKET_REORDER_WINDOW
from procesado.DatosPaquete import DatosPaquete

ETH_TYPE_IP = 0x0800
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


def leer_paquetes(directorio: str) -> Iterator[DatosPaquete]:
    """
    FUnción que lee los paquetes de los archivos .gz en el directorio dado y devuelve un iterador de DatosPaquete ordenados por timestamp.
    """
    yield from _leer_paquetes_sin_ordenar(directorio) #_reordenar_paquetes(_leer_paquetes_sin_ordenar(directorio))

def _leer_paquetes_sin_ordenar(directorio: str) -> Iterator[DatosPaquete]:
    """Leemos los paquetes de los .gz del directorio de entrada
    Empleamos dpkt para lectura, y luego extraemos los campos de interés directamente de los bytes crudos para mayor velocidad.
    """

    for ruta_pcap in listar_gzs(directorio):
        print(f"  Leyendo {ruta_pcap}...")
        with io.BufferedReader(gzip.GzipFile(ruta_pcap, "rb"), buffer_size=4 * 1024 * 1024) as f:
            lector = dpkt.pcap.Reader(f)
            yield from _extraer_paquetes(lector, ruta_pcap)


def leer_pcap(ruta_pcap: str) -> Iterator[DatosPaquete]:
    """Lee los paquetes IPv4 TCP/UDP de un único archivo PCAP o PCAPNG."""
    print(f"  Leyendo {ruta_pcap}...")
    with open(ruta_pcap, "rb", buffering=4 * 1024 * 1024) as archivo:
        try:
            lector = dpkt.pcap.Reader(archivo)
        except (ValueError, dpkt.dpkt.NeedData):
            archivo.seek(0)
            lector = dpkt.pcapng.Reader(archivo)
        yield from _extraer_paquetes(lector, ruta_pcap)


def _extraer_paquetes(lector, ruta_pcap: str) -> Iterator[DatosPaquete]:
    if lector.datalink() != dpkt.pcap.DLT_EN10MB:
        raise ValueError(
            f"Linktype no soportado en {ruta_pcap}: {lector.datalink()} "
            "(se asume Ethernet)"
        )

    for timestamp, buf in lector:
        if len(buf) < 34:  # 14 (Ethernet) + 20 (IP mínimo)
            continue

        if (buf[12] << 8 | buf[13]) != ETH_TYPE_IP:
            continue

        ip_start = 14
        proto = buf[ip_start + 9]
        if proto != IP_PROTO_TCP and proto != IP_PROTO_UDP:
            continue

        frag_offset = struct.unpack_from("!H", buf, ip_start + 6)[0] & 0x1FFF
        if frag_offset != 0:
            continue

        ihl = (buf[ip_start] & 0x0F) * 4
        l4_start = ip_start + ihl
        if len(buf) < l4_start + 4:
            continue

        dst_port, = struct.unpack_from("!H", buf, l4_start + 2)

        yield DatosPaquete(
            tStart=float(timestamp),
            srcIp=socket.inet_ntoa(buf[ip_start + 12: ip_start + 16]),
            dstIp=socket.inet_ntoa(buf[ip_start + 16: ip_start + 20]),
            dstPort=dst_port,
            ruta_pcap=ruta_pcap,
        )


def listar_pcaps(directorio: str) -> list[str]:
    """Lista PCAP y PCAPNG recursivamente."""
    rutas = []
    for raiz, _, nombres in os.walk(directorio):
        for nombre in nombres:
            if nombre.lower().endswith((".pcap", ".pcapng")):
                rutas.append(os.path.join(raiz, nombre))
    return sorted(rutas)

def listar_gzs(directorio: str) -> list[str]:
    """Devuelve las rutas de los .gz del directorio, ordenadas por su timestamp (p. ej. 1513677548.gz)."""
    archivos = [f for f in os.listdir(directorio) if f.lower().endswith(".gz")]
    if not archivos:
        raise ValueError(f"No se encontraron archivos .gz en {directorio}")

    archivos.sort(key=lambda f: int(f.split(".")[0]))
    return [os.path.join(directorio, f) for f in archivos]

def _reordenar_paquetes(
    paquetes: Iterable[DatosPaquete],
    ventana: float = PACKET_REORDER_WINDOW,
) -> Iterator[DatosPaquete]:
    """Esta función reordena los paquetes ligeramente desordenados en el tiempo, 
        usando una ventana de tiempo para determinar cuándo un paquete puede ser 
        emitido de forma segura.
        1. Llega un paquete.
        2. Se guarda en el heap.
        3. Se calcula:
            watermark = mayor_timestamp_visto - ventana
        4. Se emiten los paquetes más antiguos que el watermark.
        5. Los demás permanecen esperando.
    """
    
    buffer: list[tuple[float, int, DatosPaquete]] = [] # almacena los paquetes que no se han podido emitir, como tuplas (timestamp, orden, paquete) para mantener el orden de llegada en caso de timestamps iguales
    maximo_timestamp = float("-inf") #guarda el timestamp más grande visto hasta ahora, para poder calcular la marca de agua (watermark) y decidir cuándo un paquete puede ser emitido
    ultimo_emitido = float("-inf") # Guarda el timestamp del último paquete que ya salió de la función.

    for orden, paquete in enumerate(paquetes):
        if paquete.tStart < ultimo_emitido:
            raise ValueError(
                f"Desorden temporal superior a {ventana} segundos: "
                f"{paquete.tStart} < {ultimo_emitido}"
            )
        # Si llega un paquete con un timestamp menor que el último timestamp que ya se había 
        # emitido, significa que el reordenador ya no puede colocarlo correctamente.

        maximo_timestamp = max(maximo_timestamp, paquete.tStart)
        heapq.heappush(buffer, (paquete.tStart, orden, paquete)) #heapq mantiene el buffer ordenado por timestamp y luego por orden de llegada (para mantener el orden original en caso de timestamps iguales)
        marca_de_agua = maximo_timestamp - ventana

        while buffer and buffer[0][0] <= marca_de_agua: #los paquetes en el buffer con timestamp menor o igual a la marca de agua ya pueden ser emitidos, porque no hay posibilidad de que llegue un paquete con un timestamp menor que ellos
            _, _, paquete_ordenado = heapq.heappop(buffer) #  elimina el paquete más pequeño del heap:
            ultimo_emitido = paquete_ordenado.tStart
            yield paquete_ordenado

    while buffer:
        _, _, paquete_ordenado = heapq.heappop(buffer)
        yield paquete_ordenado
        #Cuando ya no quedan más paquetes de entrada, no puede esperar a que llegue ninguno posterior. Por eso vacía todo lo que queda en el búfer y lo entrega ordenado.
