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
            # if lector.datalink() != dpkt.pcap.DLT_EN10MB:
            #     raise ValueError(f"Linktype no soportado en {ruta_pcap}: {lector.datalink()} (se asume Ethernet)")
            #     # para ver si el tipo de enlace es ethernet, que es lo que se asume en el slicing de bytes más abajo (offsets fijos para cabeceras Ethernet/IP/TCP/UDP)
            
            for timestamp, buf in lector:
                if len(buf) < 34:  # 14 (Ethernet) + 20 (IP mínimo)
                    # print(f"  Ignorando paquete en {ruta_pcap} por tener pequeño: (tamaño={len(buf)})")
                    continue

                if (buf[12] << 8 | buf[13]) != ETH_TYPE_IP: # obtengo el ethertype
                    # print(f"  Ignorando paquete en {ruta_pcap} (ethertype={buf[12] << 8 | buf[13]})")
                    continue

                ip_start = 14
                proto = buf[ip_start + 9]
                if proto != IP_PROTO_TCP and proto != IP_PROTO_UDP:
                    # print(f"  Ignorando paquete en {ruta_pcap} (protocolo={proto})")
                    continue

                frag_offset = struct.unpack_from("!H", buf, ip_start + 6)[0] & 0x1FFF
                if frag_offset != 0:
                    # print(f"  Ignorando fragmento IP en {ruta_pcap} (offset={frag_offset})")
                    continue  # fragmento no inicial: no lleva cabecera TCP/UDP
                """se lee el campo fragment offset (bytes 6-7 de la cabecera IP, quedándonos con los 13 bits bajos vía & 0x1FFF) y 
                se descarta el paquete si no es 0 (es decir, si no es el primer fragmento) — esos 
                fragmentos no llevan cabecera TCP/UDP y antes se habrían leído como puerto destino 
                datos que en realidad son payload."""


                ihl = (buf[ip_start] & 0x0F) * 4 # me quedo con el tamaño de la cabecera IP (en bytes)
                l4_start = ip_start + ihl # me quedo con el offset del inicio de la cabecera TCP/UDP
                if len(buf) < l4_start + 4:  # 4 bytes para srcPort y dstPort
                    continue

                dst_port, = struct.unpack_from("!H", buf, l4_start + 2) # obtengo el puerto destino (2 bytes, big-endian)

                yield DatosPaquete(
                    tStart=float(timestamp),
                    srcIp=socket.inet_ntoa(buf[ip_start + 12: ip_start + 16]),
                    dstIp=socket.inet_ntoa(buf[ip_start + 16: ip_start + 20]),
                    dstPort=dst_port,
                    ruta_pcap=ruta_pcap,
                )

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
