from __future__ import annotations
import gzip
import io
import os
import socket
import struct
from typing import Iterator

import dpkt

from procesado.DatosPaquete import DatosPaquete

ETH_TYPE_IP = 0x0800
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


def listar_gzs(directorio: str) -> list[str]:
    """Devuelve las rutas de los .gz del directorio, ordenadas por su timestamp (p. ej. 1513677548.gz)."""
    archivos = [f for f in os.listdir(directorio) if f.lower().endswith(".gz")]
    if not archivos:
        raise ValueError(f"No se encontraron archivos .gz en {directorio}")

    archivos.sort(key=lambda f: int(f.split(".")[0]))
    return [os.path.join(directorio, f) for f in archivos]


def leer_paquetes(directorio: str) -> Iterator[DatosPaquete]:
    """
    Generador que recorre en orden los .gz del directorio y cede un Flujo por cada paquete
    TCP o UDP encontrado (uno por paquete, sin filtrar por flags).
    Cada pcap se lee en streaming (dpkt.pcap.Reader no lo carga entero en memoria), por lo que
    archivos de varios GB pueden procesarse con un consumo de memoria mínimo.
    Los campos se extraen con slicing/struct directamente sobre los bytes crudos en vez de
    construir objetos dpkt.ethernet.Ethernet/dpkt.ip.IP/dpkt.tcp.TCP/dpkt.udp.UDP por paquete, que es
    bastante más lento por el coste de crear y parsear esos objetos (incluidas las opciones TCP).
    """

    for ruta_pcap in listar_gzs(directorio):
        print(f"  Leyendo {ruta_pcap}...")
        with io.BufferedReader(gzip.GzipFile(ruta_pcap, "rb"), buffer_size=4 * 1024 * 1024) as f:
            lector = dpkt.pcap.Reader(f)
            if lector.datalink() != dpkt.pcap.DLT_EN10MB:
                raise ValueError(f"Linktype no soportado en {ruta_pcap}: {lector.datalink()} (se asume Ethernet)")

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
                    tStart=timestamp,
                    srcIp=socket.inet_ntoa(buf[ip_start + 12: ip_start + 16]),
                    dstIp=socket.inet_ntoa(buf[ip_start + 16: ip_start + 20]),
                    dstPort=dst_port,
                )

