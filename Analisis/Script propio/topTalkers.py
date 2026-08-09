#!/usr/bin/env python3
"""
top_talkers.py — Analiza top talkers de tráfico de red.

Uso:
  python3 topTalkers.py --topHosts --Bytes --number 20
  python3 topTalkers.py --topConversations --packets
"""

import argparse
import sys
import time
import mmap
import datetime
from collections import defaultdict
import heapq

# Variables globales:
FILE_TCP_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_tcp_'
FILE_UDP_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_udp_'
FILE_ETHERNET_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_eth_'
FILE_ARP_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_arp_'
FILE_OTHER_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_other_'

#Variables globales para TCP:
COL_SRC_IP_TCP = 0   # columna 1  → índice 0
COL_DST_IP_TCP = 2   # columna 3  → índice 2
COL_SRC_PORT_TCP = 1
COL_DST_PORT_TCP = 3
COL_PKT_SD_TCP = 16  # numberPacketsSrcToDst numero de paquetes de cliente a servidor 
COL_PKT_DS_TCP = 17  # columna 18 → índice 17
COL_TCPBYTES_SD_TCP = 36  #col 33  bytesIPSrcToDst numero de paquetes de cliente a servidor 
COL_TCPBYTES_DS_TCP = 37  # col 34 bytesIPDstToSrc

#Variables globales para UDP:
COL_SRC_IP_UDP = 0   # 
COL_DST_IP_UDP = 2   #
COL_SRC_PORT_UDP= 1
COL_DST_PORT_UDP = 3
COL_PKT_SD_UDP = 6  # numberPacketsSrcToDst numero de paquetes de cliente a servidor 
COL_PKT_DS_UDP = 7  # 
COL_UDPBYTES_SD_UDP = 44  #  numero de paquetes de cliente a servidor 
COL_UDPBYTES_DS_UDP = 45  # 

#Variables globales para ARP:
COL_SRC_IP_ARP = 2   # 
COL_DST_IP_ARP = 3   #
COL_PKT_SD_ARP = 7  # numberPacketsSrcToDst numero de paquetes de cliente a servidor 
COL_PKT_DS_ARP = 8  # 
COL_PHYBYTES_SD_ARP = 9  #  numero de paquetes de cliente a servidor 
COL_PHYBYTES_DS_ARP = 10  # 

#Variables globales para OTHER (sobre IP):
COL_SRC_IP_OTHER = 0   # 
COL_DST_IP_OTHER = 1   #
COL_PKT_SD_OTHER = 5  # numberPacketsSrcToDst numero de paquetes de cliente a servidor 
COL_PKT_DS_OTHER = 6  # 
COL_IPDATABYTES_SD_OTHER = 43  #  87bytesDataIPSrcToDst numero de paquetes de cliente a servidor 
COL_IPDATABYTES_DS_OTHER = 44  # 


def parse_args():
    parser = argparse.ArgumentParser(
        description="Calcula top talkers a partir de capturas de red."
    )

    # --- Tipo de top talker (obligatorio, mutuamente excluyentes) ---
    type_group = parser.add_mutually_exclusive_group(required=True)
    type_group.add_argument(
        "--topHosts",
        action="store_true",
        help="Hosts con mayor consumo de ancho de banda (subida + bajada).",
    )
    type_group.add_argument(
        "--topSenders",
        action="store_true",
        help="Hosts que más tráfico envían.",
    )
    type_group.add_argument(
        "--topReceivers",
        action="store_true",
        help="Hosts que más tráfico reciben.",
    )
    type_group.add_argument(
        "--topConversations",
        action="store_true",
        help="Pares de hosts con más tráfico entre ellos.",
    )

    # --- Métrica de ordenación (obligatoria, mutuamente excluyentes) ---
    metric_group = parser.add_mutually_exclusive_group(required=True)
    metric_group.add_argument(
        "--Bytes",
        action="store_true",
        help="Ordenar por bytes transferidos.",
    )
    metric_group.add_argument(
        "--packets",
        action="store_true",
        help="Ordenar por número de paquetes.",
    )

    # --- Número de resultados ---
    parser.add_argument(
        "--number",
        type=int,
        default=20,
        metavar="N",
        help="Cuántos top talkers mostrar (por defecto: 20).",
    )

    return parser.parse_args()


# Validaciones cruzadas

def validate(args):
    """Comprueba combinaciones de argumentos que argparse no puede rechazar solo."""

    if args.number <= 0:
        sys.exit("Error: --number debe ser un entero positivo.")


# Lógica de cálculo 

def imprimir_top_talkers(tipoTalker, archivo, n, metric, resultados):
    print()
    print("-" * 44)
    print(f"Cálculo TOP {tipoTalker} para {archivo} ")
    print("-" * 44)
    print(f"\n{'Rank':<6} {'Host':<20} {metric:>15}")
    print("-" * 44)
    for rank, (host, paquetes) in enumerate(resultados, start=1):
        print(f"{rank:<6} {host:<20} {paquetes:>15,}")

def top_hosts_by_packets_bytes(archivo, n, colSrcIP, colDstIP, columnaDatosSD, columnaDatosDS):
    
    print(f"\nCalculando top {n} hosts...")
    conteo = defaultdict(int)   # host → total paquetes
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols   = fila.split()
                    src_ip = cols[colSrcIP].decode()
                    dst_ip = cols[colDstIP].decode()
                    pkt_sd = int(cols[columnaDatosSD])
                    pkt_ds = int(cols[columnaDatosDS])
                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue

                conteo[src_ip] += pkt_sd + pkt_ds
                conteo[dst_ip] += pkt_sd + pkt_ds
                lineas_leidas  += 1

                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

        top = heapq.nlargest(n, conteo.items(), key=lambda x: x[1])
        return top

# def top_hosts_by_packets_awk(archivo, n):
#     awk_script = """
#     {
#         conteo[$1] += $17 + $18
#         conteo[$3] += $17 + $18
#     }
#     END {
#         for (host in conteo) print conteo[host], host
#     }
#     """
#     result = subprocess.run(
#         ["awk", awk_script, archivo],
#         capture_output=True, text=True
#     )
#     lines = result.stdout.strip().split("\n")
#     pairs = [(int(l.split()[0]), l.split()[1]) for l in lines if l]
#     pairs.sort(reverse=True)
#     return [(host, count) for count, host in pairs[:n]]

def get_top_hosts(metric: str, n: int):
    """Devuelve los N hosts con mayor BW total (TX + RX)."""

    talker = "HOSTS"

    if metric == "packets":

        resultados_tcp = top_hosts_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_PKT_SD_TCP, COL_PKT_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH.split("/")[-1] , n, metric, resultados_tcp)

        resultados_udp = top_hosts_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_PKT_SD_UDP, COL_PKT_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

        resultados_arp= top_hosts_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PKT_SD_ARP, COL_PKT_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_hosts_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_PKT_SD_OTHER, COL_PKT_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

    elif metric == "bytes":
        resultados_tcp = top_hosts_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_TCPBYTES_SD_TCP, COL_TCPBYTES_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH, n, metric, resultados_tcp)

        resultados_udp = top_hosts_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_UDPBYTES_SD_UDP, COL_UDPBYTES_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

        resultados_arp= top_hosts_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PHYBYTES_SD_ARP, COL_PHYBYTES_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_hosts_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_IPDATABYTES_SD_OTHER, COL_IPDATABYTES_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

def top_senders_by_packets_bytes(archivo, n, colSrcIP, colDstIP, columnaDatosSD, columnaDatosDS):
    
    print(f"\nCalculando top {n} senders...")
    conteo = defaultdict(int)   # host → total paquetes
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols   = fila.split()
                    src_ip = cols[colSrcIP].decode()
                    dst_ip = cols[colDstIP].decode()
                    pkt_sd = int(cols[columnaDatosSD])
                    pkt_ds = int(cols[columnaDatosDS])
                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue

                conteo[src_ip] += pkt_sd 
                conteo[dst_ip] += pkt_ds
                lineas_leidas  += 1

                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

        top = heapq.nlargest(n, conteo.items(), key=lambda x: x[1])
        return top

def get_top_senders(metric: str, n: int):

    talker = "senders"
    if metric == "packets":
        resultados_tcp = top_senders_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_PKT_SD_TCP, COL_PKT_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH.split("/")[-1] , n, metric, resultados_tcp)

        resultados_udp = top_senders_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_PKT_SD_UDP, COL_PKT_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

        resultados_arp= top_senders_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PKT_SD_ARP, COL_PKT_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_senders_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_PKT_SD_OTHER, COL_PKT_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

    elif metric == "bytes":
        resultados_tcp = top_senders_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_TCPBYTES_SD_TCP, COL_TCPBYTES_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH, n, metric, resultados_tcp)

        resultados_udp = top_senders_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_UDPBYTES_SD_UDP, COL_UDPBYTES_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

        resultados_arp= top_senders_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PHYBYTES_SD_ARP, COL_PHYBYTES_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_senders_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_IPDATABYTES_SD_OTHER, COL_IPDATABYTES_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

def top_receivers_by_packets_bytes(archivo, n, colSrcIP, colDstIP, columnaDatosSD, columnaDatosDS):
    
    print(f"\nCalculando top {n} receivers...")
    conteo = defaultdict(int)   # host → total paquetes
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols   = fila.split()
                    src_ip = cols[colSrcIP].decode()
                    dst_ip = cols[colDstIP].decode()
                    pkt_sd = int(cols[columnaDatosSD])
                    pkt_ds = int(cols[columnaDatosDS])
                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue

                conteo[src_ip] += pkt_ds 
                conteo[dst_ip] += pkt_sd
                lineas_leidas  += 1

                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

        top = heapq.nlargest(n, conteo.items(), key=lambda x: x[1])
        return top

def get_top_receivers(metric: str, n: int):
    """Devuelve los N hosts que más tráfico reciben."""
    talker = "RECEIVERS"

    if metric == "packets":
        resultados_tcp = top_receivers_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_PKT_SD_TCP, COL_PKT_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH.split("/")[-1] , n, metric, resultados_tcp)

        resultados_udp = top_receivers_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_PKT_SD_UDP, COL_PKT_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

       #La parte de macs no tiene demasiado sentido, pero la dejo. Siempre será entre las ips y macs de los routers de entrada y salida 
        resultados_arp= top_receivers_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PKT_SD_ARP, COL_PKT_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_receivers_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_PKT_SD_OTHER, COL_PKT_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

    elif metric == "bytes":
        resultados_tcp = top_receivers_by_packets_bytes(FILE_TCP_PATH, n, COL_SRC_IP_TCP, COL_DST_IP_TCP, COL_TCPBYTES_SD_TCP, COL_TCPBYTES_DS_TCP)
        imprimir_top_talkers(talker, FILE_TCP_PATH, n, metric, resultados_tcp)

        resultados_udp = top_receivers_by_packets_bytes(FILE_UDP_PATH, n, COL_SRC_IP_UDP, COL_DST_IP_UDP, COL_UDPBYTES_SD_UDP, COL_UDPBYTES_DS_UDP)
        imprimir_top_talkers(talker, FILE_UDP_PATH.split("/")[-1] , n, metric, resultados_udp)

       #La parte del ethernet no la puedo hacer, me falta algún identificador aparte de las macs 

        resultados_arp= top_receivers_by_packets_bytes(FILE_ARP_PATH, n, COL_SRC_IP_ARP, COL_DST_IP_ARP, COL_PHYBYTES_SD_ARP, COL_PHYBYTES_DS_ARP)
        imprimir_top_talkers(talker, FILE_ARP_PATH.split("/")[-1] , n, metric, resultados_arp)

        resultados_other= top_receivers_by_packets_bytes(FILE_OTHER_PATH, n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER, COL_IPDATABYTES_SD_OTHER, COL_IPDATABYTES_DS_OTHER)
        imprimir_top_talkers(talker, FILE_OTHER_PATH.split("/")[-1] , n, metric, resultados_other)

def imprimir_top_conversations(archivo, n, metric, resultados):
    print()
    print("-" * 110)
    print(f"Cálculo TOP conversations para {archivo} ")
    print("-" * 110)
    print(f"\n{'Rank':<6} {'IP client':<20} {'PORT client':<18} {'IP server':<20} {'PORT server':<18} {metric:>15}")
    print("-" * 110)
    for rank, ((ip_a, port_a, ip_b, port_b), valor) in enumerate(resultados, start=1):
        print(f"{rank:<6} {ip_a:<20} {port_a:<18} {ip_b:<20} {port_b:<18} {valor:>15,}")

# def normalize_conv(src_ip, src_port, dst_ip, dst_port):
#     """
#     Normalizo la tupla para contar como instancias de un mismo flujo flujos en ambos sentidos
#     """
#     a = (src_ip, src_port)
#     b = (dst_ip, dst_port)
#     return (*(a if a<=b else b), *(b if a<=b else a))

def top_conversations_by_packets_bytes(archivo, n, colSrcIP, colDstIP, colSrcPort, colDstPort, columnaDatosSD, columnaDatosDS):
    
    """
    Agrupa el tráfico por par de IPs (conversación).
    Ambas direcciones (A→B y B→A) se fusionan en la misma clave normalizada.
    Devuelve los N pares con mayor valor total.
    """

    print(f"\nCalculando top {n} conversations...")
    conteo = defaultdict(int)   # host → total paquetes
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols   = fila.split()
                    src_ip = cols[colSrcIP].decode()
                    dst_ip = cols[colDstIP].decode()
                    src_port = cols[colSrcPort].decode() 
                    dst_port = cols[colDstPort].decode() 
                    pkt_sd = int(cols[columnaDatosSD])
                    pkt_ds = int(cols[columnaDatosDS])

                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue

                clave = (src_ip, src_port, dst_ip, dst_port)
                conteo[clave] += pkt_sd + pkt_ds
                lineas_leidas  += 1

                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

        top = heapq.nlargest(n, conteo.items(), key=lambda x: x[1])
        return top

def imprimir_top_conversations_no_ports(archivo, n, metric, resultados):
    print()
    print("-" * 110)
    print(f"Cálculo TOP conversations para {archivo} ")
    print("-" * 110)
    print(f"\n{'Rank':<6} {'IP client':<20}  {'IP server':<20} {metric:>15}")
    print("-" * 110)
    for rank, ((ip_a, ip_b), valor) in enumerate(resultados, start=1):
        print(f"{rank:<6} {ip_a:<20}{ip_b:<20} {valor:>15,}")


# def normalize_conv_no_ports(src_ip, dst_ip):
#     """
#     Normalizo la tupla para contar como instancias de un mismo flujo flujos en ambos sentidos
#     """
    
#     return ((src_ip if src_ip<=dst_ip else dst_ip), (dst_ip if src_ip<=dst_ip else src_ip))

def top_conversations_by_packets_bytes_no_ports(archivo, n, colSrcIP, colDstIP, columnaDatosSD, columnaDatosDS):
    
    """
    Agrupa el tráfico por par de IPs (conversación).
    Ambas direcciones (A→B y B→A) se fusionan en la misma clave normalizada.
    Devuelve los N pares con mayor valor total.
    No tiene en cuenta puertos porque no hay
    """

    print(f"\nCalculando top {n} conversations...")
    conteo = defaultdict(int)   # host → total paquetes
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols   = fila.split()
                    src_ip = cols[colSrcIP].decode()
                    dst_ip = cols[colDstIP].decode()
                    pkt_sd = int(cols[columnaDatosSD])
                    pkt_ds = int(cols[columnaDatosDS])

                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue

                clave = (src_ip, dst_ip)
                conteo[clave] += pkt_sd + pkt_ds
                lineas_leidas  += 1

                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

        top = heapq.nlargest(n, conteo.items(), key=lambda x: x[1])
        return top

def get_top_conversations(metric: str, n: int):
    """Devuelve los N pares de hosts con más tráfico entre ellos."""
    
    if metric == "packets":
        resultado_tcp = top_conversations_by_packets_bytes(FILE_TCP_PATH, 
                                        n, COL_SRC_IP_TCP, COL_DST_IP_TCP,
                                        COL_SRC_PORT_TCP, COL_DST_PORT_TCP,
                                        COL_PKT_SD_TCP, COL_PKT_DS_TCP)
        imprimir_top_conversations(FILE_TCP_PATH, n, metric, resultado_tcp)

        resultado_udp = top_conversations_by_packets_bytes(FILE_UDP_PATH, 
                                        n, COL_SRC_IP_UDP, COL_DST_IP_UDP,
                                        COL_SRC_PORT_UDP, COL_DST_PORT_UDP,
                                        COL_PKT_SD_UDP, COL_PKT_DS_UDP)
        imprimir_top_conversations(FILE_UDP_PATH, n, metric, resultado_udp)

        resultado_arp = top_conversations_by_packets_bytes_no_ports(FILE_ARP_PATH, 
                                        n, COL_SRC_IP_ARP, COL_DST_IP_ARP,
                                        COL_PKT_SD_ARP, COL_PKT_DS_ARP)
        imprimir_top_conversations_no_ports(FILE_ARP_PATH, n, metric, resultado_arp)

        resultados_other = top_conversations_by_packets_bytes_no_ports(FILE_OTHER_PATH, 
                                        n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER,
                                        COL_PKT_SD_OTHER, COL_PKT_DS_OTHER)
        imprimir_top_conversations_no_ports(FILE_OTHER_PATH, n, metric, resultados_other)
                                        
    elif metric == "bytes":
        resultado_tcp = top_conversations_by_packets_bytes(FILE_TCP_PATH, 
                                        n, COL_SRC_IP_TCP, COL_DST_IP_TCP,
                                        COL_SRC_PORT_TCP, COL_DST_PORT_TCP,
                                        COL_TCPBYTES_SD_TCP, COL_TCPBYTES_DS_TCP)
        imprimir_top_conversations(FILE_TCP_PATH, n, metric, resultado_tcp)

        resultado_udp = top_conversations_by_packets_bytes(FILE_UDP_PATH, 
                                        n, COL_SRC_IP_UDP, COL_DST_IP_UDP,
                                        COL_SRC_PORT_UDP, COL_DST_PORT_UDP,
                                        COL_UDPBYTES_SD_UDP, COL_UDPBYTES_DS_UDP)
        imprimir_top_conversations(FILE_UDP_PATH, n, metric, resultado_udp)

        resultado_arp = top_conversations_by_packets_bytes_no_ports(FILE_ARP_PATH, 
                                        n, COL_SRC_IP_ARP, COL_DST_IP_ARP,
                                        COL_PHYBYTES_SD_ARP, COL_PHYBYTES_DS_ARP)
        imprimir_top_conversations_no_ports(FILE_ARP_PATH, n, metric, resultado_arp)

        resultados_other = top_conversations_by_packets_bytes_no_ports(FILE_OTHER_PATH, 
                                        n, COL_SRC_IP_OTHER, COL_DST_IP_OTHER,
                                        COL_IPDATABYTES_SD_OTHER, COL_IPDATABYTES_DS_OTHER)
        imprimir_top_conversations_no_ports(FILE_OTHER_PATH, n, metric, resultados_other)
#parte de dispatch:

def compute_and_print(args):
    # Determinar la métrica activa como string para pasarla a las funciones
    if args.Bytes:
        metric = "bytes"
    elif args.packets:
        metric = "packets"
    elif args.byFlowCount:
        metric = "flow_count"

    # Llamar a la función correspondiente al tipo solicitado
    if args.topHosts:
        get_top_hosts(metric, args.number)
    elif args.topSenders:
        get_top_senders(metric, args.number)
    elif args.topReceivers:
        get_top_receivers(metric, args.number)
    elif args.topConversations:
        get_top_conversations(metric, args.number)

def main():
    args = parse_args()
    validate(args)
    compute_and_print(args)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    inicio = time.time()

    main()

    fin = time.time()
    tiempo_total = str(datetime.timedelta(seconds=fin - inicio))
    print(f"Tiempo total: {tiempo_total}")