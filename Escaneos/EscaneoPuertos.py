from __future__ import annotations # don't execute type hints, just store them as text strings
import time
import datetime
import mmap
import math
from dataclasses import dataclass, field
from collections import defaultdict
import ipaddress
import numpy as np
from collections import Counter
import bisect

# Variables globales archivos:
# FILE_TCP_PATH =  "/opt3/proyectistas/adur.albizu/Desktop/tarea_03_03/scripts - parámetros por separado/EscaneoPuertosAdicional/logsProcesaConexiones/salida1_tcp_"
FILE_TCP_PATH = '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_tcp_'
FILE_UDP_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_udp_'
FILE_ETHERNET_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_eth_'
FILE_ARP_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_arp_'
FILE_OTHER_PATH =  '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/salida_topTalkers_other_'

COL_SRC_IP_TCP = 0   # Direccion IP del cliente de la conexion
COL_SRC_PORT_TCP = 1 # Puerto empleado por el cliente 
COL_DST_IP_TCP = 2   # Direccion IP del servidor de la conexion
COL_DST_PORT_TCP = 3 # Puerto empleado por el servidor 

COL_FIRSTPACKETTIME_TCP = 4 # timestamp del primer paquete de la conexion
COL_LASTPACKETTIME_TCP = 5 # timestamp del ultimo paquetes de la conexion
COL_LASTSRC2DST_TCP = 14 # timestamp del ultimo paquete de cliente a servidor  
COL_LASTDST2SRC_TCP = 15 # timestamp del ultimo paquete de servidor a cliente

COL_NUMPACKETS_SRC2DST_TCP = 16 # numero de paquetes de cliente a servidor (*1)
COL_NUMPACKETS_DST2SRC_TCP = 17 # numero de paquetes de servidor a cliente (*1)
COL_NUMSYNS_SRC2DST_TCP =  18 # numero de SYNs de cliente a servidor (*1)
COL_NUMSYNS_DST2SRC_TCP =  19 # numero de SYNs de servidor a cliente (*1)
COL_NUMFINS_SRC2DST_TCP =  20 # numero de FINs de cliente a servidor
COL_NUMFINS_DST2SRC_TCP =  21 # numero de FINs de servidor a cliente
COL_NUMRST_SRC2DST_TCP =  22 #  numero de RSTs de cliente a servidor 
COL_NUMRST_DST2SRC_TCP =  23 #  numero de RSTs de servidor a cliente
COL_NUMPACKETSDATA_SRC2DST_TCP = 24 # numero de paquetes con datos de cliente a servidor (*1)
COL_NUMPACKETSDATA_DST2SRC_TCP = 25 # numero de paquetes con datos de servidor a cliente (*1)

# Los usaré para detectar ACKs:
COL_FIRSTACK_SRC2DST_TIME_TCP = 8 #timestamp del primer ACK de cliente a servidor (-1 si no hay tal paquete)
COL_FIRSTACK_DST2SRC_TIME_TCP = 9#timestamp del primer ACK del servidor al cliente (-1 si no hay tal paquete)  

COL_TCPBYTES_SD_TCP = 36  #bytesIPSrcToDst numero de paquetes de cliente a servidor 
COL_TCPBYTES_DS_TCP = 37  #bytesIPDstToSrc

COL_FIRSTPACKETFLAGS_TCP = 48 # Flags del primer paquete que se ve (en hexadecimal), que si hay desorden puede no ser el primero de la conexion. 

LIMITE_PUERTOS= 10 #Limite por debajo del cual supongo más dudoso un escaneo de puertos

#Rangos internos IP de la uni: 130.206.158.0 - 130.206.175.255
RANGOS_INTERNOS =["130.206.158.0/23", #130.206.158.0 - 130.206.159.255 
                  "130.206.160.0/20"] #130.206.160.0 - 130.206.175.255

REDES_INTERNAS = [ipaddress.ip_network(r, strict=False) for r in RANGOS_INTERNOS]

# Pesos para estimar cómo de sospechosa es una conversación:
W_P=6
W_H=2
W_R=2

#Umbral para decidir si una conversación es sospechosa 
THRESHOLD = 0.52

# Para agilizar:
_cache_ips = {}

@dataclass
class FlowData:
    # Lista de todos los puertos vistos en este flujo (dst)
    puertos: list[str] = field(default_factory=list)
    # Lista que ocntiene solamente puertos únicos, _ para variable privada 
    puertosUnicos: set = field(default_factory=set)

    # Registros detallados de cada conexión individual, ordenados por t_inicio
    # Cada tupla: (t_inicio, t_fin, puerto_origen, puerto_destino)
    conexiones: list[tuple[float, float, str, str]] = field(default_factory=list)

    #Computaciones finales
    p: float | None = None  # Numero de puertos únicos normalizados
    h: float | None = None  # Entropia de Shannon normalizada
    d: float | None = None  # Desviación estándar del tiempo entre conexiones normalizada 1/(1+CV)

    puntuacion: float | None = None # Puntúa cómo de sospechosa es una interacción entre dos ips.   

    #Métodos
    def update(self, puerto_src: str,
               puerto_dst: str, 
               t_inicio: float, t_fin 
               ) -> None:

        """Registra una nueva conversación entre dos mismas ips"""
        self.puertos.append(puerto_dst)
        self.puertosUnicos.add(puerto_dst)

        entrada = (t_inicio, t_fin, puerto_src, puerto_dst)
        bisect.insort(self.conexiones, entrada)


def esIpInterna(src_ip: str) -> bool:
    if src_ip in _cache_ips:
        return _cache_ips[src_ip]

    addr = ipaddress.ip_address(src_ip)
    resultado = any(addr in red for red in REDES_INTERNAS)
    _cache_ips[src_ip] = resultado
    return resultado

def seDebeAniadirConversacion(dst_ip, total_tcp_data, 
                             number_syns_sd) -> bool:

    return (
            (esIpInterna(dst_ip)))

def preprocesado(archivo) -> dict:
    """
    Preparo la matriz necesaria para el procesado.
    Incluye todas las parejas de ips, con info como el timestamp de inicio de cada flujo perteneciente
    a la pareja, cuántos puertos se han atacado.
    """
    print(f"\nPreprocesando...")
    conversaciones = defaultdict(FlowData)   
    lineas_leidas = 0

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    
                    cols = fila.split()

                    src_ip   = cols[COL_SRC_IP_TCP].decode()
                    dst_ip   = cols[COL_DST_IP_TCP].decode()
                    src_port = cols[COL_SRC_PORT_TCP].decode()
                    dst_port = cols[COL_DST_PORT_TCP].decode()

                    # Tiempos
                    first_packet_time  = float(cols[COL_FIRSTPACKETTIME_TCP])
                    last_packet_time   = float(cols[COL_LASTPACKETTIME_TCP])
                    last_src2dst_time  = float(cols[COL_LASTSRC2DST_TCP])
                    last_dst2src_time  = float(cols[COL_LASTDST2SRC_TCP])
                    first_ack_sd_time  = float(cols[COL_FIRSTACK_SRC2DST_TIME_TCP])
                    first_ack_ds_time  = float(cols[COL_FIRSTACK_DST2SRC_TIME_TCP])

                    # Paquetes
                    num_packets_sd      = int(cols[COL_NUMPACKETS_SRC2DST_TCP])
                    num_packets_ds      = int(cols[COL_NUMPACKETS_DST2SRC_TCP])
                    num_packets_data_sd = int(cols[COL_NUMPACKETSDATA_SRC2DST_TCP])
                    num_packets_data_ds = int(cols[COL_NUMPACKETSDATA_DST2SRC_TCP])

                    # Flags TCP
                    number_syns_sd  = int(cols[COL_NUMSYNS_SRC2DST_TCP])
                    number_syns_ds  = int(cols[COL_NUMSYNS_DST2SRC_TCP])
                    number_fins_sd  = int(cols[COL_NUMFINS_SRC2DST_TCP])
                    number_fins_ds  = int(cols[COL_NUMFINS_DST2SRC_TCP])
                    number_rsts_sd  = int(cols[COL_NUMRST_SRC2DST_TCP])
                    number_rsts_ds  = int(cols[COL_NUMRST_DST2SRC_TCP])

                    # Bytes transferidos
                    bytes_sd        = int(cols[COL_TCPBYTES_SD_TCP])
                    bytes_ds        = int(cols[COL_TCPBYTES_DS_TCP])
                    total_tcp_data  = bytes_sd + bytes_ds

                    # Flags del primer paquete (hex)
                    first_packet_flags = cols[COL_FIRSTPACKETFLAGS_TCP].decode()

                    # Duración de la conexión
                    duration = last_packet_time - first_packet_time

                except (IndexError, ValueError) as e:
                    print(f"  ERROR: {e} | línea: {fila[:80]}")
                    continue


                if (seDebeAniadirConversacion(dst_ip, total_tcp_data, 
                                                number_syns_sd)):
                    clave = (src_ip,dst_ip)
                    conversaciones[clave].update(src_port, dst_port, first_packet_time , last_src2dst_time)

                lineas_leidas  += 1
                if lineas_leidas % 5_000_000 == 0:
                    print(f"  procesadas {lineas_leidas:,} líneas...")
            print(f"  procesadas al completo {lineas_leidas:,} líneas...")

    return conversaciones

def calcular_p(conversaciones: dict, percentil=99) -> None:
    """
    Normaliza el número de puertos únicos por el percentil 99 de todos los pares de ips.
    Los que superen el percentil los limito: p = 1.0
    """
    # counts = [len(c.puertosUnicos) for c in conversaciones.values()]
    # percentil99 = np.percentile(counts, percentil)
    # print(f"He aquí {percentil99}" )

    for conv in conversaciones.values():
        puertosUnicos = len(conv.puertosUnicos)
        conv.p = min(puertosUnicos / LIMITE_PUERTOS, 1.0)  # limito en 1.

def calcular_h(flujo: FlowData) -> None:
    """
    Entropía de Shannon de los puertos, normalizada por log2(n_puertos_unicos).
    H = 0: todos los paquetes van al mismo puerto (concentrado)
    H = 1: puertos perfectamente uniformes (disperso)
    """
    if not flujo.puertos:
        flujo.h = 0.0
        return

    conteo = Counter(flujo.puertos) #Counter cuenta la freceuncia de cada elemento en un iterable. Es un histograma básicamente, valor vs veces 
    n = len(flujo.puertos) # n es las ocurrencias, el número total de puertos llamados 
    n_uniq = len(conteo) # n_uniq es el número de puertos únicos

    if n_uniq == 1:          # un solo puerto, entropía 0
        flujo.h = 0.0
        return

    H = -sum((c/n) * math.log2(c/n) for c in conteo.values())  # c es la frecuencia, probabilidad = c/n 
    flujo.h = H / math.log2(n_uniq)   # normalizado [0, 1]

def calcular_d(flujo: FlowData) -> None:
    """
    Periodicidad del escaneo: 1 / (1 + CV), donde CV = std / mean
    de los tiempos entre conexiones consecutivas. Así resultado entre 0 y 1
    t = 1  : conexiones muy regulares (robótico → sospechoso)
    t = 0  : conexiones muy irregulares (humano)
    """
    tiempos = flujo.timestamps
    if len(tiempos) < 2:
        flujo.d = None   # no hay suficientes conexiones para calcular
        return

    intervalos = [tiempos[i+1] - tiempos[i] for i in range(len(tiempos)-1)]

    media = sum(intervalos) / len(intervalos)
    if media == 0:
        flujo.d = 1.0    # todas simultáneas → máxima regularidad
        return

    std = math.sqrt(sum((x - media)**2 for x in intervalos) / len(intervalos))
    CV  = std / media
    flujo.d = 1 / (1 + CV)

def puntuar(conv: FlowData) -> None:
    """
    Pongo una puntuación de sospecha [0, 1]. Tengo que calibrar w_p, w_H, w_r con nmap.
    p alto, muchos puertos únicos, sospechoso
    h alto, puertos dispersos, sospechoso
    r alto, conexiones muy regulares, sospechoso
    """

    if conv.d is None:
        return None   # flujo con una sola conexión, sin datos suficientes

    total = W_P + W_H + W_R
    conv.puntuacion = (W_P * conv.p + W_H * conv.h + W_R * conv.d) / total

def imprimir_resultado(conversaciones: dict) -> None:
    """Imprime las conversaciones sospechosas ordenadas por puntuación en la terminal."""

    # Ordena por puntuación descendente
    ordenadas = sorted(
        conversaciones.items(),
        key=lambda item: item[1].puntuacion if item[1].puntuacion is not None else -1,
        reverse=True
    )

    print(f"\n{'First timestamp':<20} {'SRC_IP':<20} {'DST_IP':<20} {'PUERTOS':>8} {'p':^6} {'h':^6} {'d':^6} {'SCORE':>7}")
    print("-" * 75)

    for (src_ip, dst_ip), conv in ordenadas:
        # if conv.puntuacion is None:
        #     continue
        # if conv.puntuacion > THRESHOLD:
        #     
        print(
            f"{conv.conexiones[0][0]:<20}{src_ip:<20} {dst_ip:<20}" # primer timestamp (lista ya ordenada por bisect)
            f"{len(conv.puertosUnicos):>8}"
            f"{0:>7.2f}"
            f"{0:>7.2f}"
            f"{0:>7.2f}"
            f"{0:>7.2f}"
        )

def main():
    conversaciones =  preprocesado(FILE_TCP_PATH)
    print(f"{len(conversaciones)} conversaciones registradas para su análisis...")
   # Calculamos los valores para p, h y r para cada conversacion
    calcular_p(conversaciones)
    for conv in conversaciones.values():
        calcular_h(conv)
        calcular_d(conv)
        puntuar(conv)

    # Imprimimos resultado en terminal:
    imprimir_resultado(conversaciones) 

if __name__ == "__main__":
    inicio = time.time()

    main()

    fin = time.time()
    tiempo_total = str(datetime.timedelta(seconds=fin - inicio))
    print(f"\nTiempo total: {tiempo_total}")