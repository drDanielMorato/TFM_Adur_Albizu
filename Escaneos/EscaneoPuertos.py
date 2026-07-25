# Script inicial para encontrar escaneos TCP SYN Scan.


from __future__ import annotations # don't execute type hints, just store them as text strings
import time
import datetime
import mmap
import math
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import ipaddress
import sys
import traceback
import argparse
import os 

# Variables globales archivos:
# FILE_TCP_PATH =  "/opt3/proyectistas/adur.albizu/Desktop/tarea_03_03/scripts - parámetros por separado/EscaneoPuertosAdicional/logsProcesaConexiones/salida1_tcp_"
INPUT_PATH = '/opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20180117-XXXXXX/mockeo_1516142417/20171215-113439/salida_tcp_'
OUTPUT_PATH = ''

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

COL_FIRSTACK_SRC2DST_TIME_TCP = 8 #timestamp del primer ACK de cliente a servidor (-1 si no hay tal paquete)
COL_FIRSTACK_DST2SRC_TIME_TCP = 9#timestamp del primer ACK del servidor al cliente (-1 si no hay tal paquete)  
COL_FIRSTSYN_SRC2DST_TIME = 6 #timestamp del primer SYN de cliente a servidor 

COL_TCPBYTES_SD_TCP = 36  #bytesIPSrcToDst numero de paquetes de cliente a servidor 
COL_TCPBYTES_DS_TCP = 37  #bytesIPDstToSrc

COL_FIRSTPACKETFLAGS_TCP = 48 # Flags del primer paquete que se ve (en hexadecimal), que si hay desorden puede no ser el primero de la conexion. 

COL_SRC_IP_UDP = 0
COL_DST_IP_UDP = 2
COL_UDPBYTES_SD_UDP = 44
COL_UDPBYTES_DS_UDP = 45

LIMITE_PUERTOS= 10 #Limite por debajo del cual supongo más dudoso un escaneo de puertos

# Ventana temporal 
INTERVALO_ESCANEOS_DIFERENTES = 86400 #Intervalo a partir del cual separo dos escaneos a una misma IP. 24h

#Rangos internos IP de la uni: 130.206.158.0 - 130.206.175.255
RANGOS_INTERNOS =["130.206.158.0/23", #130.206.158.0 - 130.206.159.255 
                  "130.206.160.0/20"] #130.206.160.0 - 130.206.175.255

REDES_INTERNAS = [ipaddress.ip_network(r, strict=False) for r in RANGOS_INTERNOS]

# Pesos para estimar cómo de sospechosa es una conversación:
W_P=1
W_H=1
W_R=1

#OBSOLETO: Umbral para decidir si una conversación es sospechosa 
THRESHOLD = 0

# Para agilizar:
_cache_ips = {}

@dataclass
class Conversacion:

    # Pareja de Ips de la conversación 
    srcIp: str
    dstIp: str

    # Registros detallados de cada conexión individual, ordenados por t_inicio
    # Cada tupla: (t_inicio, t_fin, puerto_origen, puerto_destino)
    conexiones: list[tuple[float, float, str, str]] = field(default_factory=list)

    #Tiempo final de la última conexión de la conversación
    ultimaActividad: float = 0.0

    #Computaciones finales
    p: float | None = None  # Numero de puertos únicos normalizados
    h: float | None = None  # Entropia de Shannon normalizada
    d: float | None = None  # Desviación estándar del tiempo entre conexiones normalizada 1/(1+CV)
    puntuacion: float | None = None # Puntúa cómo de sospechosa es una interacción entre dos ips.   

    # Sospechosa: Es una conversación sospechosa   
    sospechosa: bool = True

    #Método de actualización
    def update(self, puerto_src, puerto_dst, t_inicio, t_fin) -> None:
        self.conexiones.append((t_inicio, t_fin, puerto_src, puerto_dst))

def parseArgs() -> argparse.Namespace:
    """Parsea y valida los argumentos de la línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Ejecuta script de análisis"
    )
    parser.add_argument(
        "--rutaOrigen",
        "-o",
        required=True,
        help="Directorio donde se encuentra el archivo de con los registros de flujo"
    )
    parser.add_argument(
        "--rutaDestino",
        "-d",
        required=True,
        help="Directorio donde queremos montar el resultado"
    )

    return parser.parse_args()

def esIpInterna(src_ip: str) -> bool:
    if src_ip in _cache_ips:
        return _cache_ips[src_ip]

    addr = ipaddress.ip_address(src_ip)
    resultado = any(addr in red for red in REDES_INTERNAS)
    _cache_ips[src_ip] = resultado
    return resultado

def ObtenerOCrearConversacion(conversaciones, ultimaConversacionPorPareja, srcIp, dstIp, tInicio) -> Conversacion:
    """
    Dadas las IP origen e IP destino de una conexión, este método comprueba que ultimaConversacionPorPareja contiene una conversación identificada
    por dicha pareja de direcciones IP y si han pasado INTERVALO_ESCANEOS_DIFERENTES segundos desde el t_inicio de la conexión y el t_final de la conexión más
    nueva de la conversación correspondiente.
    Si es así, se devuelve la conexión existente. Si no es el caso, se crea una nueva conexión identificada por la pareja de ips.
    """
    clave = (srcIp, dstIp)
    conv = ultimaConversacionPorPareja.get(clave)

    if conv and (abs(tInicio - conv.ultimaActividad)) <= INTERVALO_ESCANEOS_DIFERENTES:
        conv.ultimaActividad = tInicio
        return conv

    nueva = Conversacion(srcIp=srcIp, dstIp=dstIp, ultimaActividad=tInicio)
    conversaciones.append(nueva)
    ultimaConversacionPorPareja[clave] = nueva
    return nueva

def seDebeAniadirRegistroFlujo(dst_ip, total_tcp_data_sd, total_tcp_data_ds,
                             number_syns_sd) -> bool:

    DatosSdEnRango = total_tcp_data_sd == 0
    DatosDsEnRango = total_tcp_data_ds <= 256
    clienteEnviaSYN = number_syns_sd == 1

    return (DatosSdEnRango and DatosDsEnRango) # and clienteEnviaSYN)

def preprocesado() -> tuple[list, int]:
    """
    Preparo la matriz necesaria para el procesado.
    Incluye todas las parejas de ips, con info como el timestamp de inicio de cada flujo perteneciente
    a la pareja, cuántos puertos se han atacado.
    """
    print(f"\nPreprocesando...")

    conversaciones: list[Conversacion] = []
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion] = {}

    contadorRegistrosFlujo = 0

    archivo = os.path.join(INPUT_PATH, "salida_tcp_")

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    
                    cols = fila.split()

                    srcIp   = cols[COL_SRC_IP_TCP].decode()
                    dstIp   = cols[COL_DST_IP_TCP].decode()
                    srcPort = cols[COL_SRC_PORT_TCP].decode()
                    dstPort = cols[COL_DST_PORT_TCP].decode()

                    # Tiempos
                    first_packet_time  = float(cols[COL_FIRSTPACKETTIME_TCP])
                    first_syn_src2dst = float(cols[COL_FIRSTSYN_SRC2DST_TIME])
                    first_packet_time = first_packet_time if first_syn_src2dst == -1 else first_syn_src2dst

                    last_packet_time   = float(cols[COL_LASTPACKETTIME_TCP])
                    # last_src2dst_time  = float(cols[COL_LASTSRC2DST_TCP])
                    # last_dst2src_time  = float(cols[COL_LASTDST2SRC_TCP])
                    # first_ack_sd_time  = float(cols[COL_FIRSTACK_SRC2DST_TIME_TCP])
                    # first_ack_ds_time  = float(cols[COL_FIRSTACK_DST2SRC_TIME_TCP])

                    # Paquetes
                    # num_packets_sd      = int(cols[COL_NUMPACKETS_SRC2DST_TCP])
                    # num_packets_ds      = int(cols[COL_NUMPACKETS_DST2SRC_TCP])
                    # num_packets_data_sd = int(cols[COL_NUMPACKETSDATA_SRC2DST_TCP])
                    # num_packets_data_ds = int(cols[COL_NUMPACKETSDATA_DST2SRC_TCP])

                    # Flags TCP
                    number_syns_sd  = int(cols[COL_NUMSYNS_SRC2DST_TCP])
                    # number_syns_ds  = int(cols[COL_NUMSYNS_DST2SRC_TCP])
                    # number_fins_sd  = int(cols[COL_NUMFINS_SRC2DST_TCP])
                    # number_fins_ds  = int(cols[COL_NUMFINS_DST2SRC_TCP])
                    # number_rsts_sd  = int(cols[COL_NUMRST_SRC2DST_TCP])
                    # number_rsts_ds  = int(cols[COL_NUMRST_DST2SRC_TCP])

                    # Bytes transferidos
                    bytes_sd        = int(cols[COL_TCPBYTES_SD_TCP])
                    bytes_ds        = int(cols[COL_TCPBYTES_DS_TCP])

                    # Flags del primer paquete (hex)
                    # first_packet_flags = cols[COL_FIRSTPACKETFLAGS_TCP].decode()

                except (IndexError, ValueError) as e:
                    raise RuntimeError(f"  ERROR: {e} | línea: {fila[:80]}")

                conversacion = ObtenerOCrearConversacion(conversaciones, ultimaConversacionPorPareja, srcIp, dstIp, first_packet_time)

                if (seDebeAniadirRegistroFlujo(dstIp, bytes_sd, bytes_ds,
                                                number_syns_sd)):
                    
                    conversacion.update(srcPort, dstPort, first_packet_time , last_packet_time)
                else:
                    conversacion.sospechosa = False

                contadorRegistrosFlujo  += 1
                if contadorRegistrosFlujo % 5_000_000 == 0:
                    print(f"Procesadas {contadorRegistrosFlujo:,} líneas...")

    return conversaciones, contadorRegistrosFlujo

def descartarFalsosPositivos(conversaciones: list[Conversacion]) -> None:
    """
    Busca conversaciones UDP ocurriendo simultaneamente a las conversaciones TCP eistentes para descartar falsos positivos
    """

    archivo = os.path.join(INPUT_PATH, "salida_udp_")

    indice = defaultdict(list)
    for conv in conversaciones:
        indice[(conv.srcIp, conv.dstIp)].append(conv)
    #Construyo un diccionario que me evite tener que recorrer conversaciones cada vez que quiera comprobar si una clave está dentro, en el bucle de lectura    

    with open(archivo, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break
                try:
                    cols = fila.split()

                    srcIp   = cols[COL_SRC_IP_UDP].decode()
                    dstIp   = cols[COL_DST_IP_UDP].decode()
                    
                    bytes_sd = int(cols[COL_UDPBYTES_SD_UDP])
                    bytes_ds = int(cols[COL_UDPBYTES_DS_UDP])

                except (IndexError, ValueError) as e:
                    raise RuntimeError(f"  ERROR: {e} | línea: {fila[:80]}")

                clave = (srcIp, dstIp)
                claveInversa = (dstIp, srcIp)
                for conv in indice.get(clave, []):
                    conv.sospechosa = False
                for conv in indice.get(claveInversa, []):
                    conv.sospechosa = False

def imprimirEstadisticas(conversaciones: list[Conversacion], contadorRegistrosFlujo: int) -> None:
    """Imprime estadísticas de conversaciones/registros sospechosos, excluyendo las
    conversaciones de un solo puerto (no puerto único, sino 1 solo puerto)."""

    contadorRegistrosFlujoSospechosos = sum(
        len(conv.conexiones) for conv in conversaciones
        if conv.sospechosa and len({c[3] for c in conv.conexiones}) > 1
    )
    contadorConversaciones = len(conversaciones)
    contadorConversacionesSospechosas = sum(
        1 for conv in conversaciones
        if conv.sospechosa and len({c[3] for c in conv.conexiones}) > 1
    )

    print(f"De {contadorRegistrosFlujo} registros de flujo, {contadorRegistrosFlujoSospechosos} fueron registrados flujos sospechosos. Porcentaje:{contadorRegistrosFlujoSospechosos/contadorRegistrosFlujo*100:.2f}%")
    print(f"De {contadorConversaciones} conversaciones, {contadorConversacionesSospechosas} son sospechosas. Porcentaje {contadorConversacionesSospechosas/contadorConversaciones*100:.2f}%")

def calcular_p_h(conv: Conversacion) -> None:
    """
    p: 
    Divide el # de puertos unicos entre el umbral mínimo a partir del cual
    consideramos el conjunto de llamadas a distintos puertos de una IP escaneo.  

    h:
    Entropía de Shannon de los puertos, normalizada por log2(n_puertos_unicos).
    H = 0: todos los paquetes van al mismo puerto (concentrado)
    H = 1: puertos perfectamente uniformes (disperso)
    """
    puertos = [c[3] for c in conv.conexiones]
    if not puertos:
        conv.h = 0.0
        return

    conteo = Counter(puertos)
    n, n_uniq = len(puertos), len(conteo)

    if n_uniq <= 1:
        conv.h = 0.0
    else:
        H = -sum((c/n) * math.log2(c/n) for c in conteo.values())
        conv.h = H / math.log2(n_uniq)

    conv.p = min(n_uniq / LIMITE_PUERTOS, 1.0)

def calcular_d(conv: Conversacion) -> None:
    """
    Periodicidad del escaneo: 1 / (1 + CV), donde CV = std / mean
    de los tiempos entre conexiones consecutivas. Así resultado entre 0 y 1
    t = 1  : conexiones muy regulares (robótico → sospechoso)
    t = 0  : conexiones muy irregulares (humano)
    """
    # Muy importante ordenar las conexiones temporalmente: 
    conv.conexiones.sort()

    if len(conv.conexiones) < 2:
        conv.d = None
        return

    tiempos = [c[0] for c in conv.conexiones]

    intervalos = [tiempos[i+1] - tiempos[i] for i in range(len(tiempos)-1)]
    media = sum(intervalos) / len(intervalos)

    if media == 0:
        conv.d = 1.0
        return

    std = math.sqrt(sum((x - media)**2 for x in intervalos) / len(intervalos))
    conv.d = 1 / (1 + std/media)

def puntuar(conv: Conversacion) -> None:
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

def imprimir_resultado(conversaciones: list[Conversacion]) -> None:
    """Imprime las conversaciones sospechosas ordenadas por puntuación en la terminal."""

    archivoOutput = os.path.join(OUTPUT_PATH,"salida2.txt")
    # Ordena por puntuación descendente
    ordenadas = sorted(
        conversaciones, 
        key=lambda conv: conv.puntuacion if conv.puntuacion is not None else -1,
        reverse=True
    )

    with open(archivoOutput, "w", encoding="utf-8", buffering=1024 * 1024) as f:
        f.write(f"\n{'Start (unix)':<16} {'Ending (unix)':<16} {'Start (local)':<20} {'Ending (local)':<20} {'IpSrc':<15} {'IpDst':<15} {'p':^7} {'h':^7} {'d':^7} {'No. Ports':<10} {'No. Unique':<12} {'Target Ports'}\n")
        f.write("-" * 210)
        f.write("\n")

        for conv in ordenadas:
            if conv.puntuacion is None:
                continue
            if conv.sospechosa and len({c[3] for c in conv.conexiones}) >1:
                t_first = conv.conexiones[0][0]
                t_last  = max(c[1] for c in conv.conexiones)

                t_first_human = datetime.datetime.fromtimestamp(t_first).strftime("%Y-%m-%d %H:%M:%S")
                t_last_human  = datetime.datetime.fromtimestamp(t_last).strftime("%Y-%m-%d %H:%M:%S")

                puertoDestino = ",".join(f"{c[3]}" for c in conv.conexiones)
                 
                f.write((
                    f"{t_first:<16.2f} {t_last:<16.2f} {t_first_human:<20} {t_last_human:<20} {conv.srcIp:<15} {conv.dstIp:<15}"
                    f" {conv.p or 0:^7.2f}"
                    f" {conv.h or 0:^7.2f}"
                    f" {conv.d or 0:^7.2f}"
                    f" {len(conv.conexiones):^10}"
                    f" {len({c[3] for c in conv.conexiones}):^12}"
                    f" {puertoDestino}"
                    f"\n"
                )) 

def manejarArgumentos(args) -> None:
    global INPUT_PATH, OUTPUT_PATH

    INPUT_PATH = args.rutaOrigen 
    OUTPUT_PATH = args.rutaDestino

def main():
    try:
        inicio = time.time()

        args = parseArgs()
        manejarArgumentos(args)

        conversaciones, contadorRegistrosFlujo =  preprocesado()
        descartarFalsosPositivos(conversaciones)
        imprimirEstadisticas(conversaciones, contadorRegistrosFlujo)

        # Calculamos los valores para p, h y r para cada conversacion
        for conv in conversaciones:
            calcular_p_h(conv)
            calcular_d(conv)
            puntuar(conv)

        # Imprimimos resultado en terminal:
        imprimir_resultado(conversaciones) 

    except Exception as e:
        print(f"Fallo inesperado en el script: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        fin = time.time()
        tiempo_total = str(datetime.timedelta(seconds=fin - inicio))
        print(f"\nTiempo total: {tiempo_total}")

if __name__ == "__main__":
    main()

    