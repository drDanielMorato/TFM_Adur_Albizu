from __future__ import annotations
from config import *
from .conversacion import Conversacion
from utils.leer_archivos import leer_registros_flujo_ordenados
from typing import Callable, Dict, Iterator, List, Tuple
import datetime
from dateutil.tz import gettz

ZONA_HORARIA = gettz(ZONA_HORARIA_DIAS)

# Firma común de procesar_registro_flujo_tcp / procesar_registro_flujo_udp (typing.* porque se evalúa en tiempo de ejecución en Python 3.8)
ProcesadorRegistroFlujo = Callable[[float, List[bytes], List[Conversacion], Dict[Tuple[str, str], Conversacion]], None]

def procesar_registro_flujo_tcp(
    first_packet_time: float,
    cols: list[bytes],
    conversaciones: list[Conversacion],
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion],
) -> None:
    """
    Procesa un único registro de flujo TCP (ya troceado en columnas) y lo incorpora a su conversación.
    """
    try:
        srcIp   = cols[COL_SRC_IP_TCP].decode()
        dstIp   = cols[COL_DST_IP_TCP].decode()
        srcPort = cols[COL_SRC_PORT_TCP].decode()
        dstPort = cols[COL_DST_PORT_TCP].decode()

        # Tiempos
        last_packet_time   = float(cols[COL_LASTPACKETTIME_TCP])

        # Bytes transferidos
        bytes_sd        = int(cols[COL_TCPBYTES_SD_TCP])
        bytes_ds        = int(cols[COL_TCPBYTES_DS_TCP])

        num_paquetes_sd = int(cols[COL_NUMPACKETS_SRC2DST_TCP])
        num_paquetes_ds = int(cols[COL_NUMPACKETS_DST2SRC_TCP])

        if (num_paquetes_sd == 0 and (0 < num_paquetes_ds <=3)):
            #Swap para solucionar asignaciones incorrectas de cliente y servicio de procesaConexiones (casos extremos)
            srcIp, dstIp = dstIp, srcIp
            srcPort, dstPort = dstPort, srcPort
            bytes_sd, bytes_ds = bytes_ds, bytes_sd

    except (IndexError, ValueError) as e:
        raise RuntimeError(f"  ERROR: {e} | línea: {b' '.join(cols)[:80]}")

    conversacion = ObtenerOCrearConversacion(
        conversaciones,
        ultimaConversacionPorPareja,
        srcIp,
        dstIp,
        first_packet_time,
        "TCP",
    )
    conversacion.flujosTotales += 1

    if aniadir_registro_flujo_tcp(bytes_sd, bytes_ds):
        conversacion.flujosSondeo += 1
        conversacion.update(srcPort, dstPort, first_packet_time, last_packet_time)

def procesar_registro_flujo_udp(
    first_packet_time: float,
    cols: list[bytes],
    conversaciones: list[Conversacion],
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion],
) -> None:
    """
    Procesa un único registro de flujo UDP (ya troceado en columnas) y lo incorpora a su conversación.
    """
    try:
        srcIp   = cols[COL_SRC_IP_UDP].decode()
        dstIp   = cols[COL_DST_IP_UDP].decode()
        srcPort = cols[COL_SRC_PORT_UDP].decode()
        dstPort = cols[COL_DST_PORT_UDP].decode()

        # Tiempos
        last_packet_time   = float(cols[COL_LASTPACKETTIME_UDP])

        # Bytes transferidos
        bytes_sd = int(cols[COL_UDPBYTES_SD_UDP])
        bytes_ds = int(cols[COL_UDPBYTES_DS_UDP])

    except (IndexError, ValueError) as e:
        raise RuntimeError(f"  ERROR: {e} | línea: {b' '.join(cols)[:80]}")

    conversacion = ObtenerOCrearConversacion(conversaciones, ultimaConversacionPorPareja, srcIp, dstIp, first_packet_time, "UDP")

    conversacion.flujosTotales += 1
    if bytes_ds == 0 and bytes_sd == 0:
        conversacion.flujosSondeo += 1
        conversacion.update(srcPort, dstPort, first_packet_time , last_packet_time)

def obtener_dia(timestamp: float) -> datetime.date:
    """Día (en ZONA_HORARIA_DIAS) al que pertenece un timestamp unix."""
    return datetime.datetime.fromtimestamp(timestamp, ZONA_HORARIA).date()

def procesar_archivo_flujos_por_dias(
    archivo: str,
    columna_timestamp: int,
    procesar_registro_flujo: ProcesadorRegistroFlujo,
    protocolo: str,
) -> Iterator[tuple[datetime.date, list[Conversacion], int, int]]:
    """
    Recorre el archivo de registros de flujo y, en lugar de acumular todo el archivo, va devolviendo
    (dia, conversaciones, registros, flujos_desordenados) cada vez que termina un día, para que el llamante
    escriba su resultado y se libere la memoria antes de seguir con el siguiente.
    Como leer_registros_flujo_ordenados emite los registros ya ordenados por timestamp, el cambio de día se
    detecta de forma fiable aunque el archivo de entrada esté desordenado. Una conversación activa a
    medianoche se corta y continúa como conversación nueva en el día siguiente.
    """
    print(f"\nProcesando flujos {protocolo} por días...")

    conversaciones: list[Conversacion] = []
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion] = {}
    contadorRegistrosFlujo = 0
    contadorFlujosDesordenados = 0
    dia_actual: datetime.date | None = None

    for first_packet_time, cols, flujo_desordenado in leer_registros_flujo_ordenados(archivo, columna_timestamp):
        dia = obtener_dia(first_packet_time)

        if dia_actual is not None and dia != dia_actual:
            yield dia_actual, conversaciones, contadorRegistrosFlujo, contadorFlujosDesordenados
            conversaciones = []
            ultimaConversacionPorPareja = {}
            contadorRegistrosFlujo = 0
            contadorFlujosDesordenados = 0

        dia_actual = dia
        procesar_registro_flujo(first_packet_time, cols, conversaciones, ultimaConversacionPorPareja)

        contadorRegistrosFlujo += 1
        contadorFlujosDesordenados += int(flujo_desordenado)
        if contadorRegistrosFlujo % 5_000_000 == 0:
            print(f"Procesadas {contadorRegistrosFlujo:,} líneas del día {dia_actual}...")

    if dia_actual is not None:
        yield dia_actual, conversaciones, contadorRegistrosFlujo, contadorFlujosDesordenados

def procesar_archivo_flujos_tcp_por_dias(archivo_tcp: str) -> Iterator[tuple[datetime.date, list[Conversacion], int, int]]:
    return procesar_archivo_flujos_por_dias(archivo_tcp, COL_FIRSTPACKETTIME_TCP, procesar_registro_flujo_tcp, "TCP")

def procesar_archivo_flujos_udp_por_dias(archivo_udp: str) -> Iterator[tuple[datetime.date, list[Conversacion], int, int]]:
    return procesar_archivo_flujos_por_dias(archivo_udp, COL_FIRSTPACKETTIME_UDP, procesar_registro_flujo_udp, "UDP")

def aniadir_registro_flujo_tcp( total_tcp_data_sd, total_tcp_data_ds) -> bool:
    #Criterio para añadir un registro de flujo a la conversación: si no hay datos de cliente a servidor, o si hay pocos datos de servidor a cliente (menos de 256 bytes)
    DatosSdEnRango = total_tcp_data_sd == 0
    DatosDsEnRango = total_tcp_data_ds <= 256

    return (DatosSdEnRango and DatosDsEnRango)

def ObtenerOCrearConversacion(conversaciones, ultimaConversacionPorPareja, srcIp, dstIp, tInicio, protocolo) -> Conversacion:
    """
    Dadas las IP origen e IP destino de una conexión, este método comprueba que ultimaConversacionPorPareja contiene una conversación identificada
    por dicha pareja de direcciones IP y si han pasado INTERVALO_ESCANEOS_DIFERENTES segundos desde el t_inicio de la conexión y el t_final de la conexión más
    nueva de la conversación correspondiente.
    Si es así, se devuelve la conexión existente. Si no es el caso, se crea una nueva conexión identificada por la pareja de ips.
    """
    clave = (srcIp, dstIp)
    conv = ultimaConversacionPorPareja.get(clave)

    if conv and (tInicio - conv.ultimaActividad) <= INTERVALO_ESCANEOS_DIFERENTES:
        conv.ultimaActividad = tInicio
        return conv

    nueva = Conversacion(srcIp=srcIp, dstIp=dstIp, protocolo=protocolo, ultimaActividad=tInicio)
    conversaciones.append(nueva)
    ultimaConversacionPorPareja[clave] = nueva
    return nueva
