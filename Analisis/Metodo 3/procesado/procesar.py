from __future__ import annotations
from config import *
from .conversacion import Conversacion
from utils.leer_archivos import leer_registros_flujo_ordenados

def procesar_archivo_flujos_tcp(archivo_tcp: str) -> tuple[list[Conversacion], int]:
    """
    Procesa el archivo de flujos TCP y devuelve una lista de conversaciones y el número total de registros de flujo procesados.
    """
    print(f"\nProcesando flujos TCP...")

    conversaciones: list[Conversacion] = []
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion] = {}

    contadorRegistrosFlujo = 0

    for first_packet_time, cols in leer_registros_flujo_ordenados(archivo_tcp, COL_FIRSTPACKETTIME_TCP):
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

        contadorRegistrosFlujo  += 1
        if contadorRegistrosFlujo % 5_000_000 == 0:
            print(f"Procesadas {contadorRegistrosFlujo:,} líneas...")

    return conversaciones, contadorRegistrosFlujo

def procesar_archivo_flujos_udp(archivo_udp: str) -> tuple[list[Conversacion], int]:
    """
    Procesa el archivo de flujos UDP y devuelve una lista de conversaciones y el número total de registros de flujo procesados.
    """
    print(f"\nProcesando flujos UDP...")

    conversaciones: list[Conversacion] = []
    ultimaConversacionPorPareja: dict[tuple[str, str], Conversacion] = {}

    contadorRegistrosFlujo = 0

    for first_packet_time, cols in leer_registros_flujo_ordenados(archivo_udp, COL_FIRSTPACKETTIME_UDP):
        try:
            srcIp   = cols[COL_SRC_IP_UDP].decode()
            dstIp   = cols[COL_DST_IP_UDP].decode()
            srcPort = cols[COL_SRC_PORT_UDP].decode()
            dstPort = cols[COL_DST_PORT_UDP].decode()

            # Tiempos
            last_packet_time   = float(cols[COL_LASTPACKETTIME_UDP])

            # Bytes transferidos
            bytes_ds        = int(cols[COL_UDPBYTES_DS_UDP])

        except (IndexError, ValueError) as e:
            raise RuntimeError(f"  ERROR: {e} | línea: {b' '.join(cols)[:80]}")

        conversacion = ObtenerOCrearConversacion(conversaciones, ultimaConversacionPorPareja, srcIp, dstIp, first_packet_time, "UDP")

        conversacion.flujosTotales += 1
        if bytes_ds == 0:
            conversacion.flujosSondeo += 1

        conversacion.update(srcPort, dstPort, first_packet_time , last_packet_time)

        contadorRegistrosFlujo  += 1
        if contadorRegistrosFlujo % 5_000_000 == 0:
            print(f"Procesadas {contadorRegistrosFlujo:,} líneas...")

    return conversaciones, contadorRegistrosFlujo

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
