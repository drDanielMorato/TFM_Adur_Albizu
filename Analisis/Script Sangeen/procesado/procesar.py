from __future__ import annotations
from config import TIME_THRESHOLD, UNIQUE_PORTS_THRESHOLD
from .candidato import Candidato
from .CamposFlowEntry import CamposFlowEntry
from .DatosPaquete import DatosPaquete

def _crear_flow_entry(paquete: DatosPaquete) -> CamposFlowEntry:
    return CamposFlowEntry(
        dstPorts={paquete.dstPort},
        ruta_pcap=paquete.ruta_pcap,
        tiempo_inicio=paquete.tStart,
        tiempo_final=paquete.tStart,
    )

def _anadir_paquete(flow_entry: CamposFlowEntry, paquete: DatosPaquete) -> None:
    flow_entry.dstPorts.add(paquete.dstPort)
    flow_entry.tiempo_final = paquete.tStart

def _crear_candidato(flow_entry: CamposFlowEntry, paquete: DatosPaquete) -> Candidato:
    return Candidato(
        tInicio=flow_entry.tiempo_inicio,
        srcIp=paquete.srcIp,
        dstIp=paquete.dstIp,
        dstPorts=list(flow_entry.dstPorts),
        fileName=flow_entry.ruta_pcap,
    )

def _eliminar_flow_entries_expiradas(
    tiempo_actual: float,
    flow_entries: dict[tuple[str, str], CamposFlowEntry],
) -> None:
    limite = tiempo_actual - TIME_THRESHOLD
    claves_expiradas = [
        clave
        for clave, flow_entry in flow_entries.items()
        if flow_entry.tiempo_final < limite
    ]
    for clave in claves_expiradas:
        del flow_entries[clave]

def procesar(ruta_archivos_paquetes: str) -> list[Candidato]:
    """Procesa paquetes y devuelve las flow entries que parecen escaneos."""
    from utils import leer_paquetes  

    return _procesar_paquetes(leer_paquetes(ruta_archivos_paquetes))


def procesar_pcap(ruta_pcap: str) -> list[Candidato]:
    """Procesa un PCAP independiente con un estado de detección nuevo."""
    from utils.leer_archivos import leer_pcap

    return _procesar_paquetes(leer_pcap(ruta_pcap))


def _procesar_paquetes(paquetes) -> list[Candidato]:
    """Procesa una secuencia cronológica de paquetes."""

    candidatos: list[Candidato] = []
    flow_entries: dict[tuple[str, str], CamposFlowEntry] = {}
    proxima_limpieza = float("-inf")

    # Iteramos sobre los paquetes ordenados por timestamp
    for paquete in paquetes:
        clave = (paquete.srcIp, paquete.dstIp)
        if paquete.tStart >= proxima_limpieza:
            _eliminar_flow_entries_expiradas(paquete.tStart, flow_entries)
            proxima_limpieza = paquete.tStart + 1.0
            #eliminamos entradas para liberar memoria

        flow_entry = flow_entries.get(clave)
        if (
            flow_entry is not None
            and paquete.tStart - flow_entry.tiempo_final > TIME_THRESHOLD
        ):
            flow_entry = None # si el paquete llega demasiado tarde, se considera que la flow entry ha expirado y se crea una nueva para este paquete

        if flow_entry is None:
            flow_entry = _crear_flow_entry(paquete)
            flow_entries[clave] = flow_entry
            continue # aquí creamos la flow entry si es necesario, y pasamos al siguiente paquete

        _anadir_paquete(flow_entry, paquete) #ahora que tenemos la flow entry, añadimos el paquete a ella

        if (
            not flow_entry.detectada
            and len(flow_entry.dstPorts) > UNIQUE_PORTS_THRESHOLD
        ):
            candidatos.append(_crear_candidato(flow_entry, paquete))
            flow_entry.detectada = True

    return candidatos
