from __future__ import annotations
from dataclasses import dataclass

@dataclass
class CamposFlowEntry:
    # Campos asociados a una flow entry identificada por la tupla (srcIp, dstIp)
    dstPorts: set[int]  # Puertos de destino únicos contactados desde srcIp a dstIp
    ruta_pcap: str  # Ruta del archivo pcap en el que se ha detectado la flow entry
    tiempo_inicio: float
    tiempo_final: float
    detectada: bool = False
