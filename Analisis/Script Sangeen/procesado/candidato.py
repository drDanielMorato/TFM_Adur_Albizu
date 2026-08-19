from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Candidato:
    tInicio: float
    srcIp: str
    dstIp: str
    dstPorts: list[int]
    fileName: str #pcap en el que ha sido detectado el escaneo
