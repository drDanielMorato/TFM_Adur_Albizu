from dataclasses import dataclass

@dataclass
class DatosPaquete:
    tStart: float
    srcIp: str
    dstIp: str
    dstPort: int
    ruta_pcap: str
