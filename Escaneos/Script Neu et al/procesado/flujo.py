from dataclasses import dataclass, field

@dataclass
class Flujo:
    """ Tupla representando a un flujo en específico"""
    tStart : float
    srcIp: str
    dstIp: str
    dstPort: int

