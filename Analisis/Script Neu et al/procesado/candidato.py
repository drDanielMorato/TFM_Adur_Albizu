from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Candidato:
    """ 
    Objeto representando a un candidato, que se corresponde con una ip origen.
    escaneos es una lista de parejas (ipDestino, puertosDestino), donde representamos los puertos escaneados para una IP. 
    Para escaneos verticales y horizontales habrá un solo elemento en la lista, mientras que para escaneos mixtos se tendrá más de un elemento.
    """
    tInicio : float
    srcIp: str
    scans :list[tuple[list[str], list[int]]]
    scanType: str

    def __str__(self) -> str:
        scans_str = "; ".join(
            f"destinos={ips} puertos={puertos}"
            for ips, puertos in self.scans
        )
        return f"[{self.scanType}] srcIp={self.srcIp} tInicio={self.tInicio:.3f} -> {scans_str}"