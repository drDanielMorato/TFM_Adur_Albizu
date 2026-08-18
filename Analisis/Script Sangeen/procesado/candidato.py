from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Candidato:
    tInicio: float
    srcIp: str
    scans: list[tuple[list[str], list[int]]]
    scanType: str

    def __str__(self) -> str:
        scans_str = "; ".join(
            f"destinos={ips} puertos={puertos}"
            for ips, puertos in self.scans
        )
        return f"[{self.scanType}] srcIp={self.srcIp} tInicio={self.tInicio:.3f} -> {scans_str}"
