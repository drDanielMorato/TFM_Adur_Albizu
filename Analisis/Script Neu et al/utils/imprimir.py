from __future__ import annotations
from procesado import Candidato
from datetime import datetime, timezone
import json

def imprimir_resultado(sospechosos: list[Candidato], ruta_archivo_resultado: str) -> None:
    """Guarda los candidatos en JSON con el formato usado por Metodo 3."""

    data = []

    for candidato in sospechosos:
        destinos = sorted({ip for ips, _ in candidato.scans for ip in ips})
        puertos = sorted({puerto for _, puertos_scan in candidato.scans for puerto in puertos_scan})
        data.append({
            "ipSource": candidato.srcIp,
            "ipDestination": destinos,
            "portsDestination": puertos,
            # "scans": [
            #     {
            #         "ipDestination": sorted(ips),
            #         "portsDestination": sorted(puertos_scan),
            #     }
            #     for ips, puertos_scan in candidato.scans
            # ], #Esto sirve para los escaneos mixtos
            "startTime": candidato.tInicio,
            "startTimeUtc": datetime.fromtimestamp(candidato.tInicio, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "protocol": "TCP",
            "scanType": candidato.scanType, 
        })

    with open(ruta_archivo_resultado, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Resultados guardados en {ruta_archivo_resultado}, {len(sospechosos)} sospechosos detectados.")