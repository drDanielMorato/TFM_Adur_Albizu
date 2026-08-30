from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from procesado.candidato import Candidato

def imprimir_resultado(
    sospechosos: list[Candidato],
    ruta_archivo_resultado: str,
    archivo_pcap: str | None = None,
    borrar_json: bool = True,
) -> None:
    """Guarda los candidatos en JSON con el formato usado por Metodo 3."""

    if os.path.exists(ruta_archivo_resultado) and not borrar_json:
        with open(ruta_archivo_resultado, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
    else:
        data = []

    for candidato in sospechosos:
        destinos = sorted({ip for ips, _ in candidato.scans for ip in ips})
        puertos = sorted({puerto for _, puertos_scan in candidato.scans for puerto in puertos_scan})
        resultado = {
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
        }
        if archivo_pcap is not None:
            resultado["file"] = archivo_pcap
        data.append(resultado)

    with open(ruta_archivo_resultado, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Resultados guardados en {ruta_archivo_resultado}, {len(sospechosos)} sospechosos detectados.")