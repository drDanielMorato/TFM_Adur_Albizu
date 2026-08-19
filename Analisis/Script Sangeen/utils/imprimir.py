from __future__ import annotations
from procesado import Candidato
import json
import os

def imprimir_resultado(sospechosos: list[Candidato], ruta_archivo_resultado: str) -> None:

    if os.path.exists(ruta_archivo_resultado):
        with open(ruta_archivo_resultado, 'r') as json_file:
            data = json.load(json_file)
    else:
        data = []

    for sospechoso in sospechosos:
        new_entry = {
            'ipSource': sospechoso.srcIp,
            'ipDestination': sospechoso.dstIp,
            'portsDestination': sospechoso.dstPorts,
            'startTime': sospechoso.tInicio,
            'fileName': sospechoso.fileName
        }
        data.append(new_entry)

    with open(ruta_archivo_resultado, 'w') as json_file:
        json.dump(data, json_file, indent=4)
        print(f"Resultados guardados en {ruta_archivo_resultado}, {len(sospechosos)} sospechosos detectados.")

