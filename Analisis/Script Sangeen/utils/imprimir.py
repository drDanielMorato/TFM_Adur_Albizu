from __future__ import annotations
from procesado import Candidato
import json
import os

def imprimir_resultado(
    sospechosos: list[Candidato],
    ruta_archivo_resultado: str,
    borrar_json: bool = False,
) -> None:

    if os.path.exists(ruta_archivo_resultado) and not borrar_json:
        with open(ruta_archivo_resultado, 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
    else:
        data = []

    for sospechoso in sospechosos:
        new_entry = {
            'ipSource': sospechoso.srcIp,
            'ipDestination': sospechoso.dstIp,
            'portsDestination': sospechoso.dstPorts,
            'startTime': sospechoso.tInicio,
            'file': sospechoso.fileName
        }
        data.append(new_entry)

    with open(ruta_archivo_resultado, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4)
        print(f"Resultados guardados en {ruta_archivo_resultado}, {len(sospechosos)} sospechosos detectados.")

