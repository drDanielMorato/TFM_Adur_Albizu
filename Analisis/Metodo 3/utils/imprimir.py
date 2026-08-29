from __future__ import annotations
from config import *
from procesado import Conversacion
import datetime
import json
import os
from dateutil.tz import gettz

ZONA_HORARIA_ESPANA = gettz("Europe/Madrid")

def imprimirEstadisticas(conversaciones: list[Conversacion], contadorRegistrosFlujo: int) -> None:
    """Imprime estadísticas de conversaciones/registros sospechosos, excluyendo las
    conversaciones de un solo puerto (no puerto único, sino 1 solo puerto)."""

    contadorRegistrosFlujoSospechosos = sum(
        len(conv.conexiones) for conv in conversaciones
        if es_sospechosa(conv)
    )
    contadorConversaciones = len(conversaciones)
    contadorConversacionesSospechosas = sum(
        1 for conv in conversaciones
        if es_sospechosa(conv)
    )
    
    print(f"De {contadorRegistrosFlujo} registros de flujo, {contadorRegistrosFlujoSospechosos} fueron registrados flujos sospechosos. Porcentaje:{contadorRegistrosFlujoSospechosos/contadorRegistrosFlujo*100 if contadorRegistrosFlujo else 0:.4f}%")
    print(f"De {contadorConversaciones} conversaciones, {contadorConversacionesSospechosas} son sospechosas. Porcentaje {contadorConversacionesSospechosas/contadorConversaciones*100 if contadorConversaciones else 0:.4f}%")

def imprimir_resultado(conversaciones: list[Conversacion], ruta_archivo_resultado: str) -> None:
    """Imprime las conversaciones sospechosas ordenadas por puntuación en la terminal."""

    archivoOutput = os.path.join(ruta_archivo_resultado, ARCHIVO_RESULTADO)

    with open(archivoOutput, "w", encoding="utf-8", buffering=1024 * 1024) as f:
        f.write(f"\n{'Start (unix)':<16} {'Ending (unix)':<16} {'Start (UTC)':<20} {'Ending (UTC)':<20} {'Proto':<5} {'IpSrc':<15} {'IpDst':<15} {'h':^7} {'No. Ports':<10} {'No. Unique':<12} {'Target Ports'}\n")
        f.write("-" * 210)
        f.write("\n")

        for conv in conversaciones:
            if es_sospechosa(conv):
                t_first = conv.conexiones[0][0]
                t_last  = max(c[1] for c in conv.conexiones)

                t_first_human = datetime.datetime.fromtimestamp(t_first, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                t_last_human = datetime.datetime.fromtimestamp(t_last, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

                puertoDestino = ",".join(f"{c[3]}" for c in conv.conexiones)
                 
                f.write((
                    f"{t_first:<16.2f} {t_last:<16.2f} {t_first_human:<20} {t_last_human:<20} {conv.protocolo:<5} {conv.srcIp:<15} {conv.dstIp:<15}"
                    f" {conv.h or 0:^7.2f}"
                    f" {len(conv.conexiones):^10}"
                    f" {len({c[3] for c in conv.conexiones}):^12}"
                    f" {puertoDestino}"
                    f"\n"
                )) 

def imprimir_resultado_json(conversaciones: list[Conversacion], ruta_archivo_resultado: str, archivo_pcap : str = "undefined", borrar_json : bool = True) -> None:
    """Imprime las conversaciones sospechosas en JSON, con el mismo formato que el script de Sangeen.
    Los resultados se acumulan sobre el archivo existente, para poder ir juntando varias ejecuciones si borrar_json = false. Por defecto, sobreescribimos"""

    archivoOutput = os.path.join(ruta_archivo_resultado, ARCHIVO_RESULTADO_JSON)

    if os.path.exists(archivoOutput) and not(borrar_json):
        with open(archivoOutput, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
    else:
        data = []

    sospechosas = [conv for conv in conversaciones if es_sospechosa(conv)]

    for conv in sospechosas:
        data.append({
            'ipSource': conv.srcIp,
            'ipDestination': conv.dstIp,
            'protocol': conv.protocolo,
            'portsDestination': sorted({int(c[3]) for c in conv.conexiones}),
            'entropy' : conv.h,
            'startTime': conv.conexiones[0][0],
            'file' : archivo_pcap
        })

    with open(archivoOutput, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)
        print(f"Resultados guardados en {archivoOutput}, {len(sospechosas)} sospechosos detectados.")


def es_sospechosa(conversacion: Conversacion) -> bool:
    """Decide si una conversación es sospechosa y merece aparecer en la lista final"""
    tiene_suficientes_intentos = len({c[3] for c in conversacion.conexiones}) > THRESHOLD_PUERTOS_UNICOS
    tiene_entropia_suficiente = True # conversacion.h > THRESHOLD_ENTROPIA 
    proporcion_sondeos = conversacion.flujosSondeo / conversacion.flujosTotales
    if conversacion.protocolo == "TCP":
        proporcion_sondeos_suficiente = proporcion_sondeos > THRESHOLD_PROPORCION_SONDEOS_TCP
    else:
        proporcion_sondeos_suficiente = proporcion_sondeos > THRESHOLD_PROPORCION_SONDEOS_UDP

    return (
        tiene_suficientes_intentos
        and tiene_entropia_suficiente
        and proporcion_sondeos_suficiente
    )
