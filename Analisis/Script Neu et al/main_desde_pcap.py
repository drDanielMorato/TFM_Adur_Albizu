"""Ejecuta el metodo de Neu et al. sobre un directorio de PCAP."""

import datetime
import os
import sys
import time
import traceback

from config import ARCHIVO_RESULTADO_JSON
from procesado import lanzar_procesaconexiones, procesar
from utils import (
    imprimir_resultado,
    localizar_archivo_tcp_opcional,
    obtener_lista_archivos_pcap,
    parseArgs,
)


def main() -> None:
    inicio = time.time()
    try:
        args = parseArgs()
        directorio_pcaps = os.path.abspath(args.rutaOrigen)
        directorio_resultado = os.path.abspath(args.rutaDestino)

        if not os.path.isdir(directorio_pcaps):
            raise ValueError(f"No existe el directorio de PCAP: {directorio_pcaps}")

        archivos_pcap = obtener_lista_archivos_pcap(directorio_pcaps)
        if not archivos_pcap:
            raise ValueError(f"No se encontraron PCAP en: {directorio_pcaps}")

        os.makedirs(directorio_resultado, exist_ok=True)
        archivo_resultado = os.path.join(directorio_resultado, ARCHIVO_RESULTADO_JSON)
        primera_escritura = True
        pcaps_procesados = 0
        pcaps_omitidos = 0

        for ruta_pcap in archivos_pcap:
            ruta_relativa = os.path.relpath(ruta_pcap, directorio_pcaps)
            ruta_sin_extension = os.path.splitext(ruta_relativa)[0]
            directorio_flujos = os.path.join(
                directorio_resultado, "registrosFlujoNeu", ruta_sin_extension
            )
            os.makedirs(directorio_flujos, exist_ok=True)

            prefijo_flujos = os.path.join(directorio_flujos, "salida")
            lanzar_procesaconexiones(ruta_pcap, prefijo_flujos)
            archivo_tcp = localizar_archivo_tcp_opcional(directorio_flujos)

            if archivo_tcp is None:
                print(f"Sin flujos TCP en {ruta_pcap}; se omite.")
                pcaps_omitidos += 1
                continue

            candidatos = procesar(archivo_tcp)
            imprimir_resultado(
                candidatos,
                archivo_resultado,
                archivo_pcap=ruta_pcap,
                borrar_json=primera_escritura,
            )
            primera_escritura = False
            pcaps_procesados += 1

        if primera_escritura:
            imprimir_resultado([], archivo_resultado)

        print(
            f"Resumen PCAP: total={len(archivos_pcap)}, "
            f"procesados={pcaps_procesados}, omitidos={pcaps_omitidos}"
        )
    except Exception as error:
        print(f"Fallo inesperado en el script: {error}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        duracion = datetime.timedelta(seconds=time.time() - inicio)
        print(f"\nTiempo total: {duracion}")


if __name__ == "__main__":
    main()