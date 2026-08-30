"""Ejecuta Sangeen sobre PCAP independientes y acumula sus candidatos."""

import argparse
import datetime
import os
import sys
import time
import traceback

from config import ARCHIVO_RESULTADO_JSON
from procesado import procesar_pcap
from utils import imprimir_resultado, listar_pcaps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ejecuta Sangeen sobre un directorio de PCAP independientes."
    )
    parser.add_argument("--rutaOrigen", "-o", required=True, help="Directorio de PCAP.")
    parser.add_argument("--rutaDestino", "-d", required=True, help="Directorio de salida.")
    return parser.parse_args()


def main() -> None:
    inicio = time.time()
    try:
        args = parse_args()
        directorio_pcaps = os.path.abspath(args.rutaOrigen)
        directorio_resultado = os.path.abspath(args.rutaDestino)

        if not os.path.isdir(directorio_pcaps):
            raise ValueError(f"No existe el directorio de PCAP: {directorio_pcaps}")

        archivos_pcap = listar_pcaps(directorio_pcaps)
        if not archivos_pcap:
            raise ValueError(f"No se encontraron PCAP en: {directorio_pcaps}")

        os.makedirs(directorio_resultado, exist_ok=True)
        archivo_resultado = os.path.join(directorio_resultado, ARCHIVO_RESULTADO_JSON)

        for indice, ruta_pcap in enumerate(archivos_pcap):
            candidatos = procesar_pcap(ruta_pcap)
            imprimir_resultado(
                candidatos,
                archivo_resultado,
                borrar_json=(indice == 0),
            )

        print(f"Resumen PCAP: total={len(archivos_pcap)}, procesados={len(archivos_pcap)}")
    except Exception as error:
        print(f"Fallo inesperado en el script: {error}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        duracion = datetime.timedelta(seconds=time.time() - inicio)
        print(f"\nTiempo total: {duracion}")


if __name__ == "__main__":
    main()