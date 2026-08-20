"""
Script que implementa el método de Neu et al. 
"""

from __future__ import annotations
from utils import parseArgs, imprimir_resultado, localizar_archivo_tcp
from procesado import procesar
import time
import datetime
import sys
import traceback

def main() -> None:
    try:
        inicio = time.time()

        args = parseArgs()
        ruta_directorio_flujos = args.rutaOrigen
        ruta_archivo_resultado = args.rutaDestino

        archivo_tcp = localizar_archivo_tcp(ruta_directorio_flujos)
        sospechosos = procesar(archivo_tcp)
        imprimir_resultado(sospechosos, ruta_archivo_resultado)

    except Exception as e:
        print(f"Fallo inesperado en el script: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        fin = time.time()
        tiempo_total = str(datetime.timedelta(seconds=fin - inicio))
        print(f"\nTiempo total: {tiempo_total}")

if __name__ == "__main__":
    main()
