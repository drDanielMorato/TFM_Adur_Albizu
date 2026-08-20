"""
Script inicial para encontrar escaneos TCP SYN Scan.
"""

from __future__ import annotations
from utils import parseArgs, imprimir_resultado, imprimir_resultado_json, imprimirEstadisticas, localizar_archivos_flujos
from procesado import procesar_archivo_flujos_tcp, procesar_archivo_flujos_udp, calcular_h
import time
import datetime
import sys
import traceback

def main() -> None:
    try:
        inicio = time.time()

        args = parseArgs()
        ruta_archivos_flujos = args.rutaOrigen
        ruta_archivo_resultado = args.rutaDestino

        archivo_tcp, archivo_udp =  localizar_archivos_flujos(ruta_archivos_flujos)

        conversaciones_tcp, registros_tcp = procesar_archivo_flujos_tcp(archivo_tcp)
        conversaciones_udp, registros_udp = procesar_archivo_flujos_udp(archivo_udp)

        conversaciones = conversaciones_tcp + conversaciones_udp
        contadorRegistrosFlujo = registros_tcp + registros_udp

        # Calculamos los valores para h de cada conversacion
        for conv in conversaciones:
            calcular_h(conv)

        imprimirEstadisticas(conversaciones, contadorRegistrosFlujo)

        # Imprimimos resultado en terminal:
        imprimir_resultado(conversaciones, ruta_archivo_resultado)
        imprimir_resultado_json(conversaciones, ruta_archivo_resultado)

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
