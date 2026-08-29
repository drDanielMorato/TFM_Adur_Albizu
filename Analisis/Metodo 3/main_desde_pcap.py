"""
Script inicial para encontrar escaneos TCP SYN Scan.
"""

from __future__ import annotations
import os
from utils import parseArgs, imprimir_resultado, imprimir_resultado_json, imprimirEstadisticas, localizar_archivos_flujos_opcionales, obtener_lista_archivos_pcap
from procesado import procesar_archivo_flujos_tcp, procesar_archivo_flujos_udp, calcular_h
from procesado import lanzar_procesaconexiones
import time
import datetime
import sys
import traceback

def main() -> None:
    # este script sirve para extraer los datos directamente desde pcaps,
    # convertir al output de procesaConexiones y lanzar el algoritmo
    try:
        inicio = time.time()

        args = parseArgs()
        ruta_archivos_pcaps = args.rutaOrigen
        ruta_archivo_resultado = args.rutaDestino

        os.makedirs(ruta_archivo_resultado, exist_ok=True)

        archivos_pcap = obtener_lista_archivos_pcap(ruta_archivos_pcaps)
        total_pcaps = len(archivos_pcap)
        pcaps_procesados = 0
        pcaps_omitidos = 0
        borrar_json = True

        for archivo_entrada in archivos_pcap:
            ruta_completa = os.path.join(ruta_archivos_pcaps, archivo_entrada)

            nombre_pcap = os.path.splitext(os.path.basename(archivo_entrada))[0]
            ruta_archivos_salida = os.path.join(ruta_archivo_resultado, "registrosFlujo", nombre_pcap)
            os.makedirs(ruta_archivos_salida, exist_ok=True)

            # procesaConexiones usa --outputFile como prefijo de ficheros, no como directorio
            prefijo_salida_flujos = os.path.join(ruta_archivos_salida, "salida")
            lanzar_procesaconexiones(ruta_completa, prefijo_salida_flujos)

            archivo_tcp, archivo_udp = localizar_archivos_flujos_opcionales(ruta_archivos_salida)

            conversaciones_tcp = []
            conversaciones_udp = []
            registros_tcp = 0
            registros_udp = 0

            if archivo_tcp:
                conversaciones_tcp, registros_tcp = procesar_archivo_flujos_tcp(archivo_tcp)

            if archivo_udp:
                conversaciones_udp, registros_udp = procesar_archivo_flujos_udp(archivo_udp)

            if not archivo_tcp and not archivo_udp:
                print(f"No se encontraron ficheros de flujos TCP/UDP para {archivo_entrada}; se omite.")
                pcaps_omitidos += 1
                continue

            conversaciones = conversaciones_tcp + conversaciones_udp
            contadorRegistrosFlujo = registros_tcp + registros_udp

            # Calculamos los valores para h de cada conversacion
            for conv in conversaciones:
                calcular_h(conv)

            print(f"procesando {ruta_completa}...")
            imprimirEstadisticas(conversaciones, contadorRegistrosFlujo)

            # Imprimimos resultado en terminal:
            # imprimir_resultado(conversaciones, ruta_archivo_resultado)
            imprimir_resultado_json(
                conversaciones,
                ruta_archivo_resultado,
                ruta_completa,
                borrar_json=borrar_json,
            )
            borrar_json = False
            pcaps_procesados += 1

        print(
            f"Resumen pcaps: total={total_pcaps}, procesados={pcaps_procesados}, omitidos={pcaps_omitidos}"
        )

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