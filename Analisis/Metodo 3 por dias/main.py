"""
Método 3 aplicado día a día, pensado para volúmenes grandes de registros de flujo (semanas de captura).
Para cada día escribe el TXT de sospechosas en un subdirectorio propio (rutaDestino/AAAA-MM-DD/)
y libera la memoria antes de pasar al siguiente. Al final escribe, por día, el número de conversaciones
totales (benignas + sospechosas), las sospechosas y su porcentaje.
La lógica de conversaciones y el criterio de sospecha son los del directorio 'Metodo 3'.
"""

from __future__ import annotations
import os
from utils import parseArgs, imprimir_resultado, imprimirEstadisticas, localizar_archivos_flujos, acumular_estadisticas_dia, imprimir_estadisticas_por_dia
from procesado import procesar_archivo_flujos_tcp_por_dias, procesar_archivo_flujos_udp_por_dias, calcular_h, Conversacion
import time
import datetime
import sys
import traceback

def analizar_dia(
    dia: datetime.date,
    protocolo: str,
    conversaciones: list[Conversacion],
    contadorRegistrosFlujo: int,
    contadorFlujosDesordenados: int,
    ruta_archivo_resultado: str,
    estadisticas: dict[datetime.date, dict[str, dict[str, int]]],
) -> None:
    """Puntúa, cuenta y vuelca a disco las conversaciones de un día. Tras la llamada no queda ninguna referencia a ellas."""

    for conv in conversaciones:
        calcular_h(conv)

    # print(f"\nDía {dia} ({protocolo}):")
    # imprimirEstadisticas(conversaciones, contadorRegistrosFlujo)

    aniadir_resultado = dia in estadisticas
    acumular_estadisticas_dia(
        estadisticas,
        dia,
        protocolo,
        conversaciones,
        contadorRegistrosFlujo,
        contadorFlujosDesordenados,
    )

    ruta_dia = os.path.join(ruta_archivo_resultado, dia.isoformat())
    os.makedirs(ruta_dia, exist_ok=True)
    imprimir_resultado(conversaciones, ruta_dia, aniadir=aniadir_resultado)

def main() -> None:
    try:
        inicio = time.time()

        args = parseArgs()
        ruta_archivos_flujos = args.rutaOrigen
        ruta_archivo_resultado = args.rutaDestino

        os.makedirs(ruta_archivo_resultado, exist_ok=True)

        archivo_tcp, archivo_udp = localizar_archivos_flujos(ruta_archivos_flujos)

        estadisticas: dict[datetime.date, dict[str, dict[str, int]]] = {}

        for dia, conversaciones, registros, desordenados in procesar_archivo_flujos_tcp_por_dias(archivo_tcp):
            analizar_dia(dia, "TCP", conversaciones, registros, desordenados, ruta_archivo_resultado, estadisticas)

        for dia, conversaciones, registros, desordenados in procesar_archivo_flujos_udp_por_dias(archivo_udp):
            analizar_dia(dia, "UDP", conversaciones, registros, desordenados, ruta_archivo_resultado, estadisticas)

        imprimir_estadisticas_por_dia(estadisticas, ruta_archivo_resultado)

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
