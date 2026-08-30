from __future__ import annotations

import argparse
import heapq
import os
from collections.abc import Iterator


COL_IP_ORIGEN = 0
COL_IP_DESTINO = 2
COL_TIEMPO_INICIO = 4
PATRONES_PROTOCOLO = {"TCP": "_tcp_", "UDP": "_udp_"}


def localizar_archivos_flujo(directorio: str) -> list[tuple[str, str]]:
    """Localiza salidas TCP/UDP no vacias de procesaConexiones."""
    archivos = []
    for raiz, _, nombres in os.walk(directorio):
        for nombre in nombres:
            ruta = os.path.join(raiz, nombre)
            for protocolo, patron in PATRONES_PROTOCOLO.items():
                if patron in nombre and os.path.getsize(ruta) > 0:
                    archivos.append((protocolo, ruta))
                    break
    return sorted(archivos, key=lambda elemento: elemento[1])


def leer_flujos_ordenados(
    ruta_archivo: str, ventana_reordenado: float
) -> Iterator[tuple[float, str, str]]:
    """Emite inicio e IPs de los flujos, ordenados mediante un watermark."""
    buffer = []
    maximo_timestamp = float("-inf")
    ultimo_emitido = float("-inf")

    with open(ruta_archivo, "rb") as archivo:
        for orden, linea in enumerate(archivo):
            columnas = linea.split()
            try:
                timestamp = float(columnas[COL_TIEMPO_INICIO])
                ip_origen = columnas[COL_IP_ORIGEN].decode()
                ip_destino = columnas[COL_IP_DESTINO].decode()
            except (IndexError, UnicodeDecodeError, ValueError) as error:
                raise RuntimeError(
                    f"Registro invalido en {ruta_archivo}: {linea[:80]}"
                ) from error

            if timestamp < ultimo_emitido:
                raise ValueError(
                    f"Desorden temporal superior a {ventana_reordenado} s en "
                    f"{ruta_archivo}: {timestamp} < {ultimo_emitido}"
                )

            maximo_timestamp = max(maximo_timestamp, timestamp)
            heapq.heappush(buffer, (timestamp, orden, ip_origen, ip_destino))
            marca_de_agua = maximo_timestamp - ventana_reordenado

            while buffer and buffer[0][0] <= marca_de_agua:
                inicio, _, origen, destino = heapq.heappop(buffer)
                ultimo_emitido = inicio
                yield inicio, origen, destino

    while buffer:
        inicio, _, origen, destino = heapq.heappop(buffer)
        yield inicio, origen, destino


def contar_conversaciones(
    ruta_archivo: str, intervalo_inactividad: float, ventana_reordenado: float
) -> tuple[int, int]:
    ultima_actividad_por_pareja = {}
    conversaciones = 0
    flujos = 0

    for inicio, ip_origen, ip_destino in leer_flujos_ordenados(
        ruta_archivo, ventana_reordenado
    ):
        pareja = (ip_origen, ip_destino)
        ultima_actividad = ultima_actividad_por_pareja.get(pareja)
        if ultima_actividad is None or inicio - ultima_actividad > intervalo_inactividad:
            conversaciones += 1
        ultima_actividad_por_pareja[pareja] = inicio
        flujos += 1

    return conversaciones, flujos


def calcular_poblacion(
    directorio: str, intervalo_inactividad: float, ventana_reordenado: float
) -> dict[str, int]:
    archivos = localizar_archivos_flujo(directorio)
    if not archivos:
        raise ValueError(
            f"No se encontraron archivos salida_tcp_/salida_udp_ en {directorio}"
        )

    resultado = {
        "conversaciones_tcp": 0,
        "conversaciones_udp": 0,
        "flujos_tcp": 0,
        "flujos_udp": 0,
        "archivos_procesados": len(archivos),
    }

    for protocolo, ruta_archivo in archivos:
        conversaciones, flujos = contar_conversaciones(
            ruta_archivo, intervalo_inactividad, ventana_reordenado
        )
        resultado[f"conversaciones_{protocolo.lower()}"] += conversaciones
        resultado[f"flujos_{protocolo.lower()}"] += flujos
        print(f"{ruta_archivo}: {conversaciones} conversaciones, {flujos} flujos")

    resultado["N"] = resultado["conversaciones_tcp"] + resultado["conversaciones_udp"]
    return resultado


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Cuenta la poblacion de conversaciones benignas de CICIDS2017 "
            "a partir de las salidas de procesaConexiones."
        )
    )
    parser.add_argument(
        "directorio_flujos",
        help="Directorio que contiene salida_tcp_ y salida_udp_, recursivamente.",
    )
    parser.add_argument(
        "--intervalo-inactividad",
        type=float,
        default=30.0,
        help="Segundos de inactividad que separan conversaciones (default: 30).",
    )
    parser.add_argument(
        "--ventana-reordenado",
        type=float,
        default=32000.0,
        help="Ventana para reordenar flujos por timestamp (default: 32000 s).",
    )
    args = parser.parse_args()

    if args.intervalo_inactividad < 0 or args.ventana_reordenado < 0:
        raise ValueError("Los intervalos deben ser positivos o cero.")

    resultado = calcular_poblacion(
        args.directorio_flujos,
        args.intervalo_inactividad,
        args.ventana_reordenado,
    )

    print()
    print(f"Archivos procesados: {resultado['archivos_procesados']}")
    print(f"Flujos TCP: {resultado['flujos_tcp']}")
    print(f"Flujos UDP: {resultado['flujos_udp']}")
    print(f"Conversaciones TCP: {resultado['conversaciones_tcp']}")
    print(f"Conversaciones UDP: {resultado['conversaciones_udp']}")
    print(f"N (conversaciones benignas): {resultado['N']}")


if __name__ == "__main__":
    main()