"""
Punto de entrada del procesado masivo.

Recorre /exploracion2/disco{1..4}/<dia>/, lee el unico .txt de cada carpeta de
dia y guarda las cuatro graficas en /exploracion2/imagenes/<dia>/.
Los .txt sueltos dentro de las carpetas disco se ignoran.
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from implementaciones import (  # noqa: E402
    generarGraficoActividadTemporalAtaques,
    generarGraficoCDFPuertosUnicos,
    generarGraficoDensidadDuracionAtaques,
    generarHistogramaNumeroPuertos,
)
from ranking import (  # noqa: E402
    dia_excluido,
    escribir_ranking_dia,
    escribir_ranking_global,
    fusionar_contactos,
)
from utils.lectura import leer_registros  # noqa: E402

ENTRADA_POR_DEFECTO = "/VD0_4SAS8TB_R5/TfmTrazas/adur.albizu/exploracion2"
SALIDA_POR_DEFECTO = "/VD0_4SAS8TB_R5/TfmTrazas/adur.albizu/exploracion2/imagenes"
NOMBRE_SALIDA = "imagenes"


def _buscar_carpetas_dia(directorio_entrada):
    """Devuelve [(nombre_disco, nombre_dia, ruta_dia), ...] ordenado."""
    carpetas = []

    for nombre_disco in sorted(os.listdir(directorio_entrada)):
        ruta_disco = os.path.join(directorio_entrada, nombre_disco)
        if not os.path.isdir(ruta_disco) or nombre_disco == NOMBRE_SALIDA:
            continue

        for nombre_dia in sorted(os.listdir(ruta_disco)):
            ruta_dia = os.path.join(ruta_disco, nombre_dia)
            if os.path.isdir(ruta_dia):
                carpetas.append((nombre_disco, nombre_dia, ruta_dia))

    return carpetas


def _buscar_txt(ruta_dia):
    """Devuelve el unico .txt de la carpeta del dia, o None."""
    ficheros = [f for f in sorted(os.listdir(ruta_dia))
                if f.lower().endswith(".txt") and os.path.isfile(os.path.join(ruta_dia, f))]

    if not ficheros:
        return None

    if len(ficheros) > 1:
        print(f"  Aviso: {len(ficheros)} .txt en {ruta_dia}; se usa {ficheros[0]}")

    return os.path.join(ruta_dia, ficheros[0])


def procesar_dia(ruta_txt, directorio_salida, prefijo, nombre_dia, contactos_globales):
    os.makedirs(directorio_salida, exist_ok=True)

    registros = leer_registros(ruta_txt)

    generarHistogramaNumeroPuertos(registros, directorio_salida, prefijo)
    generarGraficoCDFPuertosUnicos(registros, directorio_salida, prefijo)
    generarGraficoActividadTemporalAtaques(registros, directorio_salida, prefijo)
    generarGraficoDensidadDuracionAtaques(registros, directorio_salida, prefijo)

    if dia_excluido(nombre_dia):
        print("  Dia excluido del ranking")
        return False

    escribir_ranking_dia(registros.contactos, directorio_salida, prefijo)
    fusionar_contactos(contactos_globales, registros.contactos)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Genera las graficas de cada dia a partir de los resultado.txt de exploracion2"
    )
    parser.add_argument("--entrada", default=ENTRADA_POR_DEFECTO,
                        help="Carpeta que contiene disco1..disco4")
    parser.add_argument("--directorioGuardado", default=SALIDA_POR_DEFECTO,
                        help="Carpeta donde crear una subcarpeta por dia con las imagenes")

    args = parser.parse_args()

    if not os.path.isdir(args.entrada):
        parser.error(f"No existe la carpeta de entrada: {args.entrada}")

    carpetas = _buscar_carpetas_dia(args.entrada)
    if not carpetas:
        print(f"No se han encontrado carpetas de dia en {args.entrada}")
        return

    # Si un mismo dia aparece en varios discos, el prefijo lleva el disco para no pisar ficheros.
    repeticiones = Counter(dia for _, dia, _ in carpetas)

    print(f"Carpetas de dia encontradas: {len(carpetas)}")

    contactos_globales = {}
    dias_incluidos = []
    dias_descartados = 0

    for indice, (disco, dia, ruta_dia) in enumerate(carpetas, start=1):
        ruta_txt = _buscar_txt(ruta_dia)
        print(f"[{indice}/{len(carpetas)}] {disco}/{dia}")

        if ruta_txt is None:
            print("  Sin .txt en la carpeta; se omite")
            continue

        prefijo = dia if repeticiones[dia] == 1 else f"{disco}_{dia}"
        directorio_salida = os.path.join(args.directorioGuardado, dia)

        try:
            incluido = procesar_dia(ruta_txt, directorio_salida, prefijo, dia, contactos_globales)
        except Exception as error:  # una carpeta corrupta no debe parar el lote entero
            print(f"  Error procesando {ruta_txt}: {error}")
            continue

        if incluido:
            dias_incluidos.append(dia)
        else:
            dias_descartados += 1

        print(f"  Guardado en {directorio_salida}")

    ruta_global = escribir_ranking_global(
        contactos_globales, args.directorioGuardado, dias_incluidos, dias_descartados
    )
    print(f"Ranking global guardado en {ruta_global}")
    print("Procesado terminado")


if __name__ == "__main__":
    main()
