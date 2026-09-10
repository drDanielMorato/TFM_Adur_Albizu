"""Generamos una línea temporal para mostrar todos los ataques y duración (de una ip a otra en concreto="""

import argparse

from linea_tiempo_ataques import ARCHIVO_ENTRADA, generarGraficoLineaTiempoAtaques


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archivo", default=ARCHIVO_ENTRADA, help="Ruta del resultado.txt")
    parser.add_argument("--directorioGuardado", help="Directorio donde guardar el PNG resultante (opcional)")
    parser.add_argument("--no-mostrar", action="store_true", help="Solo guarda el PNG, no abre la ventana")
    args = parser.parse_args()

    generarGraficoLineaTiempoAtaques(args.archivo, args.directorioGuardado, not args.no_mostrar)


if __name__ == "__main__":
    main()
