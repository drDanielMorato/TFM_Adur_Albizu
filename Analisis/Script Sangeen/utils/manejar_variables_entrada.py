import argparse

def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ejecuta script de análisis"
    )
    parser.add_argument(
        "--rutaOrigen",
        "-o",
        required=True,
        help="Directorio donde se encuentran los pcaps a analizar"
    )
    parser.add_argument(
        "--archivoDestino",
        "-d",
        required=True,
        help="Archivo en el que dejaremos los resultados del análisis"
    )

    return parser.parse_args()
