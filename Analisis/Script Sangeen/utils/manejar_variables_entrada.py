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
        "--rutaDestino",
        "-d",
        required=True,
        help="Directorio donde dejaremos los resultados del análisis"
    )

    return parser.parse_args()
