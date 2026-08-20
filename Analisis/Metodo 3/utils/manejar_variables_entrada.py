import argparse

def parseArgs() -> argparse.Namespace:
    """Parsea y valida los argumentos de la línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Ejecuta script de análisis"
    )
    parser.add_argument(
        "--rutaOrigen",
        "-o",
        required=True,
        help="Directorio donde se encuentra el archivo de con los registros de flujo"
    )
    parser.add_argument(
        "--rutaDestino",
        "-d",
        required=True,
        help="Directorio donde queremos montar el resultado"
    )

    return parser.parse_args()
