import subprocess

from config import RUTA_BINARIO_PROCESACONEXIONES


def lanzar_procesaconexiones(ruta_archivo_entrada: str, ruta_archivo_salida: str) -> None:
    """Extrae los registros de flujo de un único PCAP."""
    comando = [
        RUTA_BINARIO_PROCESACONEXIONES,
        "--inputFile", ruta_archivo_entrada,
        "--outputFile", ruta_archivo_salida,
        "--ramLimit", "15000",
        "--procesarICMP",
        "--hilosProcesado", "1",
    ]
    resultado = subprocess.run(comando, capture_output=True, text=True)
    if resultado.returncode != 0:
        raise RuntimeError(
            f"El comando procesaConexiones fallo: {resultado.stderr.strip()}"
        )