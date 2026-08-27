import subprocess
from config import RUTA_BINARIO_PROCESACONEXIONES

def lanzar_procesaconexiones(ruta_archivo_entrada: str, ruta_archivo_salida: str) -> None:
    """
    Lanza procesaConexiones, para un único pcap
    """

    comando = [
        RUTA_BINARIO_PROCESACONEXIONES,
        "--inputFile", ruta_archivo_entrada,
        "--outputFile", ruta_archivo_salida,
        "--ramLimit", "15000",
        "--procesarICMP",
        "--hilosProcesado", "1",
    ]

    # print("Ejecutando comando:")
    # print(" ".join(str(arg) for arg in comando))
    
    result = subprocess.run(comando, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"El comando procesaConexiones falló: {result.stderr.strip()}")

    