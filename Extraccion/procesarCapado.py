# Este script se utilizará para generar logs de procesaConexiones. No añado módulos ni nada especial, estoy usando este script para hacer procesamientos sencillos
# y medir el tiempo   
# accediendo a los discos montados en los directorios /trazas1, /trazas2 y /trazas3.
# Los resultados irán al disco limpio en /opt2.

import subprocess
import sys
import time
import datetime
import traceback
import os
import argparse

# DIRECTORIO_MONTAJE1 = "/trazas1"
# DIRECTORIO_MONTAJE2 = "/trazas2"
# DIRECTORIO_MONTAJE3 = "/trazas3" # Aquí están los discos con pcaps 

# DIRECTORIO_MONTAJE_LIMPIO = "/opt2/adur"  # Aquí está el disco limpio. 

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ejecuta procesaConexiones y tseries sobre el directorio de montaje del disco indicado. Se debe indicar también el disco donde se almacenarán las trazas resultantes"
    )

    parser.add_argument(
        "--rutaOrigen",
        required=True,
        help="Directorio de montaje del direcorio a procesar (ej: /trazas1)"
    )
    parser.add_argument(
        "--rutaDestino",
        required=True,
        help="Ruta secundaria (ej: /opt2)"
    )

    return parser.parse_args()

def obtener_serial(directorio):
    """Obtiene el número de serie del disco montado en el directorio indicado."""
    try:
        result = subprocess.run(
            f'lsblk -no SERIAL $(df -P {directorio} | awk \'NR==2{{print $1}}\' | sed \'s/[0-9]*$//\')',
            shell=True,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"El comando falló para {directorio}: {result.stderr.strip()}")

        seriales = result.stdout.strip().splitlines()

        if len(seriales) == 0:
            raise ValueError(f"No se obtuvo ningún serial para {directorio}")

        if len(seriales) > 1:
            raise ValueError(f"Se obtuvieron múltiples seriales para {directorio}: {seriales}")

        return seriales[0]

    except ValueError as e:
        print(f"[ERROR] Valor inesperado: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[ERROR] Error en la ejecución del comando: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error inesperado al obtener serial de {directorio}: {e}")
        sys.exit(1)

def listarDirectorio(directorio):
    """ Realiza un simple ls"""
    result = subprocess.run(
            f"ls {directorio} ",
            shell=True,
            capture_output=True,
            text=True
        )

    if result.returncode != 0:
        raise RuntimeError(f"El comando falló para {directorio}: {result.stderr.strip()}")

    return result.stdout.strip().splitlines()
    
def obtenerTimestamp(directorio):
    """Obtiene el timestamp del primer pcap del directorio"""

    directorios = listarDirectorio(directorio)

    if len(directorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    directoriosFiltrados = [f for f in directorios if "lost+found" not in f]
    directoriosFiltrados.sort(key=lambda x: int(x.split('-')[0]))
    # estamos en los directorios superiores, cogemos el de la timestamp más baja 

    directorioObjetivo = directorio + "/" + directoriosFiltrados[0]

    archivosDirectorioObjetivo = listarDirectorio(directorioObjetivo)
    if len(archivosDirectorioObjetivo) == 0:
        raise ValueError(f"Directorio {directorio} vacío")
    archivosDirectorioObjetivo.sort(key=lambda x: int(x.split('.')[0]))

    return archivosDirectorioObjetivo[0].split(".")[0] #Devuelvo el primer timestamp, sin el gz   

def lanzarProcesarConexiones(directorioInput, directorioOutput):
    comando = ["procesaConexiones" , "--inputFile", directorioInput, "--outputFile", directorioOutput+"/salida", "--procesarICMP", "--dirOfFiles", "--showGlobals"]
    print("Ejecutando comando:", " ".join(comando))
    
    result = subprocess.run(comando, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise RuntimeError(f"El comando procesaConexiones falló: {result.stderr.strip()}")


def main():
    
    args = parse_args()
    
    try:
        start = time.time()

        directorioOrigen = args.rutaOrigen
        directorioDestino = args.rutaDestino     #no hardcodeo aquí mi nombre pero no olvidarme de que debe ir en el comando.

        serial_trazas = obtener_serial(directorioOrigen)
        nombre_trazas = obtenerTimestamp(directorioOrigen)
        directorioPadreFinalActual = f"{serial_trazas}_{nombre_trazas}"

        directorios = listarDirectorio(directorioOrigen)
        if len(directorios) == 0:
            raise ValueError(f"Directorio {directorioOrigen} vacío")

        directoriosFiltrados = [f for f in directorios if "lost+found" not in f]

        for d in directoriosFiltrados:
            directorioInput = directorioOrigen + "/" + d
            directorioOutput = directorioDestino + "/" + directorioPadreFinalActual + "/" + d
            print(f"Directorio de guardado: {directorioOutput}")

            # hay que otorgar permisos de escritura sobre el escritorio, por defecto no se dan
            os.makedirs(directorioOutput, exist_ok=True)
            os.chmod(directorioOutput, 0o777)

            lanzarProcesarConexiones(directorioInput, directorioOutput)

        print(f"{directorioOrigen} procesado satisfactoriamente")


    except Exception as e:
        print(f"[ERROR] Fallo inesperado en el script: {e}")
        print(f"[ERROR] Stack trace:\n{traceback.format_exc()}")
        sys.exit(1)

    finally:
        end = time.time()
        tiempo_total = str(datetime.timedelta(seconds=end-start))
        print(f"\nTiempo total (H:MM:SS.MM): {tiempo_total}")


if __name__ == "__main__":
    main()