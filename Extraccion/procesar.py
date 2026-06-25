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
import mmap
import logging
import json
import re
import zipfile
import shutil
import configparser
import stat

ARCHIVO_ANALIZADO = "salida_udp_" # Archivo analizado para encontrar parejas de macs para tseries

# índice de las direcciones MAC en el fichero a analizar. De momento, UDP:

SRCMAC_SRC2DST = 23
DSTMAC_SRC2DST = 24
SRCMAC_DST2SRC = 25
DSTMAC_DST2SRC = 26
MOREMACSEEN = 27

# obtener configuraciones del config.ini
RUTA_CONFIGURACIONES_PROCESACONEXIONES = ""
RUTA_BINARIO_PROCESACONEXIONES = ""
RUTA_BINARIO_TSERIES = ""     
RUTA_MODULOS_PROCESACONEXIONES = ""

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
        help="Directorio de montaje del disco donde se van a almacenar los logs (ej: /opt2)"
    )
    parser.add_argument(
        "--rutaConfig",
        required=True,
        help="Directorio donde se almacena el archivo de configuraciones config.ini (ej: /opt3/Desktop/ScriptProcesado)"
    )

    parser.add_argument(
    "--zip",
    action="store_true",
    help="Si se indica, comprime el directorio de resultados en un zip al finalizar"
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
        logging.error(f"Valor inesperado: {e}")
        sys.exit(1)
    except RuntimeError as e:
        logging.error(f"Error en la ejecución del comando: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error inesperado al obtener serial de {directorio}: {e}")
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
    """Obtiene el timestamp del primer pcap del directorio para nombrar el directorio de salida del disco"""

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

def obtenerTimestampInicio(directorio):
    """Obtiene el timestamp inicial del disco, basándose en el archivo globals"""

    subdirectorios = listarDirectorio(directorio)

    if len(subdirectorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]
    subdirectoriosFiltrados.sort(key=lambda x: int(x.split('-')[0]))

    # cogemos el de la timestamp más bajo 
    archivoObjetivo = directorio + "/" + subdirectoriosFiltrados[0] + "/globals.txt"

    with open(archivoObjetivo, 'r') as f:
        contenido = f.read()

    match = re.search(r'tstampIni/fin/dif=\s*([\d.]+),([\d.]+),([\d.]+)', contenido)
    if not match:
        raise ValueError("No se encontró tstampIni en el archivo")
    
    return float(match.group(1))


def obtenerTimestampFinal(directorio):
    """Obtiene el timestamp inicial del disco, basándose en el archivo globals"""

    subdirectorios = listarDirectorio(directorio)

    if len(subdirectorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]
    subdirectoriosFiltrados.sort(key=lambda x: int(x.split('-')[0]))

    # cogemos el de la timestamp más bajo 
    archivoObjetivo = directorio + "/" + subdirectoriosFiltrados[-1] + "/globals.txt"

    with open(archivoObjetivo, 'r') as f:
        contenido = f.read()

    match = re.search(r'tstampIni/fin/dif=\s*([\d.]+),([\d.]+),([\d.]+)', contenido)
    if not match:
        raise ValueError("No se encontró tstampIni en el archivo")
    
    return float(match.group(2))

def extract_pcap_filters(input_path, output_path):
    filters = []
 
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            prefix = "--externArgs tseries:pcapFilter="
            if line.startswith(prefix):
                pcap_filter = line[len(prefix):].strip()
                filters.append(pcap_filter)
 
    with open(os.path.join(output_path, "filtrosBpfModuloTseriesProcesaConexiones.txt"), "w") as f:
        for i, pcap_filter in enumerate(filters):
            f.write(f"{i}: {pcap_filter}\n")

def lanzarProcesaConexiones(directorioInput, directorioOutput):
    
    logging.info("Inicio lanzarProcesaConexiones")
    
    with open(RUTA_CONFIGURACIONES_PROCESACONEXIONES, 'r') as f:
        plantilla = f.read()

    contenido = plantilla.format(inputDirectory = directorioInput, 
                    outputDirectory = os.path.join(directorioOutput,"salida"),
                    pathLogFile = os.path.join(directorioOutput, "procesaConexiones.log"),
                    outputFileModuloTseries = os.path.join(directorioOutput, "salidaModuloTseries"),
                    modulesDirectory = RUTA_MODULOS_PROCESACONEXIONES)
    
    rutaConfiguracionesProcesaConexiones = os.path.join(directorioOutput, "ConfiguracionesProcesaConexiones.txt")

    with open(rutaConfiguracionesProcesaConexiones, 'w') as f:
        f.write(contenido)

    extract_pcap_filters(rutaConfiguracionesProcesaConexiones, directorioOutput)    

    comando = [RUTA_BINARIO_PROCESACONEXIONES , "--configFile", rutaConfiguracionesProcesaConexiones]

    logging.info("Ejecutando comando:")
    logging.info(" ".join(comando))
    
    result = subprocess.run(comando, capture_output=True, text=True)

    with open(os.path.join(directorioOutput, "procesaConexiones.log"), "r") as f:
        salida = f.read()
    
    indice = salida.find("numIPFragments=")
    if indice == -1:
        raise RuntimeError(f"La lectura de procesaConexiones.log falló")

    salida_filtrada = salida[indice:]
    limite = salida_filtrada.find("\n")
    if limite != -1:
        salida_filtrada = salida_filtrada[:limite]

    # Escribir en el log el contenido con las estadísticas globales:
    with open(os.path.join(directorioOutput, "globals.txt"), "w") as f:
        f.write(salida_filtrada)

    if result.returncode != 0:
        raise RuntimeError(f"El comando procesaConexiones falló: {result.stderr.strip()}")
    # print(result)

    logging.info("Fin lanzarProcesaConexiones")

def obtenerParejasMACs(directorioOutput):
    # Lanzo esto para obtener las parejas de macs del log salida_udp
    # Es clave para obtener lls flujos de entrada/salida en la red

    archivoAnalizado = directorioOutput + "/" + ARCHIVO_ANALIZADO
    parejas = set()

    logging.info(f"Se inicia procesado de {archivoAnalizado}...")

    with open(archivoAnalizado, "rb") as f:
        #Mientras que el texto sea ascii puro, no hay problema de lectura. Cuidado si fuera unicode
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            while True:
                fila = mm.readline()
                if not fila:        # fin del archivo
                    break

                cols   = fila.split()
                macCliente1 = cols[SRCMAC_SRC2DST].decode()
                macServicio1 = cols[DSTMAC_SRC2DST].decode()
                macServicio2 = cols[SRCMAC_DST2SRC].decode()
                macCliente2 = cols[DSTMAC_DST2SRC].decode()
                numMacsAdicionales = int(cols[MOREMACSEEN])

                if numMacsAdicionales == 1:
                    logging.warning(f"Hay más MACs que las extraídas para el análisis de tseries")
                
                if macCliente1 != "(null)" and macServicio1 !="(null)":
                    parejas.add(frozenset((macCliente1, macServicio1)))

                if macCliente2 != "(null)" and macServicio2 !="(null)":
                    parejas.add(frozenset((macCliente2, macServicio2)))
              
    if len(parejas) == 0:
         logging.warning(f"No hay MACs para el análisis de tseries")

    logging.info(f"finaliza procesado de {archivoAnalizado}. Parejas MAC halladas: {parejas}")
    return parejas

def generar_filtros_bpf(mac):
    plantilla = """ether src {mac}
ether src {mac} and ip proto 1
ether src {mac} and ip proto 6
ether src {mac} and ip proto 17
ether src {mac} and not (ip proto 1 or ip proto 6 or ip proto 17)
ether src {mac} and tcp and (port 80 or port 443)
ether src {mac} and tcp and (port 20 or port 21)
ether src {mac} and tcp and port 22
ether src {mac} and tcp and port 23
ether src {mac} and tcp and port 445
ether src {mac} and tcp and port 3306
ether src {mac} and tcp and port 3389
ether src {mac} and tcp and port 5432
ether src {mac} and tcp and port 5900
ether src {mac} and udp and port 53
ether src {mac} and udp and port 69
ether src {mac} and udp and port 123
ether src {mac} and udp and (port 161 or port 162)
ether src {mac} and ip6
ether src {mac} and ip6 and not (ip6 proto 58 or ip6 proto 6 or ip6 proto 17)"""
    return plantilla.format(mac=mac)

def crearArchivoFiltrosBPF(directorioOutput):
    #Creo un archivo listando todos los filtros BPF y lo dejo a la vista 
    #en el directorio de salida.  
    parejasMacs = obtenerParejasMACs(directorioOutput)
    ruta = os.path.join(directorioOutput, "filtrosBpfTseries.txt")

    with open(ruta, "w") as f:
        for pareja in parejasMacs:
            for mac in pareja:
                f.write(generar_filtros_bpf(mac))
                f.write("\n")

    logging.info(f"Filtros BPF escritos en: {ruta}")
    return ruta

def crearFicheroListaGz(directorioInput, directorioOutput):
    #Creo archivo que guarda la lista de .gzs a procesar, ordenada en base a los timestamps
    
    files = os.listdir(directorioInput)
    files.sort(key=lambda x: int(x.split('.')[0]))

    ruta = os.path.join(directorioOutput, "listaFicherosGzTseries.txt")
    with open(ruta, "w") as f:
        for filename in files:
            f.write(os.path.join(directorioInput, filename))
            f.write("\n")
    return ruta


def lanzarTseries(directorioInput, directorioOutput):
    #Sirve para lanzar tseries contra las parejas de MACs halladas en los logs de procesaConexiones 
    logging.info("Inicio lanzarTseries")

    rutaFiltros = crearArchivoFiltrosBPF(directorioOutput)
    rutaLista = crearFicheroListaGz(directorioInput, directorioOutput)
    rutaDestino = os.path.join(directorioOutput, "salidaTseries.txt")
    rutaLogs = os.path.join(directorioOutput, "tseries.log")

    tseries_comand = [RUTA_BINARIO_TSERIES, "-v", "-m", "-i", rutaLista, "-f", rutaFiltros]
    result = subprocess.run(tseries_comand, capture_output=True, text=True)

    logging.info("Ejecutando comando:")
    logging.info(" ".join(tseries_comand))

    if result.returncode != 0:
        logging.warning(f"tseries ha fallado. Leer logs en: {rutaLogs}")

    with open(rutaDestino, "w") as f:
        f.write(result.stdout)

    with open(rutaLogs, "w") as f:
        f.write(result.stderr)

    logging.info(f"tseries lanzado satisfactoriamente. Resultados en: {rutaDestino}")
    logging.info("Fin lanzarTseries")

def configurarLogger(directorioDestino):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(os.path.join(directorioDestino, f"script_{timestamp}.log")),
            logging.StreamHandler()
        ]
    )

def timestamp2Duration(ts):
    ts = float(ts)
    dias = int(ts // 86400)
    horas = int((ts % 86400) // 3600)
    minutos = int((ts % 3600) // 60)
    segundos = int(ts % 60)
    milisegundos = int((ts % 1) * 1000)

    return f"{dias}d {horas:02d}:{minutos:02d}:{segundos:02d}.{milisegundos:03d}"

def obtenerUsoMemoria(directorio):
    """Obtiene la memoria usada/libre del disco indicado"""
    result = subprocess.run(
        f"df -B1 {directorio} | awk 'NR==2{{print $3,$4}}'",
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"El comando de extracción de datos de almacenamiento falló para {directorio}: {result.stderr.strip()}")

    datos = result.stdout.strip().split()

    if len(datos) == 0:
        raise ValueError(f"No se obtuvo ningún dato de almacenamiento para el disco montado en {directorio}")
   
    return datos


def extraerDatosGlobals(directorio):
    """Obtiene todas las variables de todos los globals.txt y las devuelve en un diccionario"""
    subdirectorios = listarDirectorio(directorio)
    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]

    if len(subdirectoriosFiltrados) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    datos = {}
    for subdir in subdirectoriosFiltrados:
        archivoObjetivo = directorio + "/" + subdir + "/globals.txt"
        with open(archivoObjetivo, 'r') as f:
            contenido = f.read()

        matches = re.findall(r'(\S+)=\s*(\S+)', contenido)
        datos[subdir] = {clave: valor for clave, valor in matches}

    if len(datos) == 0:
        logging.warning("No hay datos globales para index.json") 

    # print(datos)
    return datos

def lanzarProcesados(directorios, directorioSalidaPrimerNivel, directorioOrigen):
    # Lanza tseries y procesaConexiones para cada directorio del disco original, almacenando
    # los resultados en directorios espejo dentro del directorio original

    imprimirComandoScriptProcesar()
    
    directoriosFiltrados = [f for f in directorios if "lost+found" not in f]

    for d in directoriosFiltrados:
        directorioInput = os.path.join(directorioOrigen, d)
        directorioOutput = os.path.join(directorioSalidaPrimerNivel, d)
        
        # hay que otorgar permisos de escritura sobre el escritorio, por defecto no se dan
        os.makedirs(directorioOutput, exist_ok=True)
        os.chmod(directorioOutput, 0o777)

        lanzarProcesaConexiones(directorioInput, directorioOutput)
        lanzarTseries(directorioInput, directorioOutput)

    logging.info(f"{directorioOrigen} procesado satisfactoriamente")
    logging.info(f"Resultado en: {directorioSalidaPrimerNivel}")

def make_readonly(path):
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            current = os.stat(filepath).st_mode
            os.chmod(filepath, current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)

        current = os.stat(dirpath).st_mode
        os.chmod(dirpath, current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)

def obtenerValoresDelConfig(rutaConfig):
    global RUTA_CONFIGURACIONES_PROCESACONEXIONES, RUTA_BINARIO_PROCESACONEXIONES, RUTA_BINARIO_TSERIES, RUTA_MODULOS_PROCESACONEXIONES

    config = configparser.ConfigParser()
    config.read(os.path.join(rutaConfig,'config.ini'))

    RUTA_CONFIGURACIONES_PROCESACONEXIONES = config['rutas']['rutaConfiguracionesProcesaConexiones'] 
    RUTA_BINARIO_PROCESACONEXIONES = config['rutas']['rutaBinarioProcesaConexiones']
    RUTA_BINARIO_TSERIES = config['rutas']['rutaBinarioTseries']      
    RUTA_MODULOS_PROCESACONEXIONES = config['rutas']['rutaModulosProcesaConexiones']

def imprimirComandoScriptProcesar():
    logging.info("Comando procesar.py ejecutado:")
    logging.info(' '.join(sys.argv))

def main():
    
    args = parse_args()

    try:
        start = time.time()

        # 1 - Preparación previa al procesado

        directorioOrigen = args.rutaOrigen
        directorioDestino = args.rutaDestino   
        rutaConfig = args.rutaConfig

        obtenerValoresDelConfig(rutaConfig)

        serial_trazas = "mockeo" #  obtener_serial(directorioOrigen) # "mockeo" #  
        primerTimestamp = obtenerTimestamp(directorioOrigen)
        nombreDirectorioSalidaPrimerNivel = f"{serial_trazas}_{primerTimestamp}"
        directorioSalidaPrimerNivel = os.path.join(directorioDestino, nombreDirectorioSalidaPrimerNivel)

        os.makedirs(directorioSalidaPrimerNivel, exist_ok=True)  # Crear antes del logger
        configurarLogger(directorioSalidaPrimerNivel)

        directorios = listarDirectorio(directorioOrigen)
        if len(directorios) == 0:
            raise ValueError(f"Directorio {directorioOrigen} vacío")

        # 2 - Procesado: 
        lanzarProcesados(directorios, directorioSalidaPrimerNivel, directorioOrigen)

        # 3 - Preparar y guardar index del disco, a modo de resumen del disco/procesado. 
        
        timestampInicial = obtenerTimestampInicio(directorioSalidaPrimerNivel)
        timestampFinal = obtenerTimestampFinal(directorioSalidaPrimerNivel)
        duracion = timestampFinal - timestampInicial

        usoMemoria = obtenerUsoMemoria(directorioDestino)

        datos = {
            "numeroSerie": serial_trazas,
            "directorios": directorios,
            "usado" : usoMemoria[0],
            "disponible" : usoMemoria[1],  
            "timestampInicio": timestampInicial,
            "timestampFinal": timestampFinal,
            "diferenciaTimestamps" : duracion,
            "fechaInicio" : datetime.datetime.fromtimestamp(timestampInicial).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "fechaFinal": datetime.datetime.fromtimestamp(timestampFinal).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "tiempoTranscurrido": timestamp2Duration(duracion)
        }

        datoApendice=extraerDatosGlobals(directorioSalidaPrimerNivel)
        datosCompleto={**datos, **datoApendice}

        rutaIndexJson = os.path.join(directorioSalidaPrimerNivel, "index.json")
        with open(rutaIndexJson, "w") as f:
            json.dump(datosCompleto, f, indent=4)

        logging.info(f"Índice del disco escrito en {rutaIndexJson}")

        # 4 - Convertir el directorio de salida no editable para evitar corromper datos 
        make_readonly(directorioSalidaPrimerNivel)

        # Comprimo todo en un zip:

        # if args.zip:

        #     inicioCompresion = time.time()
        #     logging.info(f"Comprimiendo resultados en {directorioSalidaPrimerNivel}.zip ...")

        #     ruta_zip = directorioSalidaPrimerNivel + ".zip"

        #     with zipfile.ZipFile(ruta_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        #         for root, dirs, files in os.walk(directorioSalidaPrimerNivel):
        #             for file in files:
        #                 ruta_absoluta = os.path.join(root, file)
        #                 ruta_relativa = os.path.relpath(ruta_absoluta, directorioSalidaPrimerNivel)
        #                 zf.write(ruta_absoluta, ruta_relativa)

        #     logging.info(f"Zip creado en: {ruta_zip}")

        #     # Borro el original
        #     shutil.rmtree(directorioSalidaPrimerNivel)
        #     logging.info(f"Directorio original eliminado: {directorioSalidaPrimerNivel}")

        #     endCompresion = time.time()
        #     tiempo_total = str(datetime.timedelta(seconds=endCompresion-inicioCompresion))
        #     logging.info(f"Tiempo total de compresión (H:MM:SS.MM): {tiempo_total}")

    except Exception as e:
        logging.error(f"Fallo inesperado en el script: {e}")
        logging.error(f"Stack trace:\n{traceback.format_exc()}")
        sys.exit(1)

    finally:
        end = time.time()
        tiempo_total = str(datetime.timedelta(seconds=end-start))
        logging.info(f"Tiempo total de ejecución (H:MM:SS.MM): {tiempo_total}")


if __name__ == "__main__":
    main()
