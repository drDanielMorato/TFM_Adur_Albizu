# Este script se utilizará para generar registros de flujo mediante procesaConexiones. 
# ProcesaConexiones se lanzará con sus opciones básicas y una serie de modulos, 
# los cuales pueden ser configurados a través su archivo de configuraciones (p. ej.ConfiguracionesProcesaConexiones.txt)
__version__ = "1.3.0"

import subprocess
import sys
import time
import datetime
import os 
import argparse
import mmap
import logging
import json
import re
import configparser
import stat
from typing import List, Dict, Set, FrozenSet, Tuple
import shlex

# Archivos de salida de procesaConexiones:
ARCHIVO_TCP = "salida_tcp_"
ARCHIVO_UDP = "salida_udp_"
ARCHIVO_ICMP = "salida_icmp_"
# Nombre del archivo analizado para encontrar parejas de MACs de la UPNA para tseries:
ARCHIVO_ANALIZADO = ARCHIVO_UDP 
# Nombre del archivo de salida donde se almacenan las estadísticas de procesaConexiones:
ARCHIVO_GLOBALES_PROCESACONEXIONES = "globals.txt"
# Nombre del archivo de salida donde se almacenan los filtros BPF implementados mediante el módulo tseries:
# de procesaConexiones
ARCHIVO_FILTROSBPF_PROCESACONEXIONES = "filtrosBpfModuloTseriesProcesaConexiones.txt" 
# Nombre del archivo de salida donde se almacenan los logs de procesaConexiones
ARCHIVO_LOGS_PROCESACONEXIONES = "procesaConexiones.log" 
# Nombre del archivo de entrada de procesaConexiones donde se almacenan las configuraciones que van a aplicarse:
# Viene definido en config.ini 
ARCHIVO_CONFIGURACIONES_PROCESACONEXIONES = "" 
# Nombre del archivo de salida donde se almacenan los filtros implementados mediante tseries:
ARCHIVO_FILTROSBPF_TSERIES = "filtrosBpfTseries.txt"
ARCHIVO_FILTROSNETS_TSERIES = "filtrosNETsTseries.txt"
# Nombre del archivo que pasa la lista de archivos .gz a procesar a tseries (herramienta):
ARCHIVO_LISTAGZS_TSERIES = "listaFicherosGzTseries.txt"
# Nombre del fichero con la salida de tseries (herramienta):
ARCHIVO_SALIDA_TSERIES = "salidaTseries.txt" 
# Nombre del fichero con los logs de tseries (herramienta):
ARCHIVO_LOGS_TSERIES = "tseries.log" 
# Nombre del archivo índice del disco:
ARCHIVO_INDICE = "index.json" 

# Columnas a analizar del fichero ARCHIVO_ANALIZADO
SRCMAC_SRC2DST = 23
DSTMAC_SRC2DST = 24
SRCMAC_DST2SRC = 25
DSTMAC_DST2SRC = 26
MOREMACSEEN = 27

# Variables que almacenarán las onfiguraciones del config.ini
RUTA_PLANTILLACONFIGURACIONES_PROCESACONEXIONES = ""
RUTA_BINARIO_PROCESACONEXIONES = ""
RUTA_BINARIO_TSERIES = ""     
RUTA_MODULOS_PROCESACONEXIONES = ""

def parseArgs() -> argparse.Namespace:
    """Parsea y valida los argumentos de la línea de comandos"""

    parser = argparse.ArgumentParser(
        description="Ejecuta procesaConexiones y tseries sobre el directorio de montaje del disco indicado. Se debe indicar también el disco donde se almacenarán las trazas resultantes"
    )

    parser.add_argument(
        "--version", "-v", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--rutaOrigen",
        "-o",
        required=True,
        help="Directorio de montaje del direcorio a procesar (ej: /trazas1)"
    )
    parser.add_argument(
        "--rutaDestino",
        "-d",
        required=True,
        help="Directorio de montaje del disco donde se van a almacenar los logs (ej: /opt2)"
    )
    parser.add_argument(
        "--rutaConfig",
        "-c",
        required=True,
        help="Ruta del archivo de configuraciones config.ini (ej: /opt3/Desktop/ScriptProcesado/config.ini)"
    )

    return parser.parse_args()

def obtenerSerial(directorio: str) -> str:
    """Obtiene el número de serie del disco montado en el directorio indicado en --rutaOrigen."""

    directorio_seguro = shlex.quote(directorio)
    result = subprocess.run(
        f'lsblk -no SERIAL $(df -P {directorio_seguro} | awk \'NR==2{{print $1}}\' | sed \'s/[0-9]*$//\')',
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"lbslk falló al obtener el serial del disco montado en {directorio}: {result.stderr.strip()}")

    seriales = result.stdout.strip().splitlines()

    if len(seriales) == 0:
        raise ValueError(f"No se obtuvo ningún serial para {directorio}")

    if len(seriales) > 1:
        raise ValueError(f"Se obtuvieron múltiples seriales para {directorio}: {seriales}")

    return seriales[0]

def listarDirectorio(directorio: str) -> List[str]:
    """ Devuelve un array con la lista de subdirectorios de un directorio"""
    directorio_seguro = shlex.quote(directorio)
    comando = f"ls {directorio_seguro}"
    result = subprocess.run(
            comando,
            shell=True,
            capture_output=True,
            text=True
        )

    if result.returncode != 0:
        raise RuntimeError(f"{comando} falló para {directorio}: {result.stderr.strip()}")

    return result.stdout.strip().splitlines()
    
def obtenerTimestamp(directorio: str) -> str:
    """
    Obtiene el timestamp del primer pcap del directorio de origen para nombrar el directorio padre de salida 
    del disco.
    """
    directorios = listarDirectorio(directorio)

    if len(directorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    #Estamos en los directorios superiores, cogemos el de la timestamp más baja 
    directoriosFiltrados = [f for f in directorios if "lost+found" not in f]
    directoriosFiltrados.sort(key=lambda x: int(x.replace('-', '')))

    directorioObjetivo = os.path.join(directorio, directoriosFiltrados[0])
    archivosDirectorioObjetivo = listarDirectorio(directorioObjetivo)
    if len(archivosDirectorioObjetivo) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    archivosDirectorioObjetivo.sort(key=lambda x: int(x.split('.')[0]))

    return archivosDirectorioObjetivo[0].split(".")[0] #Devuelvo el primer timestamp, sin el gz   

def obtenerTimestampInicio(directorio: str) -> float:
    """
    Obtiene el timestamp inicial del disco, basándose en el archivo globals.txt contenido en el directorio
    de salida.
    Este valor es utilizado para rellenar el archivo index.json del disco.
    """
    subdirectorios = listarDirectorio(directorio)
    if len(subdirectorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]
    subdirectoriosFiltrados.sort(key=lambda x: int(x.replace('-', '')))

    # Cogemos el globals.txt con el timestamp más bajo 
    archivoObjetivo = os.path.join(directorio, subdirectoriosFiltrados[0], ARCHIVO_GLOBALES_PROCESACONEXIONES)
    with open(archivoObjetivo, 'r') as f:
        contenido = f.read()

    match = re.search(r'tstampIni/fin/dif=\s*([\d.]+),([\d.]+),([\d.]+)', contenido)
    if not match:
        raise ValueError("No se encontró tstampIni en el archivo")
    
    return float(match.group(1))

def obtenerTimestampFinal(directorio: str) -> float:
    """
    Obtiene el timestamp final del disco, basándose en el archivo globals.txt contenido en el directorio
    de salida.
    Este valor es utilizado para rellenar el archivo index.json del disco.
    """

    subdirectorios = listarDirectorio(directorio)

    if len(subdirectorios) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]
    subdirectoriosFiltrados.sort(key=lambda x: int(x.replace('-', '')))

    # Cogemos el globals.txt con el timestamp más alto 
    archivoObjetivo = os.path.join(directorio, subdirectoriosFiltrados[-1], ARCHIVO_GLOBALES_PROCESACONEXIONES)
    with open(archivoObjetivo, 'r') as f:
        contenido = f.read()

    match = re.search(r'tstampIni/fin/dif=\s*([\d.]+),([\d.]+),([\d.]+)', contenido)
    if not match:
        raise ValueError("No se encontró tstampIni en el archivo")
    
    return float(match.group(2))

def extraerFiltrosBpfProcesaConexionesYGuardarEnArchivo(input_path: str, output_path: str) -> None:
    """
    Este método lista los filtros BPF implementados en el modulo tseries de procesaConexiones
    en un archivo filtrosBpfModuloTseriesProcesaConexiones.txt, en el directorio de salida.
    Mientras los filtros no sean numerosos, se puede usar el código actual. Si no, se tendrá que implementar 
    mmap
    """
    filters = []
 
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            prefix = "--externArgs tseries:pcapFilter="
            if line.startswith(prefix):
                pcap_filter = line[len(prefix):].strip()
                filters.append(pcap_filter)
 
    with open(os.path.join(output_path, ARCHIVO_FILTROSBPF_PROCESACONEXIONES), "w") as f:
        for i, pcap_filter in enumerate(filters):
            f.write(f"{i}: {pcap_filter}\n")

def prepararFicheroConfiguracionesProcesaConexiones(directorioInput: str, directorioOutput: str) -> str:
    """
    Coge la plantilla de configuraciones de procesaConexiones definida en config.ini y la rellena con los parámetros que se le han
    pasado como entrada a procesar.py, creando el archivo con configuraciones que se le va a pasar a procesaConexiones
    """
    with open(RUTA_PLANTILLACONFIGURACIONES_PROCESACONEXIONES, 'r') as f:
        plantilla = f.read()
    contenido = plantilla.format(inputDirectory = directorioInput, 
                    outputDirectory = os.path.join(directorioOutput,"salida"),
                    pathLogFile = os.path.join(directorioOutput, ARCHIVO_LOGS_PROCESACONEXIONES),
                    outputFileModuloTseries = os.path.join(directorioOutput, "salidaModuloTseries"),
                    modulesDirectory = RUTA_MODULOS_PROCESACONEXIONES)
    
    rutaConfiguracionesProcesaConexiones = os.path.join(directorioOutput, ARCHIVO_CONFIGURACIONES_PROCESACONEXIONES)
    with open(rutaConfiguracionesProcesaConexiones, 'w') as f:
        f.write(contenido)

    return rutaConfiguracionesProcesaConexiones

def extraerEstadisticasGlobalesYGuardarEnArchivo(directorioOutput: str) -> None:
    """
    Este método extrae las estadísticas globales de procesaConexiones de su archivo de logs 
    y lo almacena en el archivo ARCHIVO_GLOBALES_PROCESACONEXIONES del directorio de salida
    """

    with open(os.path.join(directorioOutput, ARCHIVO_LOGS_PROCESACONEXIONES), "r") as f:
        salida = f.read()
    
    indice = salida.find("numIPFragments=")
    salida_filtrada = salida[indice:]

    limite = salida_filtrada.find("\n")
    if limite != -1:
        salida_filtrada = salida_filtrada[:limite]

    if indice == -1 or limite == -1:
        raise RuntimeError(f"La lectura de {ARCHIVO_LOGS_PROCESACONEXIONES} falló porque los logs de procesaConexiones no tienen el formato correcto")

    # Escribir en el log el contenido con las estadísticas globales:
    with open(os.path.join(directorioOutput, ARCHIVO_GLOBALES_PROCESACONEXIONES), "w") as f:
        f.write(salida_filtrada)

def lanzarProcesaConexiones(directorioInput: str, directorioOutput: str) -> None:
    """
    Lanza procesaConexiones, implementando las configuraciones del archivo de configuraciones de procesaConexiones.
    """
    logging.info("Inicio lanzarProcesaConexiones")

    #1- Preparamos el archivo de configuraciones que le llega como input a procesaConexiones
    rutaConfiguracionesProcesaConexiones = prepararFicheroConfiguracionesProcesaConexiones(
        directorioInput, directorioOutput
    )   

    #2- Ejecución de procesaConexiones: 
    comando = [RUTA_BINARIO_PROCESACONEXIONES , "--configFile", rutaConfiguracionesProcesaConexiones]
    logging.info("Ejecutando comando:")
    logging.info(" ".join(comando))
    result = subprocess.run(comando, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"El comando procesaConexiones falló: {result.stderr.strip()}")

    #3- Creamos archivos en el directorio de salida con los filtros BPF aplicados y las estadísticas globales de procesaConexiones    
    extraerFiltrosBpfProcesaConexionesYGuardarEnArchivo(rutaConfiguracionesProcesaConexiones, directorioOutput)
    extraerEstadisticasGlobalesYGuardarEnArchivo(directorioOutput)

    logging.info("Fin lanzarProcesaConexiones")

def obtenerParejasMACs(directorioOutput: str) -> Set[FrozenSet[str]]:
    """
    Lanzo esto para obtener las parejas de macs del log ARCHIVO_ANALIZADO de procesaConexiones
    """
    archivoAnalizado = os.path.join(directorioOutput, ARCHIVO_ANALIZADO)
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

def obtener_IPs(directorioOutput):
    """
    Devuelve un set con las direcciones IP asociadas a la direccion MAC del router de la UPNA.

    - Si la columna 78 es "00:41:d2:9b:d6:ef", añade el valor de la columna 1.
    - Si la columna 80 es "00:41:d2:9b:d6:ef", añade el valor de la columna 3.

    Las columnas se numeran desde 0.
    """

    macUPNA = "00:41:d2:9b:d6:ef"
    valores = set()

    ruta_fichero = os.path.join(directorioOutput, ARCHIVO_TCP)
    with open(ruta_fichero, "r") as f:
        for linea in f:
            columnas = linea.split()

            # Comprobar que la línea tiene suficientes columnas
            if len(columnas) > 80:
                if columnas[78] == macUPNA:
                    valores.add(columnas[0])

                if columnas[80] == macUPNA:
                    valores.add(columnas[2])
        f.close()

    ruta_fichero = os.path.join(directorioOutput, ARCHIVO_UDP)
    with open(ruta_fichero, "r") as f:
        for linea in f:
            columnas = linea.split()

            # Comprobar que la línea tiene suficientes columnas
            if len(columnas) > 25:
                if columnas[23] == macUPNA:
                    valores.add(columnas[0])

                if columnas[25] == macUPNA:
                    valores.add(columnas[2])

    ruta_fichero = os.path.join(directorioOutput, ARCHIVO_ICMP)
    with open(ruta_fichero, "r") as f:
        for linea in f:
            columnas = linea.split()

            # Comprobar que la línea tiene suficientes columnas
            if len(columnas) > 23:
                if columnas[21] == macUPNA:
                    valores.add(columnas[0])

                if columnas[23] == macUPNA:
                    valores.add(columnas[2])

    return valores
     
def generarFiltrosNETs(ip: str) -> str:
    """
    Rellena una plantilla de filtros NET con las dirección IP que se le ha proporcionado
    """
    plantilla = """ether src {mac}
{ip} 255.255.255.255 0.0.0.0 0.0.0.0
0.0.0.0 0.0.0.0 {ip} 255.255.255.255}"""
    return plantilla.format(ip=ip)
    
def generarFiltrosBpf(mac: str) -> str:
    """
    Rellena una plantilla de filtros BPF con las dirección MAC que se le ha proporcionado
    """
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

def crearArchivoFiltrosBPF(directorioOutput: str) -> str:
    """
    Crea un archivo listando todos los filtros NETs que se le van a aplicar a tseries (herramienta)
    y los almacena en un archivo ARCHIVO_FILTROSBPF_TSERIES en el directorio de salida.
    El archivo permanece después de la ejecución como prueba.
    """
    parejasMacs = obtenerParejasMACs(directorioOutput)
    ruta = os.path.join(directorioOutput, ARCHIVO_FILTROSBPF_TSERIES)

    with open(ruta, "w") as f:
        for pareja in sorted(parejasMacs, key=lambda p: sorted(p)):
            for mac in pareja:
                f.write(generarFiltrosBpf(mac))
                f.write("\n")

    logging.info(f"Filtros BPF escritos en: {ruta}")
    return ruta

def crearArchivoFiltrosNETs(directorioOutput: str) -> str:
    """
    Crea un archivo listando todos los filtros NETs que se le van a aplicar a tseries (herramienta)
    y los almacena en un archivo ARCHIVO_FILTROSNETS_TSERIES en el directorio de salida.
    El archivo permanece después de la ejecución como prueba.
    """
    ips = obtener_IPs(directorioOutput)
    ruta = os.path.join(directorioOutput, ARCHIVO_FILTROSNETS_TSERIES)

    with open(ruta, "w") as f:
        for ip in sorted(ips, key=lambda p: sorted(p)):
            f.write(generarFiltrosNETs(ip))
            f.write("\n")

    logging.info(f"Filtros NETs escritos en: {ruta}")
    return ruta

def crearFicheroListaGz(directorioInput: str, directorioOutput: str) -> str:
    """
    Creo archivo que guarda la lista de .gzs a procesar por tseries (herramienta), ordenada en base a los
    timestamps, y lo almacena en el directorio de salida
    """
    files = os.listdir(directorioInput)
    files.sort(key=lambda x: int(x.split('.')[0]))

    ruta = os.path.join(directorioOutput, ARCHIVO_LISTAGZS_TSERIES)
    with open(ruta, "w") as f:
        for filename in files:
            f.write(os.path.join(directorioInput, filename))
            f.write("\n")
    return ruta

def lanzarTseries(directorioInput: str, directorioOutput: str) -> None:
    """
    Ejecución de tseries
    """
    logging.info("Inicio lanzarTseries")

    # 1- Preparamos archivos que tseries (herramienta) necesita
    #rutaFiltros = crearArchivoFiltrosBPF(directorioOutput)
    rutaFiltros = crearArchivoFiltrosNETs(directorioOutput)
    rutaLista = crearFicheroListaGz(directorioInput, directorioOutput)
    
    # 2 - Ejecutamos tseries 
    #tseries_comand = [RUTA_BINARIO_TSERIES, "-v", "-m", "-i", rutaLista, "-f", rutaFiltros]
    tseries_comand = [RUTA_BINARIO_TSERIES, "-v", "-m", "-i", rutaLista, "-f", rutaFiltros, "-N"]
    result = subprocess.run(tseries_comand, capture_output=True, text=True)
    logging.info("Ejecutando comando:")
    logging.info(" ".join(tseries_comand))

    if result.returncode != 0:
        raise RuntimeError(f"El comando tseries falló: {result.stderr.strip()}")

    # 3 - Se guarda resultado en fichero de salida 
    rutaDestino = os.path.join(directorioOutput, ARCHIVO_SALIDA_TSERIES)
    rutaLogs = os.path.join(directorioOutput, ARCHIVO_LOGS_TSERIES)

    with open(rutaDestino, "w") as f:
        f.write(result.stdout)
    with open(rutaLogs, "w") as f:
        f.write(result.stderr)

    logging.info(f"tseries lanzado satisfactoriamente. Resultados en: {rutaDestino}")
    logging.info("Fin lanzarTseries")

def configurarLogger(directorioDestino: str) -> None:
    """
    Aquí se configura el logger: ruta de los logs resultantes, formato, fecha...
    """
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

def timestamp2Duration(ts: str) -> str:
    """
    Transformación de timestamp a formato legible
    """
    ts = float(ts)
    dias = int(ts // 86400)
    horas = int((ts % 86400) // 3600)
    minutos = int((ts % 3600) // 60)
    segundos = int(ts % 60)
    milisegundos = int((ts % 1) * 1000)

    return f"{dias}d {horas:02d}:{minutos:02d}:{segundos:02d}.{milisegundos:03d}"

def obtenerUsoMemoria(directorio: str) -> List[str]:
    """Obtiene la memoria usada/libre del disco indicado"""
    directorio_seguro = shlex.quote(directorio)
    result = subprocess.run(
        f"df -B1 {directorio_seguro} | awk 'NR==2{{print $3,$4}}'",
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

def extraerDatosGlobals(directorio: str) -> Dict[str, Dict[str, str]]: 
    """Obtiene todas las variables de todos los globals.txt y las devuelve en un diccionario"""
    subdirectorios = listarDirectorio(directorio)
    subdirectoriosFiltrados = [f for f in subdirectorios if f.split('-')[0].isdigit()]

    if len(subdirectoriosFiltrados) == 0:
        raise ValueError(f"Directorio {directorio} vacío")

    datos = {}
    for subdir in subdirectoriosFiltrados:
        archivoObjetivo = os.path.join(directorio, subdir, ARCHIVO_GLOBALES_PROCESACONEXIONES)
        with open(archivoObjetivo, 'r') as f:
            contenido = f.read()

        matches = re.findall(r'(\S+)=\s*(\S+)', contenido)
        datos[subdir] = {clave: valor for clave, valor in matches}

    if len(datos) == 0:
        raise ValueError(f"No hay datos globales para {ARCHIVO_INDICE} ") 

    return datos

def imprimirComandoScriptProcesar() -> None:
    logging.info("Comando procesar.py ejecutado:")
    logging.info(' '.join(sys.argv))

def lanzarProcesados(directorios: List[str], directorioSalidaPrimerNivel: str, directorioOrigen: str) -> None:
    """
    Lanza tseries y procesaConexiones para cada directorio del disco original, almacenando
    los resultados en directorios espejo dentro del directorio original
    """
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

def makeReadonly(path: str) -> None:
    """
    Convierte el directorio que se le proporciona en readonly
    """
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            current = os.stat(filepath).st_mode
            os.chmod(filepath, current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)

        current = os.stat(dirpath).st_mode
        os.chmod(dirpath, current & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)

def obtenerValoresDelConfig(rutaConfig: str) -> None:
    """
    Extrae los valores de las configuraciones del archivo proporcionado en --rutaConfig
    """
    global RUTA_PLANTILLACONFIGURACIONES_PROCESACONEXIONES, RUTA_BINARIO_PROCESACONEXIONES, RUTA_BINARIO_TSERIES, RUTA_MODULOS_PROCESACONEXIONES, ARCHIVO_CONFIGURACIONES_PROCESACONEXIONES

    config = configparser.ConfigParser()
    config.read(rutaConfig)

    RUTA_PLANTILLACONFIGURACIONES_PROCESACONEXIONES = config['rutas']['rutaPlantillaConfiguracionesProcesaConexiones'] 
    RUTA_BINARIO_PROCESACONEXIONES = config['rutas']['rutaBinarioProcesaConexiones']
    RUTA_BINARIO_TSERIES = config['rutas']['rutaBinarioTseries']      
    RUTA_MODULOS_PROCESACONEXIONES = config['rutas']['rutaModulosProcesaConexiones']

    ARCHIVO_CONFIGURACIONES_PROCESACONEXIONES = os.path.basename(RUTA_PLANTILLACONFIGURACIONES_PROCESACONEXIONES)

def prepararEntorno(args: argparse.Namespace) -> Tuple[str, str, List[str]]:
    """
    Prepara el entorno de ejecución: lee argumentos de entrada, lee config, calcula directorio de
    salida de primer nivel, crea el logger y valida que haya datos.

    Devuelve directorioSalidaPrimerNivel, serial_trazas y la lista directorios.
    """
    directorioOrigen = args.rutaOrigen
    directorioDestino = args.rutaDestino   
    rutaConfig = args.rutaConfig

    obtenerValoresDelConfig(rutaConfig)

    serial_trazas =  obtenerSerial(directorioOrigen) # "mockeo" #  
    primerTimestamp = obtenerTimestamp(directorioOrigen)

    nombreDirectorioSalidaPrimerNivel = f"{serial_trazas}_{primerTimestamp}"
    directorioSalidaPrimerNivel = os.path.join(
        directorioDestino, nombreDirectorioSalidaPrimerNivel
    )
    os.makedirs(directorioSalidaPrimerNivel, exist_ok=True)  # Crear antes del logger

    configurarLogger(directorioSalidaPrimerNivel)

    directorios = listarDirectorio(directorioOrigen)
    if len(directorios) == 0:
        raise ValueError(f"Directorio {directorioOrigen} vacío")

    return directorioSalidaPrimerNivel, serial_trazas, directorios

def generarIndiceDisco(
    directorioSalidaPrimerNivel: str,
    directorioDestino: str,
    serial_trazas: str,
    directorios: List[str],
) -> str:
    """
    Calcula los datos de resumen del procesado y los escribe en index.json.
    Devuelve la ruta del index.json generado.
    """
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

    rutaIndexJson = os.path.join(directorioSalidaPrimerNivel, ARCHIVO_INDICE)
    with open(rutaIndexJson, "w") as f:
        json.dump(datosCompleto, f, indent=4)

    logging.info(f"Índice del disco escrito en {rutaIndexJson}")
    return  rutaIndexJson





def main() -> None:
    """
    Flujo principal
    """
    args = parseArgs()
    start = time.time()

    try:
        # 1 - Preparación previa al procesado
        directorioSalidaPrimerNivel, serial_trazas, directorios = (
            prepararEntorno(args)
        )

        # 2 - Procesado: 
        lanzarProcesados(directorios, directorioSalidaPrimerNivel, args.rutaOrigen)

        # 3 - Preparar y guardar index del disco, a modo de resumen del disco/procesado. 
        generarIndiceDisco(
            directorioSalidaPrimerNivel,
            args.rutaDestino,
            serial_trazas,
            directorios,
        )

        # 4 - Convertir el directorio de salida no editable para evitar corromper datos 
        makeReadonly(directorioSalidaPrimerNivel)

    except Exception as e:
        logging.error(f"Fallo inesperado en el script: {e}", exc_info=True)
        sys.exit(1)

    finally:
        end = time.time()
        tiempo_total = str(datetime.timedelta(seconds=end-start))
        logging.info(f"Tiempo total de ejecución (H:MM:SS.MM): {tiempo_total}")

if __name__ == "__main__":
    main()
