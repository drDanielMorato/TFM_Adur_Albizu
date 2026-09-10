"""
Lectura de los ficheros resultado.txt en una sola pasada.

Los ficheros de exploracion2 tienen muchisimas lineas y una ultima columna
(Target Ports) enormemente larga, asi que se leen una unica vez y se limita
el numero de cortes por linea.
"""

from collections import Counter
from datetime import datetime, timedelta

import numpy as np

try:
    from zoneinfo import ZoneInfo  # type: ignore[import-not-found]
except ImportError:
    ZoneInfo = None

ZONA_HORARIA_ESPANOLA = ZoneInfo("Europe/Madrid") if ZoneInfo else None

# Indices de columna (0-based) en las lineas de datos de resultado.txt
COL_INICIO = 0
COL_FIN = 1
COL_PROTOCOLO = 6
COL_PUERTOS_UNICOS = 11
NUM_COLUMNAS_MINIMAS = 12

LINEAS_CABECERA = 2


class RegistrosDia:
    """Datos ya agregados de un fichero resultado.txt."""

    def __init__(self, conteo_puertos, inicios, fines, protocolos):
        self.conteo_puertos = conteo_puertos
        self.inicios = np.asarray(inicios, dtype=float)
        self.fines = np.asarray(fines, dtype=float)
        self.protocolos = np.asarray(protocolos, dtype="U3")

    @property
    def hay_puertos(self):
        return bool(self.conteo_puertos)

    @property
    def hay_ataques(self):
        return self.inicios.size > 0

    def puertos_ordenados(self):
        """Devuelve los valores de puertos unicos y sus frecuencias, ordenados por valor."""
        valores = np.fromiter(self.conteo_puertos.keys(), dtype=float, count=len(self.conteo_puertos))
        frecuencias = np.fromiter(self.conteo_puertos.values(), dtype=float, count=len(self.conteo_puertos))
        orden = np.argsort(valores)
        return valores[orden], frecuencias[orden]

    def duraciones(self):
        """Duraciones reales de cada ataque, en segundos (pueden ser cero)."""
        return self.fines - self.inicios

    def fines_ajustados(self):
        """Fines con duracion minima de 1 s, para el calculo de actividad temporal."""
        return np.where(self.fines > self.inicios, self.fines, self.inicios + 1.0)


def leer_registros(ruta_txt):
    """Lee un resultado.txt y devuelve un RegistrosDia.

    - El histograma y la CDF de puertos usan todas las conversaciones.
    - La actividad temporal y la duracion solo usan TCP/UDP, como en el script original.
    """
    conteo_puertos = Counter()
    inicios = []
    fines = []
    protocolos = []
    lineas_utiles = 0

    with open(ruta_txt, "r", encoding="utf-8", errors="replace") as archivo:
        for linea in archivo:
            if not linea.strip():
                continue

            lineas_utiles += 1
            if lineas_utiles <= LINEAS_CABECERA:
                continue

            partes = linea.split(None, NUM_COLUMNAS_MINIMAS)
            if len(partes) < NUM_COLUMNAS_MINIMAS:
                continue

            try:
                puertos_unicos = float(partes[COL_PUERTOS_UNICOS])
                inicio = float(partes[COL_INICIO])
                fin = float(partes[COL_FIN])
            except ValueError:
                continue

            conteo_puertos[puertos_unicos] += 1

            protocolo = partes[COL_PROTOCOLO].upper()
            if protocolo not in ("TCP", "UDP"):
                continue

            if fin < inicio:
                inicio, fin = fin, inicio

            inicios.append(inicio)
            fines.append(fin)
            protocolos.append(protocolo)

    return RegistrosDia(conteo_puertos, inicios, fines, protocolos)


def _ultimo_domingo(year, month):
    from calendar import monthrange

    ultimo_dia = monthrange(year, month)[1]
    fecha = datetime(year, month, ultimo_dia)
    return ultimo_dia - ((fecha.weekday() + 1) % 7)


def _offset_espana_desde_utc(fecha_utc):
    inicio_verano = datetime(fecha_utc.year, 3, _ultimo_domingo(fecha_utc.year, 3), 1, 0)
    fin_verano = datetime(fecha_utc.year, 10, _ultimo_domingo(fecha_utc.year, 10), 1, 0)
    return timedelta(hours=2 if inicio_verano <= fecha_utc < fin_verano else 1)


def datetime_espanol_desde_unix(timestamp):
    if ZONA_HORARIA_ESPANOLA:
        return datetime.fromtimestamp(timestamp, ZONA_HORARIA_ESPANOLA)

    fecha_utc = datetime.utcfromtimestamp(timestamp)
    return fecha_utc + _offset_espana_desde_utc(fecha_utc)
