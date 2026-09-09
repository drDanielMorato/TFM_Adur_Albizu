from utils.graficar import leerColumna, leerColumnas, calcular_histograma_simple, graficar_histograma_frecuencias, graficar_curva, graficar_actividad_temporal_protocolos
from utils.estadisticas import *
import argparse
import numpy as np
import os
from datetime import datetime, timedelta
from calendar import monthrange

try:
    from zoneinfo import ZoneInfo  # type: ignore[import-not-found]
except ImportError:
    ZoneInfo = None

ZONA_HORARIA_ESPANOLA = ZoneInfo("Europe/Madrid") if ZoneInfo else None


def _ultimo_domingo(year, month):
    ultimo_dia = monthrange(year, month)[1]
    fecha = datetime(year, month, ultimo_dia)
    return ultimo_dia - ((fecha.weekday() + 1) % 7)


def _offset_espana_desde_utc(fecha_utc):
    inicio_verano = datetime(fecha_utc.year, 3, _ultimo_domingo(fecha_utc.year, 3), 1, 0)
    fin_verano = datetime(fecha_utc.year, 10, _ultimo_domingo(fecha_utc.year, 10), 1, 0)
    return timedelta(hours=2 if inicio_verano <= fecha_utc < fin_verano else 1)


def _datetime_espanol_desde_unix(timestamp):
    if ZONA_HORARIA_ESPANOLA:
        return datetime.fromtimestamp(timestamp, ZONA_HORARIA_ESPANOLA)

    fecha_utc = datetime.utcfromtimestamp(timestamp)
    return fecha_utc + _offset_espana_desde_utc(fecha_utc)

def generarHistogramaNumeroPuertos(args, filtrar = False, quedarmeConInterna = False, titulo = "", numFigura = 1):
    """ Genera el histograma del números de puertos únicos, teniendo en cuenta
    todas las conversaciones
    """
    x,z = leerColumnas(args.archivo, 11, 7)
    x = [float(xi) for xi in x]

    total_number_attacks = len(x)

    if filtrar:
        x = filtrarPorIpSrc(x,z,quedarmeConInterna)

        number_filtered_attacks = len(x)
        percentage = number_filtered_attacks / total_number_attacks *100
        tipo_ataque = "outcoming" if quedarmeConInterna else "incoming"

        print (f"Number of {tipo_ataque} attacks: {number_filtered_attacks} ")
        print (f"Percentage of {tipo_ataque} attacks: {percentage:.2f} %")

        if not x:
            print(f"No hay conversaciones {tipo_ataque}; se omite la grafica")
            return


    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    
    graficar_histograma_frecuencias(x, f, titulo, "Unique ports", "Frecuency", None, args.directorioGuardado, 10001, False, numFigura)
    

def generarHistogramaNumeroPuertosPorProtocolo(args, protocolo, titulo = "", numFigura = 1):
    """Genera el histograma de puertos únicos filtrando por protocolo."""
    puertos_unicos, protocolos = leerColumnas(args.archivo, 11, 6)
    puertos_unicos = [float(puerto) for puerto, proto in zip(puertos_unicos, protocolos) if proto.upper() == protocolo.upper()]

    if not puertos_unicos:
        print(f"No hay conversaciones con protocolo {protocolo.upper()}")
        return

    ruta_guardado = os.path.join(args.directorioGuardado, f"histograma_puertos_unicos_{protocolo.lower()}.png")
    x, f = calcular_histograma_simple(puertos_unicos, args.directorioGuardado)
    graficar_histograma_frecuencias(x, f, titulo, "Unique ports", "Frecuency", None, ruta_guardado, 10001, False, numFigura)


def _leer_ataques_temporales(ruta_txt):
    ataques = []
    with open(ruta_txt, "r", encoding="utf-8") as archivo:
        for numero_linea, linea in enumerate(archivo, start=1):
            if numero_linea <= 2 or not linea.strip():
                continue

            partes = linea.split()
            if len(partes) < 12:
                continue

            inicio = float(partes[0])
            fin = float(partes[1])
            protocolo = partes[6].upper()

            if protocolo not in ("TCP", "UDP"):
                continue

            if fin < inicio:
                inicio, fin = fin, inicio

            if fin == inicio:
                fin = inicio + 1

            ataques.append((inicio, fin, protocolo))

    return ataques


def _calcular_ventana_segundos(inicio, fin):
    rango = fin - inicio

    if rango <= 6 * 60 * 60:
        return 60
    if rango <= 24 * 60 * 60:
        return 5 * 60
    if rango <= 7 * 24 * 60 * 60:
        return 30 * 60
    return 60 * 60


def generarGraficoActividadTemporalAtaques(args, numFigura = 1):
    """Genera una grafica temporal de ataques activos por protocolo."""
    ataques = _leer_ataques_temporales(args.archivo)

    if not ataques:
        print("No hay ataques TCP/UDP para generar la actividad temporal")
        return

    inicio_global = min(inicio for inicio, _, _ in ataques)
    fin_global = max(fin for _, fin, _ in ataques)
    ventana_segundos = _calcular_ventana_segundos(inicio_global, fin_global)
    bordes_ventanas = np.arange(inicio_global, fin_global + ventana_segundos, ventana_segundos)

    if len(bordes_ventanas) < 2:
        bordes_ventanas = np.array([inicio_global, inicio_global + ventana_segundos])

    tiempos = [_datetime_espanol_desde_unix((bordes_ventanas[i] + bordes_ventanas[i + 1]) / 2) for i in range(len(bordes_ventanas) - 1)]
    actividad_por_protocolo = {}

    for protocolo in ("TCP", "UDP"):
        ataques_protocolo = [(inicio, fin) for inicio, fin, proto in ataques if proto == protocolo]
        actividad = []

        for inicio_ventana, fin_ventana in zip(bordes_ventanas[:-1], bordes_ventanas[1:]):
            ataques_activos = sum(1 for inicio, fin in ataques_protocolo if inicio < fin_ventana and fin > inicio_ventana)
            actividad.append(ataques_activos)

        actividad_por_protocolo[protocolo] = actividad

    ruta_guardado = os.path.join(args.directorioGuardado, "actividad_temporal_ataques.png")
    titulo = f"Temporal Attack Activity by Protocol ({ventana_segundos // 60} min window)"
    graficar_actividad_temporal_protocolos(tiempos, actividad_por_protocolo, titulo, ruta_guardado, numFigura, ZONA_HORARIA_ESPANOLA)
    print(f"Grafica de actividad temporal guardada en: {ruta_guardado}")


def generarHistogramaNumeroPuertosLogaritmico(args, numFigura = 1):
    """ Genera el histograma del números de puertos únicos, teniendo en cuenta
    todas las conversaciones. Y en escala logarítmica
    """
    x = leerColumna(args.archivo, 11)
    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    graficar_histograma_frecuencias(x, f, "Distribution of Conversations by Number of Unique Ports", "Unique ports", "log10(frecuency)", None, args.directorioGuardado, 10001, True, numFigura)

def generarGraficoPorcentajeTraficoGlobalParaConversacionesConNPuertosUnicos(args, numFigura = 1):
    """ 
    Genera gráfica en la que Y es porcentaje en el número de flujos global,
    y X es conversaciones con N puertos únicos
    """
    x = leerColumna(args.archivo, 11)
    # print(f"longitud columna {len(x)}" )
    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    
    numeroConversacionesTotal = 395431
    y = calcularPorcentajesDeTotalFlujos(numeroConversacionesTotal, f)
    graficar_histograma_frecuencias(x, y, "Percentage of Total Conversations With a Given Number of Unique Ports", "Unique ports", "Percentage", None, args.directorioGuardado, 10001, False, numFigura)

def generarGraficoEntropiaParaConversacionNPuertosUnicos(args, numFigura = 1):
    """
    Para cada grupo d conversaciones con N puertos únicos, calcula la H media
    y gráfica las Hs para todas las conversaciones.
    """
    x,y = leerColumnas(args.archivo, 11, 9)
    x = [float(xi) for xi in x]
    y = [float(yi) for yi in y]
    
    medias = calcularMediaPorGrupo(x,y)
    
    x,y = zip(*medias.items()) #Desempaqueto
    graficar_histograma_frecuencias(x, y, "Mean Conversation Entropy (H) by Unique Ports", "Unique ports", "H", None, args.directorioGuardado, 10001, False, numFigura)

def generarGraficoCDFPuertosUnicos(args, numFigura = 1):
    """ 
    Genero CDF para el número de puertos únicos.
    """
    x = leerColumna(args.archivo, 11)
    x,y = CDF(x)
    graficar_curva(x, y, "CDF", "Unique ports", "CDF", args.directorioGuardado, 10001, numFigura)

    obtener_percentiles(x)


