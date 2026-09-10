"""
Las cuatro graficas pedidas para el procesado masivo por dias.

Todas reciben los registros ya leidos (una sola pasada por fichero) y guardan
la imagen en disco; ninguna dibuja por pantalla.
"""

import os

import numpy as np

from utils.graficas import (
    graficar_actividad_temporal,
    graficar_cdf,
    graficar_densidad_loglog,
    graficar_histograma_loglog,
)
from utils.lectura import ZONA_HORARIA_ESPANOLA, datetime_espanol_desde_unix

X_MIN_PUERTOS = 10
X_MAX_PUERTOS = 65500
CUANTIL_CORTE_CDF = 0.999
BINS_DENSIDAD = 50


def generarHistogramaNumeroPuertos(registros, directorio_salida, prefijo):
    """Histograma de puertos unicos (todo el trafico) con ejes log-log."""
    if not registros.hay_puertos:
        print("  Sin conversaciones para el histograma de puertos unicos")
        return

    x, frecuencias = registros.puertos_ordenados()
    ruta = os.path.join(directorio_salida, f"{prefijo}_histograma_puertos_unicos.png")
    dibujada = graficar_histograma_loglog(
        x, frecuencias,
        "Distribution of Conversations by Number of Unique Ports",
        "Unique ports", "Frequency", ruta,
        x_min=X_MIN_PUERTOS, x_max=X_MAX_PUERTOS,
    )

    if not dibujada:
        print("  Sin valores positivos para el histograma logaritmico de puertos")


def generarGraficoCDFPuertosUnicos(registros, directorio_salida, prefijo):
    """CDF de puertos unicos, acotada a la zona donde la curva cambia."""
    if not registros.hay_puertos:
        print("  Sin conversaciones para la CDF de puertos unicos")
        return

    valores, frecuencias = registros.puertos_ordenados()
    acumulado = np.cumsum(frecuencias)
    y = acumulado / acumulado[-1]

    # Cortamos donde la CDF practicamente ya vale 1 para no arrastrar la cola plana.
    indice_corte = int(np.searchsorted(y, CUANTIL_CORTE_CDF))
    indice_corte = min(indice_corte, valores.size - 1)
    x_max = float(valores[indice_corte]) * 1.05
    x_max = max(x_max, X_MIN_PUERTOS + 1)

    ruta = os.path.join(directorio_salida, f"{prefijo}_cdf_puertos_unicos.png")
    graficar_cdf(valores, y, "CDF of Unique Ports", "Unique ports", "CDF", ruta,
                 x_min=X_MIN_PUERTOS, x_max=x_max)


def _calcular_ventana_segundos(inicio, fin):
    rango = fin - inicio

    if rango <= 6 * 60 * 60:
        return 60
    if rango <= 24 * 60 * 60:
        return 5 * 60
    if rango <= 7 * 24 * 60 * 60:
        return 30 * 60
    return 60 * 60


def _actividad_por_ventana(inicios, fines, bordes):
    """Numero de ataques activos en cada ventana, mediante array de diferencias.

    Evita el bucle ventanas x ataques del script original, inviable con estos ficheros.
    """
    num_ventanas = len(bordes) - 1
    diferencias = np.zeros(num_ventanas + 1, dtype=np.int64)

    if inicios.size == 0:
        return diferencias[:num_ventanas]

    primera = np.clip(np.searchsorted(bordes, inicios, side="right") - 1, 0, num_ventanas - 1)
    ultima = np.clip(np.searchsorted(bordes, fines, side="left") - 1, 0, num_ventanas - 1)

    validos = primera <= ultima
    np.add.at(diferencias, primera[validos], 1)
    np.add.at(diferencias, ultima[validos] + 1, -1)

    return np.cumsum(diferencias)[:num_ventanas]


def generarGraficoActividadTemporalAtaques(registros, directorio_salida, prefijo):
    """Actividad temporal de ataques por protocolo (eje Y logaritmico) + resumen en .txt."""
    if not registros.hay_ataques:
        print("  Sin ataques TCP/UDP para la actividad temporal")
        return

    inicios = registros.inicios
    fines = registros.fines_ajustados()

    inicio_global = float(inicios.min())
    fin_global = float(fines.max())
    ventana_segundos = _calcular_ventana_segundos(inicio_global, fin_global)
    bordes = np.arange(inicio_global, fin_global + ventana_segundos, ventana_segundos, dtype=float)

    if bordes.size < 2:
        bordes = np.array([inicio_global, inicio_global + ventana_segundos], dtype=float)

    centros = (bordes[:-1] + bordes[1:]) / 2
    tiempos = [datetime_espanol_desde_unix(centro) for centro in centros]

    actividad_por_protocolo = {}
    for protocolo in ("TCP", "UDP"):
        mascara = registros.protocolos == protocolo
        actividad_por_protocolo[protocolo] = _actividad_por_ventana(inicios[mascara], fines[mascara], bordes)

    ruta = os.path.join(directorio_salida, f"{prefijo}_actividad_temporal_ataques.png")
    titulo = f"Temporal Attack Activity by Protocol ({ventana_segundos // 60} min window)"
    graficar_actividad_temporal(tiempos, actividad_por_protocolo, titulo, ruta, ZONA_HORARIA_ESPANOLA)

    _escribir_ataques_por_segundo(registros, directorio_salida, prefijo,
                                  inicio_global, fin_global, ventana_segundos,
                                  actividad_por_protocolo)


def _escribir_ataques_por_segundo(registros, directorio_salida, prefijo, inicio_global,
                                  fin_global, ventana_segundos, actividad_por_protocolo):
    """Guarda el ritmo aproximado de ataques por segundo."""
    duracion_total = max(fin_global - inicio_global, 1e-9)
    total_ataques = int(registros.inicios.size)
    ruta = os.path.join(directorio_salida, f"{prefijo}_ataques_por_segundo.txt")

    lineas = [
        f"Day: {prefijo}",
        f"Observed span (s): {duracion_total:.2f}",
        f"Window size (s): {ventana_segundos}",
        f"Total attacks (TCP+UDP): {total_ataques}",
        f"Attacks per second (overall): {total_ataques / duracion_total:.6f}",
        "",
    ]

    for protocolo in ("TCP", "UDP"):
        cuantos = int(np.count_nonzero(registros.protocolos == protocolo))
        lineas.append(f"{protocolo} attacks: {cuantos}")
        lineas.append(f"{protocolo} attacks per second: {cuantos / duracion_total:.6f}")

    lineas.append("")
    for protocolo, actividad in actividad_por_protocolo.items():
        actividad = np.asarray(actividad, dtype=float)
        lineas.append(f"{protocolo} peak concurrent attacks in a window: {int(actividad.max())}")
        lineas.append(f"{protocolo} mean concurrent attacks per window: {actividad.mean():.3f}")

    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write("\n".join(lineas) + "\n")


def generarGraficoDensidadDuracionAtaques(registros, directorio_salida, prefijo):
    """Densidad de la duracion de los ataques con ejes log-log."""
    if not registros.hay_ataques:
        print("  Sin ataques TCP/UDP para la densidad de duracion")
        return

    duraciones = registros.duraciones()
    ceros = int(np.count_nonzero(duraciones == 0))
    duraciones = duraciones[np.isfinite(duraciones) & (duraciones > 0)]

    if duraciones.size == 0:
        print("  Sin duraciones positivas para el histograma logaritmico")
        return

    minimo, maximo = float(duraciones.min()), float(duraciones.max())
    if minimo == maximo:
        minimo, maximo = minimo / 2, maximo * 2

    bordes = np.geomspace(minimo, maximo, BINS_DENSIDAD + 1)
    densidad, bordes = np.histogram(duraciones, bins=bordes, density=True)
    centros = (bordes[:-1] + bordes[1:]) / 2
    anchuras = bordes[1:] - bordes[:-1]

    titulo = "Attack Duration Density (positive durations)"
    if ceros:
        titulo += f"\nExcluded: {ceros} zero-duration"

    ruta = os.path.join(directorio_salida, f"{prefijo}_densidad_duracion_ataques.png")
    dibujada = graficar_densidad_loglog(centros, densidad, anchuras, titulo,
                                        "Duration (s)", "Density (1/s)", ruta)

    if not dibujada:
        print("  Sin densidad positiva para el histograma logaritmico de duraciones")
