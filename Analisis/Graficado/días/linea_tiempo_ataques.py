"""Dibuja todos los ataques de resultado.txt en una línea de tiempo (tipo Gantt),
basándose en su tiempo de inicio y final. Los ataques que se solapen en el
tiempo se colocan en carriles (filas) distintos para que se puedan distinguir.
"""

from datetime import datetime, timezone
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.collections import LineCollection

ARCHIVO_ENTRADA = "/home/adur/Desktop/TFM_Ziber/DatosPruebas/Out/metodo 3/resultado.txt"
COLOR_ATAQUE = "steelblue"


def _datetime_utc_desde_unix(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc)


def _leer_ataques(archivo):
    """Lee (inicio, fin) de cada fila de resultado.txt.

    Sigue el mismo formato de 13 campos que ranking_atacantes.py. Si fin < inicio
    se intercambian, y si fin == inicio se añade 1s para que el ataque sea visible
    en el gráfico (un punto de duración 0 no se vería).
    """
    ataques = []
    with open(archivo, encoding="utf-8") as entrada:
        for numero_linea, linea in enumerate(entrada, start=1):
            texto = linea.strip()
            if not texto or texto.startswith("Start (unix)") or set(texto) == {"-"}:
                continue

            campos = texto.split(maxsplit=12)
            try:
                if len(campos) != 13:
                    raise ValueError("13 fields were expected, included the Target Ports list")
                inicio = float(campos[0])
                fin = float(campos[1])
            except ValueError as error:
                raise ValueError(f"{archivo}, línea {numero_linea}: {error}") from error

            if fin < inicio:
                inicio, fin = fin, inicio
            if fin == inicio:
                fin = inicio + 1

            ataques.append((inicio, fin))

    return ataques


def _asignar_carriles(ataques_ordenados):
    """Asigna a cada ataque el primer carril libre (algoritmo greedy de scheduling
    de intervalos), minimizando el número de filas usadas. Solo se abre un carril
    nuevo si el ataque solapa con todos los existentes."""
    fin_por_carril = []  # fin_por_carril[i] = tiempo de fin del último ataque puesto en el carril i
    carriles = []

    for inicio, fin in ataques_ordenados:
        carril_libre = next(
            (i for i, fin_carril in enumerate(fin_por_carril) if fin_carril <= inicio),
            None,
        )
        if carril_libre is None:
            carril_libre = len(fin_por_carril)
            fin_por_carril.append(fin)
        else:
            fin_por_carril[carril_libre] = fin

        carriles.append(carril_libre)

    return carriles


def generarGraficoLineaTiempoAtaques(archivo=ARCHIVO_ENTRADA, directorioGuardado=None, mostrar=True, numFigura=1):
    """Genera una línea de tiempo con todos los ataques de `archivo`.
    Guarda el PNG en directorioGuardado si se indica."""
    ataques = _leer_ataques(archivo)

    if not ataques:
        print("No hay ataques en el archivo de entrada")
        return

    ataques_ordenados = sorted(ataques, key=lambda ataque: ataque[0])
    carriles = _asignar_carriles(ataques_ordenados)

    plt.figure(numFigura, figsize=(14, max(3, min(0.05 * (max(carriles) + 1), 12))))
    ejes = plt.gca()

    # Un solo LineCollection para todos los segmentos: con miles de ataques, crear un
    # artista por segmento (p. ej. via ax.hlines en un bucle) resulta muy lento de renderizar.
    x_inicio = [mdates.date2num(_datetime_utc_desde_unix(inicio)) for inicio, _ in ataques_ordenados]
    x_fin = [mdates.date2num(_datetime_utc_desde_unix(fin)) for _, fin in ataques_ordenados]
    segmentos = [((xi, carril), (xf, carril)) for xi, xf, carril in zip(x_inicio, x_fin, carriles)]
    ejes.add_collection(LineCollection(segmentos, colors=COLOR_ATAQUE, linewidths=2))

    # Si la duración es muy corta respecto al rango total del eje X, la línea puede
    # quedar por debajo de un píxel de ancho y no verse. Se marca también el inicio
    # de cada ataque con un punto para que siga siendo visible.
    ejes.scatter(x_inicio, carriles, color=COLOR_ATAQUE, s=8, zorder=3)

    ejes.set_xlim(min(x_inicio), max(x_fin))
    ejes.set_ylim(-1, max(carriles) + 1)
    ejes.set_title(f"Attack timeline ({len(ataques_ordenados)} attacks, {max(carriles) + 1} overlapping lanes)")
    ejes.set_xlabel("Time (UTC)")
    ejes.set_ylabel("Lane (only used to separate overlapping attacks)")
    ejes.xaxis.set_major_locator(mdates.AutoDateLocator())
    ejes.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M", tz=timezone.utc))
    plt.xticks(rotation=30, ha="right")
    ejes.grid(True, alpha=0.3)
    plt.tight_layout()

    if directorioGuardado is not None:
        directorio = Path(directorioGuardado)
        directorio.mkdir(parents=True, exist_ok=True)
        ruta_png = directorio / "linea_tiempo_ataques.png"
        plt.savefig(ruta_png, dpi=150)
        print(f"Grafica de linea de tiempo guardada en: {ruta_png}")

    if mostrar:
        plt.show()
    else:
        plt.close()
