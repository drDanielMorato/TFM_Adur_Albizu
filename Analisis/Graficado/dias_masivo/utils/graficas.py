"""
Funciones de dibujo para el procesado masivo.

Se fuerza el backend Agg: las graficas nunca se muestran, solo se guardan.
"""

import matplotlib

matplotlib.use("Agg")

import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

COLORES_PROTOCOLO = {
    "TCP": "steelblue",
    "UDP": "darkorange",
}


def _etiqueta_log(etiqueta):
    """Marca la etiqueta de un eje logaritmico."""
    return f"{etiqueta} (log scale)"


def graficar_histograma_loglog(x, frecuencias, titulo, xlabel, ylabel, ruta_guardado, x_min=10, x_max=65500):
    """Histograma con una linea por valor exacto y ambos ejes logaritmicos."""
    x = np.asarray(x, dtype=float)
    frecuencias = np.asarray(frecuencias, dtype=float)

    # El eje logaritmico no admite ceros.
    visibles = (x > 0) & (frecuencias > 0)
    if not visibles.any():
        return False

    base = 0.8
    figura, ejes = plt.subplots(figsize=(8, 5))
    # Lineas de grosor fijo en pantalla: un ancho en unidades de dato se deformaria con la escala log.
    ejes.vlines(x[visibles], base, frecuencias[visibles], color="steelblue", linewidth=0.7)
    ejes.set_xscale("log")
    ejes.set_yscale("log")
    ejes.set_xlim(x_min, x_max)
    ejes.set_ylim(bottom=base)  # las frecuencias son enteras, no bajan de 1
    ejes.set_title(titulo)
    ejes.set_xlabel(_etiqueta_log(xlabel))
    ejes.set_ylabel(_etiqueta_log(ylabel))
    ejes.grid(True, which="both", alpha=0.3)
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)
    return True


def graficar_cdf(x, y, titulo, xlabel, ylabel, ruta_guardado, x_min=10, x_max=None):
    """CDF empirica como funcion escalonada, sin interpolar entre valores."""
    figura, ejes = plt.subplots(figsize=(8, 5))
    ejes.plot(x, y, color="green", linewidth=1.4, drawstyle="steps-post")
    ejes.set_xlim(x_min, x_max)
    ejes.set_ylim(0, 1.05)
    ejes.set_title(titulo)
    ejes.set_xlabel(xlabel)
    ejes.set_ylabel(ylabel)
    ejes.grid(True, alpha=0.3)
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)


def graficar_actividad_temporal(tiempos, actividad_por_protocolo, titulo, ruta_guardado, zona_horaria=None):
    """Actividad temporal por protocolo con eje vertical logaritmico."""
    figura, ejes = plt.subplots(figsize=(12, 6))

    for protocolo, actividad in actividad_por_protocolo.items():
        ejes.step(tiempos, actividad, where="mid", label=protocolo,
                  color=COLORES_PROTOCOLO.get(protocolo), linewidth=1.2)

    ejes.set_yscale("log", nonpositive="clip")
    ejes.set_ylim(bottom=0.8)  # el numero de ataques activos es entero
    if len(tiempos) > 1:
        ejes.set_xlim(tiempos[0], tiempos[-1])
    ejes.set_title(titulo)
    ejes.set_xlabel("Time (UTC+1)")
    ejes.set_ylabel(_etiqueta_log("Active attacks"))
    ejes.legend()
    ejes.grid(True, which="both", alpha=0.3)
    ejes.xaxis.set_major_locator(mdates.AutoDateLocator())
    ejes.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M", tz=zona_horaria))
    figura.autofmt_xdate(rotation=30, ha="right")
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)


def graficar_densidad_loglog(centros, densidad, anchuras, titulo, xlabel, ylabel, ruta_guardado):
    """Densidad de probabilidad con ambos ejes logaritmicos."""
    centros = np.asarray(centros, dtype=float)
    densidad = np.asarray(densidad, dtype=float)
    anchuras = np.asarray(anchuras, dtype=float)

    mascara = densidad > 0
    if not mascara.any():
        return False

    figura, ejes = plt.subplots(figsize=(8, 5))
    ejes.bar(centros[mascara], densidad[mascara], width=anchuras[mascara],
             color="darkorange", alpha=0.7, edgecolor="black", linewidth=0.3)
    ejes.set_xscale("log")
    ejes.set_yscale("log")
    ejes.set_xlim(centros.min() - anchuras[0] / 2, centros.max() + anchuras[-1] / 2)
    ejes.set_title(titulo)
    ejes.set_xlabel(_etiqueta_log(xlabel))
    ejes.set_ylabel(_etiqueta_log(ylabel))
    ejes.grid(True, which="both", alpha=0.3)
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)
    return True
