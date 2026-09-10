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


def _anchuras_logaritmicas(x, fraccion=0.004):
    """Anchura de barra que se ve constante sobre un eje X logaritmico."""
    factor = 10.0 ** fraccion
    return x * (factor - 1.0 / factor)


def graficar_histograma_loglog(x, frecuencias, titulo, xlabel, ylabel, ruta_guardado, x_min=10, x_max=65500):
    """Histograma de frecuencias con ambos ejes logaritmicos."""
    x = np.asarray(x, dtype=float)
    frecuencias = np.asarray(frecuencias, dtype=float)

    # El eje logaritmico no admite ceros ni valores fuera del rango pedido.
    mascara = (x > 0) & (frecuencias > 0)
    x, frecuencias = x[mascara], frecuencias[mascara]
    if x.size == 0:
        return False

    figura, ejes = plt.subplots(figsize=(8, 5))
    ejes.bar(x, frecuencias, width=_anchuras_logaritmicas(x), color="steelblue", edgecolor="black", linewidth=0.3)
    ejes.set_xscale("log")
    ejes.set_yscale("log")
    ejes.set_xlim(x_min, x_max)
    ejes.set_ylim(bottom=0.8)  # las frecuencias son enteras, no bajan de 1
    ejes.set_title(titulo)
    ejes.set_xlabel(xlabel)
    ejes.set_ylabel(ylabel)
    ejes.grid(True, which="both", alpha=0.3)
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)
    return True


def graficar_cdf(x, y, titulo, xlabel, ylabel, ruta_guardado, x_min=10, x_max=None):
    """CDF acotada a la zona donde realmente cambia."""
    figura, ejes = plt.subplots(figsize=(8, 5))
    ejes.plot(x, y, color="green", linewidth=1.4)
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
    ejes.set_title(titulo)
    ejes.set_xlabel("Time (UTC+1)")
    ejes.set_ylabel("Active attacks")
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
    ejes.set_xlabel(xlabel)
    ejes.set_ylabel(ylabel)
    ejes.grid(True, which="both", alpha=0.3)
    figura.tight_layout()
    figura.savefig(ruta_guardado, dpi=150)
    plt.close(figura)
    return True
