"""Visualize the ports scanned by one scan from a TXT file."""

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter

# Sirve para generar un gráfico de los puertos escaneados por un ataque.

def leer_puertos(archivo):
    """Read comma-separated ports from a text file and return sorted unique ports."""
    texto = Path(archivo).read_text(encoding="utf-8")
    texto = re.sub(r"\x1b\]633;[^\x07]*\x07", "", texto)
    puertos = set()
    for numero, valor in enumerate(texto.replace("\n", ",").split(","), start=1):
        valor = valor.strip()
        if not valor:
            continue
        try:
            puerto = int(valor)
        except ValueError as error:
            raise ValueError(f"Invalid port at item {numero}: {valor!r}") from error
        if not 0 <= puerto <= 65535:
            raise ValueError(f"Port outside the 0–65535 range: {puerto}")
        puertos.add(puerto)
    if not puertos:
        raise ValueError("The input file does not contain any port")
    return sorted(puertos)


def leer_puertos_y_rango(archivo):
    """Return ports present in a port list or in an Nmap report, plus its range."""
    texto = Path(archivo).read_text(encoding="utf-8")
    texto_limpio = re.sub(r"\x1b\]633;[^\x07]*\x07", "", texto)

    rango_nmap = re.search(r"\s-p\s+(\d+)(?:-(\d+))?\b", texto_limpio)
    if rango_nmap:
        puerto_minimo = int(rango_nmap.group(1))
        puerto_maximo = int(rango_nmap.group(2) or rango_nmap.group(1))
        puertos = sorted(
            int(coincidencia.group(1))
            for coincidencia in re.finditer(
                r"^\s*(\d+)/(?:tcp|udp)\s+(?:open|open\|filtered)\b",
                texto_limpio,
                re.MULTILINE,
            )
        )
        if not puertos:
            raise ValueError("The Nmap report does not contain any listed port")
        return puertos, puerto_minimo, puerto_maximo

    puertos = leer_puertos(archivo)
    return puertos, puertos[0], puertos[-1]


def generar_grafico_puertos(archivo, salida=None, mostrar=True, desde=None, hasta=None):
    """Plot whether each port in the input range appears in the input file."""
    puertos, puerto_minimo, puerto_maximo = leer_puertos_y_rango(archivo)
    if desde is not None:
        puerto_minimo = desde
    if hasta is not None:
        puerto_maximo = hasta
    if puerto_minimo > puerto_maximo:
        raise ValueError("The lower port limit cannot be greater than the upper limit")
    if not 0 <= puerto_minimo <= 65535 or not 0 <= puerto_maximo <= 65535:
        raise ValueError("The plot range must be between 0 and 65535")
    puertos_en_rango = np.arange(puerto_minimo, puerto_maximo + 1)
    puertos_escaneados = np.isin(puertos_en_rango, puertos)

    figura, eje = plt.subplots(figsize=(14, 2.8))
    colores = plt.matplotlib.colors.ListedColormap(["#e5e7eb", "#176b87"])
    eje.imshow(
        puertos_escaneados[np.newaxis, :],
        aspect="auto",
        interpolation="none",
        cmap=colores,
        extent=(puerto_minimo - 0.5, puerto_maximo + 0.5, 0, 1),
        vmin=0,
        vmax=1,
    )
    eje.plot([], [], color="#176b87", linewidth=8, label="Scanned")
    eje.plot([], [], color="#e5e7eb", linewidth=8, label="Not scanned")

    eje.set_xlim(puerto_minimo - 0.5, puerto_maximo + 0.5)
    eje.set_ylim(0, 1)
    eje.set_xlabel("Port number")
    eje.set_yticks([])
    eje.set_title(f"Scanned ports ({puerto_minimo:,}–{puerto_maximo:,})")
    eje.xaxis.set_major_locator(plt.MaxNLocator(12, integer=True))
    eje.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    eje.grid(axis="x", alpha=0.25)
    eje.legend(loc="upper center", bbox_to_anchor=(0.5, -0.35), ncol=2, frameon=False)
    eje.spines["top"].set_visible(False)
    eje.spines["right"].set_visible(False)
    eje.spines["left"].set_visible(False)
    eje.tick_params(axis="y", length=0)
    figura.tight_layout()

    if salida is None:
        salida = Path(archivo).with_name(f"{Path(archivo).stem}_port_map.png")
    salida = Path(salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    figura.savefig(salida, dpi=180, bbox_inches="tight", facecolor="white")
    print(f"Port map saved to: {salida}")
    if mostrar:
        plt.show()
    else:
        plt.close(figura)
    return salida


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archivo", help="TXT containing comma-separated ports")
    parser.add_argument("--salida", help="Output PNG path")
    parser.add_argument("--desde", type=int, help="First port to show")
    parser.add_argument("--hasta", type=int, help="Last port to show")
    parser.add_argument("--no-mostrar", action="store_true", help="Only save the PNG")
    args = parser.parse_args()
    generar_grafico_puertos(
        args.archivo,
        args.salida,
        not args.no_mostrar,
        args.desde,
        args.hasta,
    )