"""
graficar.py
Funciones para leer datos (x, y) desde un .txt y generar histogramas.
"""
 
from collections import Counter
import csv
import mmap
import io
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator
 
def leerColumna(ruta_txt, columna, separador=None):
    """
    Lee un archivo .txt y devuelve como lista los valores de una sola columna.
    Usa mmap para mapear el archivo en memoria en vez de leerlo por bloques.
    """
    x = []
    count = 1
    with open(ruta_txt, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapa:
            # mmap nos da bytes; csv.reader necesita texto, así que
            # envolvemos el mapa con TextIOWrapper para leerlo como texto
            texto = io.TextIOWrapper(io.BytesIO(mapa), encoding="utf-8")
            for linea in texto:
                linea = linea.strip()
                if not linea:  # saltar líneas vacías
                    continue
                if count > 2:
                    partes = linea.split(separador)
                    x.append(float(partes[columna]))
                    # if count ==4:
                    #     print("holas",partes[0])
                count+=1
    return x

def leerColumnas(ruta_txt, columna1, columna2 = None, separador=None):
    """
    Lee un archivo .txt y devuelve como lista los valores de una sola columna.
    Usa mmap para mapear el archivo en memoria en vez de leerlo por bloques.
    """
    x = []
    y = [] 
    count = 1
    with open(ruta_txt, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapa:
            # mmap nos da bytes; csv.reader necesita texto, así que
            # envolvemos el mapa con TextIOWrapper para leerlo como texto
            texto = io.TextIOWrapper(io.BytesIO(mapa), encoding="utf-8")
            for linea in texto:
                linea = linea.strip()
                if not linea:  # saltar líneas vacías
                    continue
                if count > 2:
                    partes = linea.split(separador)
                    x.append(partes[columna1])
                    y.append(partes[columna2])
                    # if count ==4:
                    #     print("holas",partes[0])
                count+=1
                
    return x,y



def calcular_histograma_simple(valores, guardar_csv=None):
    conteo = Counter(valores)
    x = sorted(conteo.keys())
    frecuencia = [conteo[val] for val in x]

    outputFile = os.path.join(guardar_csv, "histogram.csv")

    if guardar_csv:
        with open(outputFile, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["x", "frecuencia"])
            writer.writerows(zip(x, frecuencia))
        # print(f"CSV guardado en: {outputFile}")

    return x, frecuencia

 
def graficar_histograma_frecuencias(x, frecuencia, titulo="Histograma",
                                     xlabel="x", ylabel="Frecuencia",
                                     ancho_barra=None, guardar_como=None, maxEjeX = None, logaritmico = False, figura = 1):
    """
    Genera un histograma de barras a partir de valores de x que YA
    traen su frecuencia asociada (no se calculan bins, se dibuja tal cual).
 
    Si 'ancho_barra' es None, se calcula automáticamente a partir del
    espaciado entre valores de x consecutivos.
    Si 'guardar_como' se indica (ej: "salida.png"), guarda la imagen en
    lugar de solo mostrarla.
    """
    if ancho_barra is None:
            ancho_barra = 0.01
 
    plt.figure(figura,figsize=(8, 5))
    plt.bar(x, frecuencia, width=ancho_barra, color="steelblue", edgecolor="black")
    # plt.plot(x,frecuencia)
    plt.title(titulo)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    # plt.grid(True)
    plt.xlim(min(x),maxEjeX)

    if logaritmico:
        plt.yscale('log', base = 10)
    else:
        plt.yscale('linear')
 
    if guardar_como:
        plt.savefig(guardar_como, dpi=150)
        # print(f"Histograma guardado en: {guardar_como}")

    
def graficar_curva(x, frecuencia, titulo="Histograma", xlabel="x", ylabel="Frecuencia", guardar_como=None, maxEjeX = None, figura = 1):
    """
    Genera un plot notmal
    """
 
    plt.figure(figura,figsize=(8, 5))
    # plt.plot(x,frecuencia)
    plt.title(titulo)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    # plt.grid(True)
    plt.xlim(min(x),maxEjeX)
    plt.plot(x,frecuencia,'green')
 
    if guardar_como:
        plt.savefig(guardar_como, dpi=150)
        # print(f"Plot guardado en: {guardar_como}")
   


def graficar_actividad_temporal_protocolos(tiempos, actividad_por_protocolo, titulo="Temporal Activity by Protocol", guardar_como=None, figura=1, zona_horaria=None):
    """Plots the number of active attacks over time by protocol."""
    plt.figure(figura, figsize=(12, 6))

    colores = {
        "TCP": "steelblue",
        "UDP": "darkorange"
    }

    for protocolo, actividad in actividad_por_protocolo.items():
        plt.step(tiempos, actividad, where="mid", label=protocolo, color=colores.get(protocolo, None), linewidth=1.8)

    plt.title(titulo)
    plt.xlabel("time (UTC+1)")
    plt.ylabel("active attacks")
    plt.legend()
    plt.grid(True, alpha=0.3)

    ax = plt.gca()
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M", tz=zona_horaria))
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()

    if guardar_como:
        plt.savefig(guardar_como, dpi=150)




