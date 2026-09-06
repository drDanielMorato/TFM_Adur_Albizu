"""
Punto de entrada del programa. Importamos solo aquellas funciones
que necesitamos
"""

import argparse
from implementaciones import generarHistogramaNumeroPuertos, generarHistogramaNumeroPuertosLogaritmico, generarGraficoPorcentajeTraficoGlobalParaConversacionesConNPuertosUnicos, generarGraficoEntropiaParaConversacionNPuertosUnicos, generarGraficoCDFPuertosUnicos
import matplotlib.pyplot as plt

def main():
    parser = argparse.ArgumentParser(
        description= "..."
    )
    parser.add_argument("--archivo", help = "Ruta del la salida de EscaneoPuertos.py")
    parser.add_argument("--directorioGuardado", help = "Ruta donde guardar archivos .csv y gráficas resultantes")
    
    args = parser.parse_args()

    generarHistogramaNumeroPuertos(args, False, False, "Distribution of Conversations by Number of Unique Ports", 1)
    generarHistogramaNumeroPuertos(args, True, True, "Distribution of Conversations by Number of Unique Ports (outgoing)", 2)
    generarHistogramaNumeroPuertos(args, True, False, "Distribution of Conversations by Number of Unique Ports (incoming)", 3)
    generarHistogramaNumeroPuertosLogaritmico(args, 4)
    generarGraficoPorcentajeTraficoGlobalParaConversacionesConNPuertosUnicos(args, 5)
    generarGraficoEntropiaParaConversacionNPuertosUnicos(args, 6)

    generarGraficoCDFPuertosUnicos(args, 7)
    # print("hola")
    plt.show()

if __name__ == "__main__":
    main()