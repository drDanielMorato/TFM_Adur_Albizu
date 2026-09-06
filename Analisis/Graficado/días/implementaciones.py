from utils.graficar import leerColumna, leerColumnas, calcular_histograma_simple, graficar_histograma_frecuencias, graficar_curva
from utils.estadisticas import calcularPorcentajesDeTotalFlujos, calcularMediaPorGrupo, CDF, filtrarPorIpSrc
import argparse

def generarHistogramaNumeroPuertos(args, filtrar = False, quedarmeConInterna = False, titulo = "", numFigura = 1):
    """ Genera el histograma del números de puertos únicos, teniendo en cuenta
    todas las conversaciones
    """
    x,z = leerColumnas(args.archivo, 11, 7)
    x = [float(xi) for xi in x]

    if filtrar:
        x = filtrarPorIpSrc(x,z,quedarmeConInterna)

    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    
    graficar_histograma_frecuencias(x, f, titulo, "unique ports", "frecuency", None, args.directorioGuardado, 10001, False, numFigura)
    

def generarHistogramaNumeroPuertosLogaritmico(args, numFigura = 1):
    """ Genera el histograma del números de puertos únicos, teniendo en cuenta
    todas las conversaciones. Y en escala logarítmica
    """
    x = leerColumna(args.archivo, 11)
    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    graficar_histograma_frecuencias(x, f, "Distribution of Conversations by Number of Unique Ports", "unique ports", "log10(frecuency)", None, args.directorioGuardado, 10001, True, numFigura)

def generarGraficoPorcentajeTraficoGlobalParaConversacionesConNPuertosUnicos(args, numFigura = 1):
    """ 
    Genera gráfica en la que Y es porcentaje en el número de flujos global,
    y X es conversaciones con N puertos únicos
    """
    x = leerColumna(args.archivo, 11)
    print(f"longitud columna {len(x)}" )
    x,f = calcular_histograma_simple(x, args.directorioGuardado)
    
    numeroConversacionesTotal = 395431
    y = calcularPorcentajesDeTotalFlujos(numeroConversacionesTotal, f)
    graficar_histograma_frecuencias(x, y, "Percentage of Total Conversations With a Given Number of Unique Ports", "unique ports", "percentage", None, args.directorioGuardado, 10001, False, numFigura)

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
    graficar_histograma_frecuencias(x, y, "Mean Conversation Entropy (H) by Unique Ports", "unique ports", "H", None, args.directorioGuardado, 10001, False, numFigura)

def generarGraficoCDFPuertosUnicos(args, numFigura = 1):
    """ 
    Genero CDF para el número de puertos únicos.
    """
    x = leerColumna(args.archivo, 11)
    x,y = CDF(x)
    graficar_curva(x, y, "CDF", "unique ports", "CDF", args.directorioGuardado, 10001, numFigura)
