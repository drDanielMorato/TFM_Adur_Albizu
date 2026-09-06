from collections import defaultdict
import numpy as np
import ipaddress

RANGOS_INTERNOS =["130.206.158.0/23", #130.206.158.0 - 130.206.159.255 
                  "130.206.160.0/20"] #130.206.160.0 - 130.206.175.255
# Para agilizar:
REDES_INTERNAS = [ipaddress.ip_network(r, strict=False) for r in RANGOS_INTERNOS]
_cache_ips = {}

def calcularPorcentajesDeTotalFlujos(numeroRegistrosFlujoTotal, y):
    """ Dada y, que serían las frecuencias en un histograma,
    las divide por el número total de tregistros de flujo
    """
    porcentajes =[conteo/numeroRegistrosFlujoTotal*100 for conteo in y]

    # Comprobando porsiaca:
    suma = sum(porcentajes)
    print(suma) 

    return porcentajes 

def calcularMediaPorGrupo(x,y):
    """Para cada x, calcula la media de los valores y asociados
    """
    grupos = defaultdict(list)

    for xi, yi in zip(x,y):
        grupos[xi].append(yi)

    return {xi: sum(ys)/len(ys) for xi, ys in grupos.items()} 


def CDF(data):
    """ calcula la cdf para una array the valores"""
    x = np.sort(data)
    y = np.arange(1, len(x)+1) / len(x)
    return x,y

def esIpInterna(src_ip: str) -> bool:
    if src_ip in _cache_ips:
        return _cache_ips[src_ip]

    addr = ipaddress.ip_address(src_ip)
    resultado = any(addr in red for red in REDES_INTERNAS)
    _cache_ips[src_ip] = resultado
    return resultado

def filtrarPorIpSrc(x,z,quedarmeConInterna):
    """ filtra x según la ipSrc, que viene en z.
    filtroIpExterna significa que me quedo con ip externa
    """
    return [xi for xi, zi in zip(x, z) if esIpInterna(zi) == quedarmeConInterna]

def obtener_percentiles(x) -> None:
    p25 = np.percentile(x, 25)
    print(f"Percentile 25: {p25} ")
    
    p50 = np.percentile(x, 50)
    print(f"Percentile 50: {p50} ")

    p75 = np.percentile(x, 75)
    print(f"Percentile 75: {p75} ")
    
    p90 = np.percentile(x, 90)
    print(f"Percentile 90: {p90} ")

    p99 = np.percentile(x, 99)
    print(f"Percentile 99: {p99} ")
