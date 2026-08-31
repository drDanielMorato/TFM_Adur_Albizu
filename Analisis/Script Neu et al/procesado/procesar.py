from __future__ import annotations
from config import *
from .flujo import Flujo
from .candidato import Candidato
from collections import defaultdict
from utils.leer_archivos import leer_registros_flujo_tcp_ordenados

def procesar(ruta_archivo_flujos : str) -> list[Candidato]:
    """
    Proceso los datos para encontrar ips sospechosas de hacer un escaneo horizontal, vertical o mixto.
    """
    print("Preprocesando...")

    candidatos: list[Candidato] = []
    flujos : list[Flujo] = []

    tiempoInicioVentana: float | None = None
    contadorRegistrosFlujo : int = 0

    for tstart, cols in leer_registros_flujo_tcp_ordenados(ruta_archivo_flujos):
        try:
            srcIp = cols[COL_IP_SRC].decode()
            dstIp = cols[COL_IP_DST].decode()
            srcPort = int(cols[COL_PORT_SRC])
            dstPort = int(cols[COL_PORT_DST])
            num_paquetes_sd = int(cols[COL_NUMERO_PAQUETES_SRC_DST])
            num_paquetes_ds = int(cols[COL_NUMERO_PAQUETES_DST_SRC])
            numeroPaquetes = num_paquetes_sd + num_paquetes_ds
        except (IndexError, ValueError, UnicodeDecodeError) as error:
            raise RuntimeError(f"ERROR: {error} | columnas: {b' '.join(cols)[:80]}") from error

        if num_paquetes_sd == 0 and 0 < num_paquetes_ds <= 3:
            #Swap para solucionar asignaciones incorrectas de cliente y servicio de procesaConexiones (casos extremos)
            srcIp, dstIp = dstIp, srcIp
            srcPort, dstPort = dstPort, srcPort

        if tiempoInicioVentana is None:
            tiempoInicioVentana = tstart

        if tstart > tiempoInicioVentana + INTERVALO_VENTANA_ESCANEO:
            candidatos.extend(analizar_ventana(flujos))
            tiempoInicioVentana = tstart
            flujos = []

        if numeroPaquetes <= MAX_PAQUETES_FLUJO:
            nuevo_flujo = Flujo(tStart=tstart, srcIp=srcIp, dstIp=dstIp, dstPort=dstPort)
            flujos.append(nuevo_flujo)

        contadorRegistrosFlujo += 1
        if contadorRegistrosFlujo % 5_000_000 == 0:
            print(f"Procesadas {contadorRegistrosFlujo:,} líneas...")

    if flujos:
        candidatos.extend(analizar_ventana(flujos))

    return candidatos

def analizar_ventana(flujos : list[Flujo]) -> list[Candidato] :
    """
    Analiza los flujos en la ventana configurada para encontrar posibles escaneos horizontales, verticales y mixtos.
    """
    nuevos_candidatos : list[Candidato] = []

    # nuevos_candidatos.extend(detectar_escaneos_horizontales(flujos))
    nuevos_candidatos.extend(detectar_escaneos_verticales(flujos))
    # nuevos_candidatos.extend(detectar_escaneos_mixtos(flujos))

    return nuevos_candidatos

def detectar_escaneos_horizontales(flujos: list[Flujo]) -> list[Candidato]:
    """
    Agrupa flujos por ips y pd, y devuelve los grupos con al menos 3 ipd distintos
    """
    groups: dict[tuple[str, int], list[Flujo]] = defaultdict(list)

    for flujo in flujos:
        key = (flujo.srcIp, flujo.dstPort)
        groups[key].append(flujo)  

    candidatos = []
    for key, flujosDelGrupo in groups.items():
        ipsDestino = {f.dstIp for f in flujosDelGrupo}  # ips únicas para el filtro
        if len(ipsDestino) >= UMBRAL_HOSTS_HORIZONTAL:
            candidatos.append(
                Candidato(
                    tInicio=min(f.tStart for f in flujosDelGrupo),  # el más antiguo del grupo
                    srcIp=key[0],
                    scans=[(list(ipsDestino), [key[1]])],
                    scanType="HorizontalScan",
                )
            )

    return candidatos

def detectar_escaneos_verticales(flujos: list[Flujo]) -> list[Candidato]:
    """
    Agrupa flujos por ips e ipds, y devuelve aquellos con una suma total de pesos de flujos >=15
    """
    groups: dict[tuple[str, str], list[Flujo]] = defaultdict(list)
    
    for flujo in flujos:
        key = (flujo.srcIp, flujo.dstIp)
        groups[key].append(flujo)  

    candidatos = []
    for key, flujosDelGrupo in groups.items():
        puertosDestino = {f.dstPort for f in flujosDelGrupo}  # puertos únicos para el filtro  
        if cacular_peso_total(puertosDestino) >= UMBRAL_PESO_VERTICAL:
            candidatos.append(
                Candidato(
                    tInicio=min(f.tStart for f in flujosDelGrupo),  # el más antiguo del grupo
                    srcIp=key[0],
                    scans=[([key[1]], list(puertosDestino))],
                    scanType="VerticalScan",
                )
            )

    return candidatos

def cacular_peso_total(puertos_destino : list[int]) -> int:
    """
    Dada la lista de puertos escaneados por un grupo de flujos identificados por (ipsrc, ipdst), se calcula
    un peso W = 5 * CPS + 3 * OPS, donde CPS son puertos comunmente atacos y OPS puertos convencionales
    """
    W = sum([
        calcular_peso_individual(p)
        for p in puertos_destino
    ])

    return W

def calcular_peso_individual(puerto : int) -> int:
    """
    calcula el peso según si un puerto es conocido o no conocido
    """
    if (puerto in PUERTOS_CONOCIDOS):
        return PESO_PUERTOS_CONOCIDOS
    else:
        return PESO_PUERTOS_COMUNES

def detectar_escaneos_mixtos(flujos: list[Flujo]) -> list[Candidato]:
    """
    Detecta escaneos mixtos: la ips contactó al menos 2 ipd distintas, y al menos
    una de ellas tiene un peso vertical (suma de pesos de puertos) >= 6.
    """

    # Agrupamos por (srcIp, dstIp) para poder calcular puertos y peso por host
    groupsPorPar: dict[tuple[str, str], list[Flujo]] = defaultdict(list)
    for flujo in flujos:
        key = (flujo.srcIp, flujo.dstIp)
        groupsPorPar[key].append(flujo)

    # Puertos únicos y peso vertical de cada (srcIp, dstIp)
    puertosPorPar: dict[tuple[str, str], list[int]] = {}
    pesosPorPar: dict[tuple[str, str], int] = {}
    tInicioPorPar: dict[tuple[str, str], float] = {}

    for key, flujosDelGrupo in groupsPorPar.items():
        puertosDestino = [f.dstPort for f in flujosDelGrupo]
        puertosPorPar[key] = puertosDestino
        pesosPorPar[key] = cacular_peso_total(puertosDestino)
        tInicioPorPar[key] = min(f.tStart for f in flujosDelGrupo)

    # Hosts destino distintos contactados por cada srcIp
    hostsPorOrigen: dict[str, set[str]] = defaultdict(set)
    for (srcIp, dstIp) in groupsPorPar.keys():
        hostsPorOrigen[srcIp].add(dstIp)

    candidatos = []
    for srcIp, hosts in hostsPorOrigen.items():
        if len(hosts) < MIN_HOSTS_MIXTO:
            continue

        # ¿Al menos un host contactado supera el umbral vertical?
        hayHostMarcado = any(
            pesosPorPar[(srcIp, dstIp)] >= UMBRAL_PESO_MIXTO
            for dstIp in hosts
        )

        if hayHostMarcado:
            # scans: un elemento (ipDestino, puertosDestino) por cada host contactado
            scans = [
                ([dstIp], list(puertosPorPar[(srcIp, dstIp)]))
                for dstIp in hosts
            ]

            candidatos.append(
                Candidato(
                    tInicio=min(tInicioPorPar[(srcIp, dstIp)] for dstIp in hosts),
                    srcIp=srcIp,
                    scans=scans,
                    scanType="MixedScan",
                )
            )

    return candidatos