"""
Ranking de IPs origen por victimas distintas, con la misma regla que
Analisis/Graficado/dias/ranking_atacantes.py.
"""

import os

# Dias incompletos o repartidos entre dos discos: no entran en ningun ranking.
DIAS_EXCLUIDOS = {
    "2017-12-19": "incompleto",
    "2018-01-18": "a medias entre dos discos",
    "2018-02-07": "a medias entre dos discos",
    "2018-02-26": "a medias entre dos discos",
    "2018-03-15": "ultimo dia de los discos",
}
MINIMO_VICTIMAS = 2
CABECERA = (
    f"{'Rank':<8} {'Proto':<7} {'Attacker IP':<39} {'No. of victims':>12} "
    f"{'Mean unique ports/victim':>28}"
)


def dia_excluido(nombre_dia):
    return nombre_dia in DIAS_EXCLUIDOS


def fusionar_contactos(acumulado, contactos):
    """Une los puertos de un dia en la estructura global."""
    for protocolo, atacantes in contactos.items():
        destino_protocolo = acumulado.setdefault(protocolo, {})
        for atacante, victimas in atacantes.items():
            destino_atacante = destino_protocolo.setdefault(atacante, {})
            for victima, puertos in victimas.items():
                destino_atacante.setdefault(victima, set()).update(puertos)


def construir_ranking(contactos):
    """Ordena cada protocolo por numero de victimas distintas."""
    rankings = {}

    for protocolo, atacantes in sorted(contactos.items()):
        filas = []
        for atacante, victimas in atacantes.items():
            numero_victimas = len(victimas)
            if numero_victimas > MINIMO_VICTIMAS:
                filas.append({
                    "protocolo": protocolo,
                    "ip_atacante": atacante,
                    "numero_victimas": numero_victimas,
                    "media_puertos_unicos_por_victima": (
                        sum(len(puertos) for puertos in victimas.values()) / numero_victimas
                    ),
                })

        filas.sort(key=lambda fila: (-fila["numero_victimas"], fila["ip_atacante"]))
        for puesto, fila in enumerate(filas, start=1):
            fila["puesto"] = puesto
        rankings[protocolo] = filas

    return rankings


def formatear_ranking(rankings, titulo, encabezado_extra=()):
    lineas = [titulo, "=" * len(titulo), *encabezado_extra]

    if not rankings:
        lineas.append("No hay registros de contactos.")

    for protocolo, filas in rankings.items():
        lineas.extend([f"\nRanking of attackers - {protocolo}", CABECERA, "-" * len(CABECERA)])
        if not filas:
            lineas.append("No hay IPs que hayan contactado mas de 2 victimas diferentes.")
            continue
        for fila in filas:
            lineas.append(f"{fila['puesto']:<8} {protocolo:<7} {fila['ip_atacante']:<39} "
                          f"{fila['numero_victimas']:>12} "
                          f"{fila['media_puertos_unicos_por_victima']:>28.2f}")

    return "\n".join(lineas) + "\n"


def escribir_ranking_dia(contactos, directorio_salida, prefijo):
    ruta = os.path.join(directorio_salida, f"{prefijo}_ranking_conversaciones.txt")
    texto = formatear_ranking(construir_ranking(contactos),
                              f"Ranking de conversaciones - {prefijo}")
    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write(texto)
    return ruta


def escribir_ranking_global(contactos, directorio_salida, dias_incluidos, dias_descartados):
    excluidos = ", ".join(f"{dia} ({motivo})" for dia, motivo in sorted(DIAS_EXCLUIDOS.items()))
    encabezado = [
        f"Dias incluidos: {len(dias_incluidos)}",
        f"Periodo: {min(dias_incluidos)} a {max(dias_incluidos)}" if dias_incluidos
        else "Periodo: sin datos",
        f"Dias descartados por criterio: {excluidos}",
        f"Carpetas de dia descartadas en esta ejecucion: {dias_descartados}",
    ]

    ruta = os.path.join(directorio_salida, "ranking_conversaciones_global.txt")
    texto = formatear_ranking(construir_ranking(contactos),
                              "Ranking de conversaciones - global", encabezado)
    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write(texto)
    return ruta
