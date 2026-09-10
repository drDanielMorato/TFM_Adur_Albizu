"""Genera gráficas globales de las estadisticas globales generadas para cada disco"""
import argparse
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt


ARCHIVO_ENTRADA = Path(
    "/home/adur/Desktop/TFM_Ziber/DatosPruebas/Out/metodo 3/"
    "resultados_globales/global.txt"
)
ARCHIVO_CONVERSACIONES = Path(
    "/home/adur/Desktop/TFM_Ziber/DatosPruebas/Out/metodo 3/resultado.txt"
)
PROTOCOLOS = ("TCP", "UDP")
COLORES = {"TCP": "#2463a6", "UDP": "#d97706", "TOTAL": "#26734d"}

# Dias incompletos o repartidos entre dos discos: no entran en ningun ranking.
DIAS_EXCLUIDOS = {
    date(2017, 12, 19): "incompleto",
    date(2018, 1, 18): "a medias entre dos discos",
    date(2018, 2, 7): "a medias entre dos discos",
    date(2018, 2, 26): "a medias entre dos discos",
    date(2018, 3, 15): "ultimo dia de los discos",
}
MINIMO_VICTIMAS = 2
CABECERA_RANKING = (
    f"{'Rank':<8} {'Proto':<7} {'Attacker IP':<39} {'No. of victims':>12} "
    f"{'Mean unique ports/victim':>28}"
)


def leer_resultados(ruta):
    """Lee los conteos de global.txt agrupados por fecha y protocolo."""
    datos = defaultdict(dict)

    with ruta.open(encoding="utf-8") as archivo:
        for numero_linea, linea in enumerate(archivo, start=1):
            campos = linea.split()
            if not campos or campos[0].lower().startswith("día"):
                continue
            if len(campos) != 8:
                raise ValueError(
                    f"Línea {numero_linea}: se esperaban 8 columnas y hay {len(campos)}"
                )

            try:
                fecha = datetime.strptime(campos[0], "%Y-%m-%d").date()
                protocolo = campos[1].upper()
                conversaciones = int(campos[3])
                sospechosas = int(campos[4])
            except ValueError as error:
                raise ValueError(f"Línea {numero_linea} no válida: {linea.strip()}") from error

            if protocolo not in PROTOCOLOS:
                raise ValueError(
                    f"Línea {numero_linea}: protocolo no admitido: {protocolo}"
                )
            if protocolo in datos[fecha]:
                raise ValueError(
                    f"Línea {numero_linea}: entrada duplicada para {fecha} {protocolo}"
                )
            if conversaciones < 0 or sospechosas < 0 or sospechosas > conversaciones:
                raise ValueError(f"Línea {numero_linea}: conteos no válidos")

            datos[fecha][protocolo] = {
                "conversaciones": conversaciones,
                "sospechosas": sospechosas,
            }

    if not datos:
        raise ValueError("El fichero no contiene filas de datos")

    incompletas = [
        fecha for fecha, protocolos in datos.items()
        if set(protocolos) != set(PROTOCOLOS)
    ]
    if incompletas:
        fechas = ", ".join(fecha.isoformat() for fecha in sorted(incompletas))
        raise ValueError(f"Hay días presentes sin ambos protocolos: {fechas}")

    return dict(datos)


def rango_fechas(inicio, fin):
    fecha = inicio
    while fecha <= fin:
        yield fecha
        fecha += timedelta(days=1)


def porcentaje(sospechosas, conversaciones):
    return sospechosas * 100 / conversaciones if conversaciones else 0.0


def metricas_fecha(datos_fecha):
    metricas = {}
    for protocolo in PROTOCOLOS:
        conversaciones = datos_fecha[protocolo]["conversaciones"]
        sospechosas = datos_fecha[protocolo]["sospechosas"]
        metricas[protocolo] = (conversaciones, sospechosas)

    conversaciones_total = sum(metricas[p][0] for p in PROTOCOLOS)
    sospechosas_total = sum(metricas[p][1] for p in PROTOCOLOS)
    metricas["TOTAL"] = (conversaciones_total, sospechosas_total)
    return metricas


def preparar_series(datos, fechas):
    porcentajes = {clave: [] for clave in (*PROTOCOLOS, "TOTAL")}
    absolutos = {clave: [] for clave in (*PROTOCOLOS, "TOTAL")}

    for fecha in fechas:
        if fecha not in datos:
            for clave in porcentajes:
                porcentajes[clave].append(float("nan"))
                absolutos[clave].append(float("nan"))
            continue

        for clave, (conversaciones, sospechosas) in metricas_fecha(datos[fecha]).items():
            porcentajes[clave].append(porcentaje(sospechosas, conversaciones))
            absolutos[clave].append(sospechosas)

    return porcentajes, absolutos


def configurar_eje_fechas(eje):
    localizador = mdates.AutoDateLocator(minticks=6, maxticks=14)
    eje.xaxis.set_major_locator(localizador)
    eje.xaxis.set_major_formatter(mdates.ConciseDateFormatter(localizador))
    eje.grid(True, axis="both", alpha=0.25)


def sombrear_dias_sin_datos(eje, fechas_sin_datos):
    for indice, fecha in enumerate(fechas_sin_datos):
        centro = mdates.date2num(fecha)
        eje.axvspan(
            centro - 0.5,
            centro + 0.5,
            color="#9ca3af",
            alpha=0.22,
            linewidth=0,
            label="No data" if indice == 0 else None,
        )


def guardar_grafica(
    fechas, series, protocolo, fechas_sin_datos, ruta, titulo, etiqueta_y,
    escala_logaritmica=False,
):
    figura, eje = plt.subplots(figsize=(13, 6.5))
    posiciones = mdates.date2num(fechas)
    eje.bar(
        posiciones,
        series[protocolo],
        width=0.8,
        label=protocolo,
        color=COLORES[protocolo],
    )

    sombrear_dias_sin_datos(eje, fechas_sin_datos)
    configurar_eje_fechas(eje)
    eje.set_title(titulo)
    eje.set_xlabel("Date")
    eje.set_ylabel(etiqueta_y)
    eje.set_xlim(posiciones[0] - 0.5, posiciones[-1] + 0.5)
    if escala_logaritmica:
        eje.set_yscale("log")
    else:
        eje.set_ylim(bottom=0)
    eje.legend()
    figura.tight_layout()
    figura.savefig(ruta, dpi=180)
    plt.close(figura)


def formatear_entero(valor):
    return f"{valor:,}".replace(",", ".")


def escribir_informe(datos, fechas, fechas_sin_datos, ruta):
    totales = {
        clave: {"conversaciones": 0, "sospechosas": 0}
        for clave in (*PROTOCOLOS, "TOTAL")
    }

    for datos_fecha in datos.values():
        for clave, (conversaciones, sospechosas) in metricas_fecha(datos_fecha).items():
            totales[clave]["conversaciones"] += conversaciones
            totales[clave]["sospechosas"] += sospechosas

    segundos_observados = len(datos) * 24 * 60 * 60

    lineas = [
        "RESUMEN DE CONVERSACIONES SOSPECHOSAS",
        "====================================",
        f"Periodo: {fechas[0].isoformat()} a {fechas[-1].isoformat()}",
        f"Días del periodo: {len(fechas)}",
        f"Días con datos: {len(datos)}",
        f"Días sin datos: {len(fechas_sin_datos)}",
        "Fechas sin datos: "
        + (", ".join(fecha.isoformat() for fecha in fechas_sin_datos) or "ninguna"),
        "",
        "TOTALES GLOBALES",
        "----------------",
        f"Tiempo observado para las tasas: {formatear_entero(segundos_observados)} s",
        "(días con datos x 86.400 s; los días sin datos quedan excluidos)",
        "",
    ]

    for clave in (*PROTOCOLOS, "TOTAL"):
        conversaciones = totales[clave]["conversaciones"]
        sospechosas = totales[clave]["sospechosas"]
        etiqueta = "TCP + UDP" if clave == "TOTAL" else clave
        lineas.extend([
            f"{etiqueta}:",
            f"  Conversaciones: {formatear_entero(conversaciones)}",
            f"  Conversaciones sospechosas: {formatear_entero(sospechosas)}",
            f"  Porcentaje sospechoso: {porcentaje(sospechosas, conversaciones):.6f}%",
            f"  Conversaciones por segundo: {conversaciones / segundos_observados:.6f}",
            f"  Conversaciones sospechosas por segundo: {sospechosas / segundos_observados:.9f}",
        ])

    encabezado = (
        f"{'Fecha':<12} {'Estado':<10} "
        f"{'Conv. TCP':>14} {'Sosp. TCP':>12} {'% TCP':>11} "
        f"{'Conv. UDP':>14} {'Sosp. UDP':>12} {'% UDP':>11} "
        f"{'Conv. total':>14} {'Sosp. total':>13} {'% total':>11}"
    )
    lineas.extend(["", "DETALLE DIARIO", "---------------", encabezado, "-" * len(encabezado)])

    for fecha in fechas:
        if fecha not in datos:
            lineas.append(f"{fecha.isoformat():<12} {'SIN DATOS':<10} " + "N/D".rjust(len(encabezado) - 23))
            continue

        metricas = metricas_fecha(datos[fecha])
        columnas = []
        for clave in (*PROTOCOLOS, "TOTAL"):
            conversaciones, sospechosas = metricas[clave]
            columnas.extend([
                f"{formatear_entero(conversaciones):>14}",
                f"{formatear_entero(sospechosas):>12}",
                f"{porcentaje(sospechosas, conversaciones):>10.6f}%",
            ])
        lineas.append(f"{fecha.isoformat():<12} {'CON DATOS':<10} " + " ".join(columnas))

    lineas.extend([
        "",
        "Nota: los días sin datos no se contabilizan como cero. En las gráficas se",
        "representan mediante una franja gris y no contienen ninguna barra.",
        "Los porcentajes se recalculan a partir de los conteos sin usar el valor",
        "redondeado que figura en el fichero de entrada.",
        "Las tasas por segundo son promedios calculados sobre días completos con",
        "datos; no representan mediciones instantáneas segundo a segundo.",
    ])

    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")


def leer_contactos(ruta):
    """Agrupa los puertos por fecha, protocolo, IP origen e IP destino.

    Los puertos se unen entre conversaciones del mismo (protocolo, origen,
    destino): sumar los contadores «No. Unique» contaria dos veces los repetidos.
    """
    por_dia = defaultdict(dict)
    globales = {}
    descartadas = 0

    with ruta.open(encoding="utf-8") as entrada:
        for numero_linea, linea in enumerate(entrada, start=1):
            texto = linea.strip()
            if not texto or texto.startswith("Start (unix)") or set(texto) == {"-"}:
                continue

            # Las fechas UTC ocupan dos campos cada una al separar por espacios.
            campos = texto.split(maxsplit=12)
            try:
                if len(campos) != 13:
                    raise ValueError("se esperaban 13 campos, incluida la lista de puertos")
                fecha = datetime.strptime(campos[2], "%Y-%m-%d").date()
                protocolo, origen, destino = campos[6].upper(), campos[7], campos[8]
                puertos = {int(puerto) for puerto in campos[12].split(",") if puerto}
                if any(puerto < 0 or puerto > 65535 for puerto in puertos):
                    raise ValueError("puerto fuera del rango 0-65535")
            except ValueError as error:
                raise ValueError(f"{ruta}, linea {numero_linea}: {error}") from error

            if fecha in DIAS_EXCLUIDOS:
                descartadas += 1
                continue

            for destinos in (por_dia[fecha].setdefault(protocolo, {}),
                             globales.setdefault(protocolo, {})):
                destinos.setdefault(origen, {}).setdefault(destino, set()).update(puertos)

    return dict(por_dia), globales, descartadas


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
        lineas.extend([f"\nRanking of attackers — {protocolo}",
                       CABECERA_RANKING, "-" * len(CABECERA_RANKING)])
        if not filas:
            lineas.append("No hay IPs que hayan contactado mas de 2 victimas diferentes.")
            continue
        for fila in filas:
            lineas.append(f"{fila['puesto']:<8} {protocolo:<7} {fila['ip_atacante']:<39} "
                          f"{fila['numero_victimas']:>12} "
                          f"{fila['media_puertos_unicos_por_victima']:>28.2f}")

    return "\n".join(lineas) + "\n"


def escribir_rankings(archivo_conversaciones, directorio_salida):
    """Escribe un ranking por dia mas uno acumulado de todo el periodo."""
    por_dia, globales, descartadas = leer_contactos(archivo_conversaciones)

    directorio = directorio_salida / "rankings"
    directorio.mkdir(parents=True, exist_ok=True)
    rutas = []

    for fecha in sorted(por_dia):
        ruta = directorio / f"ranking_conversaciones_{fecha.isoformat()}.txt"
        ruta.write_text(
            formatear_ranking(
                construir_ranking(por_dia[fecha]),
                f"Ranking de conversaciones - {fecha.isoformat()}",
            ),
            encoding="utf-8",
        )
        rutas.append(ruta)

    excluidos = ", ".join(
        f"{fecha.isoformat()} ({motivo})" for fecha, motivo in sorted(DIAS_EXCLUIDOS.items())
    )
    encabezado_extra = [
        f"Dias con datos: {len(por_dia)}",
        f"Periodo: {min(por_dia).isoformat()} a {max(por_dia).isoformat()}" if por_dia
        else "Periodo: sin datos",
        f"Dias descartados: {excluidos}",
        f"Conversaciones descartadas por pertenecer a esos dias: {formatear_entero(descartadas)}",
    ]

    ruta_global = directorio / "ranking_conversaciones_global.txt"
    ruta_global.write_text(
        formatear_ranking(
            construir_ranking(globales),
            "Ranking de conversaciones - global",
            encabezado_extra,
        ),
        encoding="utf-8",
    )
    rutas.append(ruta_global)

    return rutas


def analizar(archivo_entrada, directorio_salida, archivo_conversaciones=None):
    datos = leer_resultados(archivo_entrada)
    fechas = list(rango_fechas(min(datos), max(datos)))
    fechas_con_datos = sorted(datos)
    fechas_sin_datos = [fecha for fecha in fechas if fecha not in datos]
    porcentajes, absolutos = preparar_series(datos, fechas_con_datos)

    directorio_salida.mkdir(parents=True, exist_ok=True)
    ruta_porcentaje_tcp = directorio_salida / "porcentaje_conversaciones_sospechosas_diario_tcp.png"
    ruta_porcentaje_udp = directorio_salida / "porcentaje_conversaciones_sospechosas_diario_udp.png"
    ruta_absoluto_tcp = directorio_salida / "conversaciones_sospechosas_diarias_tcp.png"
    ruta_absoluto_udp = directorio_salida / "conversaciones_sospechosas_diarias_udp.png"
    ruta_porcentaje_tcp_log = directorio_salida / "porcentaje_conversaciones_sospechosas_diario_tcp_logaritmico.png"
    ruta_absoluto_tcp_log = directorio_salida / "conversaciones_sospechosas_diarias_tcp_logaritmico.png"
    ruta_informe = directorio_salida / "resumen_conversaciones_diarias.txt"

    guardar_grafica(
        fechas_con_datos,
        porcentajes,
        "TCP",
        fechas_sin_datos,
        ruta_porcentaje_tcp,
        "Daily Percentage of Suspicious TCP Conversations",
        "Suspicious conversations (%)",
    )
    guardar_grafica(
        fechas_con_datos,
        porcentajes,
        "UDP",
        fechas_sin_datos,
        ruta_porcentaje_udp,
        "Daily Percentage of Suspicious UDP Conversations",
        "Suspicious conversations (%)",
    )
    guardar_grafica(
        fechas_con_datos,
        absolutos,
        "TCP",
        fechas_sin_datos,
        ruta_absoluto_tcp,
        "Daily Number of Suspicious TCP Conversations",
        "Suspicious conversations",
    )
    guardar_grafica(
        fechas_con_datos,
        absolutos,
        "UDP",
        fechas_sin_datos,
        ruta_absoluto_udp,
        "Daily Number of Suspicious UDP Conversations",
        "Suspicious conversations",
    )
    guardar_grafica(
        fechas_con_datos,
        porcentajes,
        "TCP",
        fechas_sin_datos,
        ruta_porcentaje_tcp_log,
        "Daily Percentage of Suspicious TCP Conversations",
        "Suspicious conversations (%, log scale)",
        escala_logaritmica=True,
    )
    guardar_grafica(
        fechas_con_datos,
        absolutos,
        "TCP",
        fechas_sin_datos,
        ruta_absoluto_tcp_log,
        "Daily Number of Suspicious TCP Conversations",
        "Suspicious conversations (log scale)",
        escala_logaritmica=True,
    )
    escribir_informe(datos, fechas, fechas_sin_datos, ruta_informe)

    rutas = [
        ruta_porcentaje_tcp,
        ruta_porcentaje_udp,
        ruta_absoluto_tcp,
        ruta_absoluto_udp,
        ruta_porcentaje_tcp_log,
        ruta_absoluto_tcp_log,
        ruta_informe,
    ]

    if archivo_conversaciones is not None:
        if archivo_conversaciones.is_file():
            rutas.extend(escribir_rankings(archivo_conversaciones, directorio_salida))
        else:
            print(f"Aviso: no se encuentra {archivo_conversaciones}; se omiten los rankings")

    return tuple(rutas)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Genera gráficas diarias e informe de conversaciones sospechosas "
            "para TCP, UDP y ambos protocolos juntos."
        )
    )
    parser.add_argument(
        "--archivo",
        type=Path,
        default=ARCHIVO_ENTRADA,
        help=f"Fichero global.txt (por defecto: {ARCHIVO_ENTRADA})",
    )
    parser.add_argument(
        "--directorio-salida",
        type=Path,
        help="Directorio de salida (por defecto: el directorio de global.txt)",
    )
    parser.add_argument(
        "--archivo-conversaciones",
        type=Path,
        default=ARCHIVO_CONVERSACIONES,
        help=f"resultado.txt para los rankings (por defecto: {ARCHIVO_CONVERSACIONES})",
    )
    args = parser.parse_args()

    directorio_salida = args.directorio_salida or args.archivo.parent
    try:
        rutas = analizar(args.archivo, directorio_salida, args.archivo_conversaciones)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print("Archivos generados:")
    for ruta in rutas:
        print(f"  {ruta}")


if __name__ == "__main__":
    main()