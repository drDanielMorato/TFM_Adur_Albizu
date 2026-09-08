"""Ranking de IPs origen por víctimas distintas, separado por protocolo."""

import argparse
from datetime import datetime
from pathlib import Path


ARCHIVO_ENTRADA = "/home/adur/Desktop/TFM_Ziber/DatosPruebas/Out/metodo 3/resultado.txt"


def generarRankingAtacantes(archivo=ARCHIVO_ENTRADA, directorioGuardado=None):
    """Lee resultado.txt, muestra el ranking y devuelve sus filas por protocolo.

    Se considera atacante a IpSrc y víctima a IpDst. Solo se incluyen orígenes
    con más de dos destinos distintos DENTRO de cada protocolo. No se aplica
    otro criterio de detección: se parte de los registros del archivo recibido.

    La media es la suma de los puertos únicos de cada víctima dividida entre
    el número de víctimas. Los puertos se unen entre todas las conversaciones
    del mismo (protocolo, origen, destino); no se promedian conversaciones ni
    se suman sus contadores «No. Unique», ya que podrían repetir puertos.

    Si se proporciona directorioGuardado, solo se escribe un TXT alineado,
    con una sección por protocolo y la fecha UTC de los datos en el nombre:
    ranking_atacantes_AAAA-MM-DD.txt. Si hay varios días, se incluye el rango
    AAAA-MM-DD_a_AAAA-MM-DD; si no hay registros, se utiliza sin_fecha.
    Las filas devueltas conservan la media sin redondear; las tablas la
    muestran con dos decimales. Los empates se ordenan por IP origen.
    """
    contactos = {}
    fechas = set()
    with open(archivo, encoding="utf-8") as entrada:
        for numero_linea, linea in enumerate(entrada, start=1):
            texto = linea.strip()
            if not texto or texto.startswith("Start (unix)") or set(texto) == {"-"}:
                continue

            # Las fechas UTC ocupan dos campos cada una al separar por espacios.
            campos = texto.split(maxsplit=12)
            try:
                if len(campos) != 13:
                    raise ValueError("se esperaban 13 campos, incluida la lista Target Ports")
                float(campos[0])
                float(campos[1])
                fecha_inicio = datetime.strptime(campos[2], "%Y-%m-%d").date()
                fecha_fin = datetime.strptime(campos[4], "%Y-%m-%d").date()
                protocolo, origen, destino = campos[6].upper(), campos[7], campos[8]
                puertos = {int(puerto) for puerto in campos[12].split(",")}
                if any(puerto < 0 or puerto > 65535 for puerto in puertos):
                    raise ValueError("puerto fuera del rango 0–65535")
            except ValueError as error:
                raise ValueError(f"{archivo}, línea {numero_linea}: {error}") from error

            fechas.update((fecha_inicio, fecha_fin))
            victimas = contactos.setdefault(protocolo, {}).setdefault(origen, {})
            victimas.setdefault(destino, set()).update(puertos)

    rankings = {}
    lineas_txt = []
    cabecera = (f"{'Puesto':<8} {'Proto':<7} {'IP atacante':<39} {'N.º víctimas':>12} "
                f"{'Media puertos únicos/víctima':>28}")
    for protocolo, atacantes in sorted(contactos.items()):
        filas = []
        for atacante, victimas in atacantes.items():
            numero_victimas = len(victimas)
            if numero_victimas > 2:
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

        lineas_txt.extend([f"\nRanking de atacantes — {protocolo}",
                           cabecera, "-" * len(cabecera)])
        if not filas:
            lineas_txt.append("No hay IPs que hayan contactado más de 2 víctimas diferentes.")
            continue
        for fila in filas:
            lineas_txt.append(f"{fila['puesto']:<8} {protocolo:<7} {fila['ip_atacante']:<39} "
                              f"{fila['numero_victimas']:>12} "
                              f"{fila['media_puertos_unicos_por_victima']:>28.2f}")

    if not contactos:
        lineas_txt.append("No hay registros de contactos en el archivo de entrada.")

    tabla_txt = "\n".join(lineas_txt) + "\n"
    print(tabla_txt, end="")

    if directorioGuardado is not None:
        directorio = Path(directorioGuardado)
        directorio.mkdir(parents=True, exist_ok=True)
        if not fechas:
            etiqueta_fecha = "sin_fecha"
        elif len(fechas) == 1:
            etiqueta_fecha = min(fechas).isoformat()
        else:
            etiqueta_fecha = f"{min(fechas).isoformat()}_a_{max(fechas).isoformat()}"
        ruta_txt = directorio / f"ranking_atacantes_{etiqueta_fecha}.txt"
        ruta_txt.write_text(tabla_txt, encoding="utf-8")
        print(f"Ranking guardado en: {ruta_txt}")

    return rankings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archivo", default=ARCHIVO_ENTRADA, help="Archivo resultado.txt")
    parser.add_argument("--directorioGuardado", help="Directorio del TXT fechado según los datos UTC (opcional)")
    args = parser.parse_args()
    generarRankingAtacantes(args.archivo, args.directorioGuardado)