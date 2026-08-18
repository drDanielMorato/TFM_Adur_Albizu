from __future__ import annotations
from config import *
from .DatosPaquete import DatosPaquete
from .candidato import Candidato


def procesar(ruta_archivos_paquetes: str) -> None:
    """
    Consume leer_paquetes en streaming, agrupando los flujos en ventanas de 1 segundo,
    para no acumular en memoria todos los flujos de los 24 pcaps a la vez.
    """
    from utils import leer_paquetes  # import diferido: evita el ciclo utils <-> procesado

    candidatos: list[Candidato] = []
    flujos: list[DatosPaquete] = []
    tiempoInicioVentana: float | None = None

    for paquete in leer_paquetes(ruta_archivos_paquetes):
        if tiempoInicioVentana is None:
            tiempoInicioVentana = paquete.tStart

        if paquete.tStart > tiempoInicioVentana + 1.0:
            # candidatos.extend(analizar_ventana(flujos))
            tiempoInicioVentana = paquete.tStart
            flujos = []

        flujos.append(paquete)

    # if flujos:
    #     candidatos.extend(analizar_ventana(flujos))
    # return


def analizar_ventana(flujos: list[DatosPaquete]) -> list[Candidato]:
    """Analiza los flujos de una ventana de 1 segundo para encontrar posibles escaneos (método de Sangeen et al.)."""
    raise NotImplementedError