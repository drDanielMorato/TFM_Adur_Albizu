from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Conversacion:

    # Pareja de Ips de la conversación 
    srcIp: str
    dstIp: str

    # Protocolo de transporte de los registros de flujo de la conversación
    protocolo: str = "TCP"

    # Registros detallados de cada conexión individual, ordenados por t_inicio
    # Cada tupla: (t_inicio, t_fin, puerto_origen, puerto_destino)
    conexiones: list[tuple[float, float, str, str]] = field(default_factory=list)

    #Tiempo final de la última conexión de la conversación
    ultimaActividad: float = 0.0

    #Computaciones finales
    h: float | None = None  # Entropia de Shannon normalizada

    # Registros totales y compatibles con el criterio de sondeo del protocolo
    flujosTotales: int = 0
    flujosSondeo: int = 0

    #Método de actualización
    def update(self, puerto_src, puerto_dst, t_inicio, t_fin) -> None:
        self.conexiones.append((t_inicio, t_fin, puerto_src, puerto_dst))
