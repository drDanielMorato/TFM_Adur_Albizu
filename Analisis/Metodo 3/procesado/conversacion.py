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

    # Sospechosa: Es una conversación sospechosa   
    sospechosa: bool = True

    # Registros de flujo en los que el destino devolvió datos: en un escaneo la mayoría de sondeos se quedan sin respuesta
    registrosConRespuesta: int = 0

    #Método de actualización
    def update(self, puerto_src, puerto_dst, t_inicio, t_fin) -> None:
        self.conexiones.append((t_inicio, t_fin, puerto_src, puerto_dst))
