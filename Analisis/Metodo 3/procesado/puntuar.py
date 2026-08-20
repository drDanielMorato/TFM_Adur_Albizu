from __future__ import annotations
from config import *
from .conversacion import Conversacion
import math
from collections import Counter

def calcular_h(conv: Conversacion) -> None:
    """
    h:
    Entropía de Shannon de los puertos, normalizada por log2(n_puertos_unicos).
    H = 0: todos los paquetes van al mismo puerto (concentrado)
    H = 1: puertos perfectamente uniformes (disperso)
    """
    puertos = [c[3] for c in conv.conexiones]
    if not puertos:
        conv.h = 0.0
        return

    conteo = Counter(puertos)
    n, n_uniq = len(puertos), len(conteo)

    if n_uniq <= 1:
        conv.h = 0.0
    else:
        H = -sum((c/n) * math.log2(c/n) for c in conteo.values())
        conv.h = H / math.log2(n_uniq)
