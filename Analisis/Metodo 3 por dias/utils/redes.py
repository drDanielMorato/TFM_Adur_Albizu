from __future__ import annotations
from config import REDES_INTERNAS
import ipaddress

# Para agilizar:
_cache_ips = {}

def esIpInterna(src_ip: str) -> bool:
    if src_ip in _cache_ips:
        return _cache_ips[src_ip]

    addr = ipaddress.ip_address(src_ip)
    resultado = any(addr in red for red in REDES_INTERNAS)
    _cache_ips[src_ip] = resultado
    return resultado
