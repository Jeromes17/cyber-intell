# scanner/network_scanner.py
import psutil
from typing import List, Dict

def _format_addr(addr):
    if not addr:
        return "N/A"
    # psutil returns a namedtuple with ip and port
    try:
        return f"{addr.ip}:{addr.port}"
    except Exception:
        # fallback if structure differs
        return str(addr)

def get_all_connections() -> List[Dict]:
    """
    Return list of all active network connections.
    Each item: { 'pid', 'local_address', 'remote_address', 'status', 'type' }
    """
    conns = []
    try:
        for conn in psutil.net_connections(kind='all'):
            try:
                conns.append({
                    'pid': conn.pid,
                    'local_address': _format_addr(conn.laddr),
                    'remote_address': _format_addr(conn.raddr),
                    'status': conn.status,
                    'family': str(conn.family).split('.')[-1],   # AF_INET, AF_INET6, etc.
                    'type': str(conn.type).split('.')[-1]        # SOCK_STREAM, SOCK_DGRAM
                })
            except Exception:
                continue
    except Exception:
        # on some systems psutil.net_connections may require admin; return empty list on failure
        return []
    return conns
