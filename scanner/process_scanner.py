# scanner/process_scanner.py
import psutil
from typing import List, Dict

def get_all_processes() -> List[Dict]:
    """
    Return list of all running processes with safe handling for access errors.
    Each item: { 'pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent', 'memory_percent' }
    """
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            # Normalize missing values
            item = {
                'pid': info.get('pid'),
                'name': info.get('name') or '',
                'username': info.get('username') or '',
                'exe': info.get('exe') or '',
                'cmdline': ' '.join(info.get('cmdline') or []),
                'cpu_percent': info.get('cpu_percent') or 0.0,
                'memory_percent': round(info.get('memory_percent') or 0.0, 2)
            }
            procs.append(item)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # skip processes that vanish or are protected
            continue
    return procs
