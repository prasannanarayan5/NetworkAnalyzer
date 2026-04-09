"""
Utility Functions
"""
import psutil
from typing import List, Dict, Any

from models import NetworkInterface


def get_network_interfaces() -> Dict[str, Any]:
    """
    Get all network interfaces.

    Returns:
        Dict with interfaces list and current interface
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, st in stats.items():
        ip = "—"
        if name in addrs:
            for a in addrs[name]:
                if a.family == 2:  # AF_INET
                    ip = a.address
                    break
        
        interfaces.append(
            NetworkInterface(
                name=name,
                ip=ip,
                is_up=st.isup,
                speed=st.speed,
            )
        )

    return {"interfaces": interfaces}


def format_bytes(bytes_val: int) -> str:
    """
    Format bytes to human-readable string.

    Args:
        bytes_val: Number of bytes

    Returns:
        Formatted string (B, KB, MB, GB)
    """
    bytes_val = int(bytes_val) or 0

    if bytes_val < 1024:
        return f"{bytes_val} B"
    if bytes_val < 1048576:
        return f"{bytes_val / 1024:.1f} KB"
    if bytes_val < 1073741824:
        return f"{bytes_val / 1048576:.1f} MB"
    return f"{bytes_val / 1073741824:.2f} GB"


def format_time(seconds: int) -> str:
    """
    Format seconds to MM:SS format.

    Args:
        seconds: Number of seconds

    Returns:
        Formatted time string
    """
    minutes = seconds // 60
    secs = seconds % 60
    return f"{minutes:02d}:{secs:02d}"


def dict_to_list(d: Dict[str, int], key_name: str = "ip", val_name: str = "count") -> List[Dict[str, Any]]:
    """
    Convert dict to list of dicts.

    Args:
        d: Dictionary to convert
        key_name: Name for keys in output
        val_name: Name for values in output

    Returns:
        List of dicts
    """
    return [{key_name: k, val_name: v} for k, v in d.items()]
