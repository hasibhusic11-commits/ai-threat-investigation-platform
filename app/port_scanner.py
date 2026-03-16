import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.config import PORTSCAN_MAX_PORTS, PORTSCAN_TIMEOUT

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433,
    1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 8000, 8080, 8443, 9200, 27017,
]


def _is_allowed_target(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _scan_one(ip: str, port: int) -> dict[str, Any]:
    result = {"port": port, "open": False, "banner": ""}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(PORTSCAN_TIMEOUT)

    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            result["open"] = True
            try:
                sock.sendall(b"\r\n")
                banner = sock.recv(128)
                if banner:
                    result["banner"] = banner.decode(errors="ignore").strip()
            except Exception:
                pass
    finally:
        sock.close()

    return result


def run_port_scan(ip: str, ports: list[int] | None = None) -> dict[str, Any]:
    if not _is_allowed_target(ip):
        raise ValueError("Target must be a private, loopback, or link-local IP address.")

    if not ports:
        ports = COMMON_PORTS[:]

    cleaned_ports = []
    for p in ports:
        if isinstance(p, int) and 1 <= p <= 65535:
            cleaned_ports.append(p)

    cleaned_ports = sorted(set(cleaned_ports))[:PORTSCAN_MAX_PORTS]

    if not cleaned_ports:
        raise ValueError("No valid ports supplied.")

    results = []
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(_scan_one, ip, port) for port in cleaned_ports]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["open"]]

    return {
        "target": ip,
        "scanned_ports": cleaned_ports,
        "open_ports": open_ports,
        "results": results,
    }

