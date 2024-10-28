# A fast and customizable Python port scanner designed to identify open TCP and UDP ports and retrieve basic version information from services when available. 
# This tool is intended for ethical hackers and security professionals who need a quick overview of active services on a target machine.
#
# @author h3st4k3r
#

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
import sys

TIMEOUT = 1 
MAX_PORT = 65535
open_ports = [] 
def print_logo():
    logo = r"""
    __  ____________ ____________   ____             __     _____                     ______            __
   / / / /__  / ___// ____/ ____/  / __ \____  _____/ /_   / ___/_________ _____     /_  __/___  ____  / /
  / /_/ / /_ <\__ \/ __/ / /      / /_/ / __ \/ ___/ __/   \__ \/ ___/ __ `/ __ \     / / / __ \/ __ \/ / 
 / __  /___/ /__/ / /___/ /___   / ____/ /_/ / /  / /_    ___/ / /__/ /_/ / / / /    / / / /_/ / /_/ / /  
/_/ /_//____/____/_____/\____/  /_/    \____/_/   \__/   /____/\___/\__,_/_/ /_/    /_/  \____/\____/_/   
                                                                                                          
    h3st4k3r-port-scan: Fast and customizable port scanner
    """
    print(logo)

def get_service_version_tcp(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            sock.sendallsock.sendall(b'Hello h3st4k3r\r\n')
            banner = sock.recv(1024).decode().strip()
            open_ports.append((port, "TCP")) 
            return f"TCP {port} open - Version: {banner}"
    except Exception:
        return None

def get_service_version_udp(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendto(b'Hello from h3st4k3r-port-scan', (ip, port))
            data, _ = sock.recvfrom(1024)
            open_ports.append((port, "UDP"))
            return f"UDP {port} open - Response: {data.decode().strip()}"
    except Exception:
        return None

def scan_port_tcp(ip, port):
    version_info = get_service_version_tcp(ip, port)
    if version_info:
        print(version_info)

def scan_port_udp(ip, port):
    version_info = get_service_version_udp(ip, port)
    if version_info:
        print(version_info)

def display_summary():
    if open_ports:
        print("\nSummary of Open Ports:")
        table = PrettyTable()
        table.field_names = ["Port", "Protocol"]
        for port, protocol in open_ports:
            table.add_row([port, protocol])
        print(table)
    else:
        print("\nNo open ports found.")

def main():
    print_logo()

    parser = argparse.ArgumentParser(description="TCP/UDP port scanner that retrieves service versions.")
    parser.add_argument("ip", nargs="?", help="IP address of the target machine to scan")
    args = parser.parse_args()

    if not args.ip:
        print("Usage: python port-scan.py <IP>")
        print("Options:")
        print("  <IP>       IP address of the target machine to scan")
        print("  --help     Show this help message and exit")
        sys.exit(1)

    ip = args.ip
    print(f"Scanning TCP and UDP ports on IP: {ip}")

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: scan_port_tcp(ip, port), range(1, MAX_PORT + 1))
        executor.map(lambda port: scan_port_udp(ip, port), range(1, MAX_PORT + 1))
    display_summary()

if __name__ == "__main__":
    main()
