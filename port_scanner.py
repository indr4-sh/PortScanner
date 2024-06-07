#!/usr/bin/env python3

import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

open_sockets = []

def sig_handler(sig, frame):
    print("\nSaliendo del programa...")
    for s in open_sockets:
        s.close()
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Scanner')
    parser.add_argument("-t", "--target", required=True, help="Victim target to scan (Eg: -t 192.168.10.1)")
    parser.add_argument("-p", "--port", required=True, help="Port range to scan (Eg: -p 1-65535)")
    options = parser.parse_args()
    return options.target, options.port

def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    open_sockets.append(s)
    return s

def port_scanner(port, host):
    s = create_socket()
    try:
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = s.recv(1024)
        response = response.decode(errors='ignore').split('\n')

        if response:
            print(f"\nEl puerto {port} está abierto\n")
            for line in response:
                print(line)
        else:
            print(f"\nEl puerto {port} está abierto")
    except (socket.timeout, ConnectionRefusedError):
        pass
    finally:
        s.close()

def scan_ports(ports, target):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(port, target), ports)

def parse_ports(port_str):
    if '-' in port_str:
        start, end = map(int, port_str.split("-"))
        return range(start, end+1)
    elif ',' in port_str:
        return map(int, port_str.split(","))
    else:
        return [int(port_str)]

def main():
    target, port_str = get_arguments()
    ports = parse_ports(port_str)
    scan_ports(ports, target)

if __name__ == '__main__':
    main()
