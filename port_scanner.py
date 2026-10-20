#!/usr/bin/env python3
"""
Multi-threaded TCP Port Scanner
--------------------------------
Scans a target host across a range of ports using concurrent threads,
resolves the hostname, and reports open ports with common service names.
 
Usage:
    python3 port_scanner.py <target> [--start 1] [--end 1024] [--threads 100] [--timeout 1.0]
 
Examples:
    python3 port_scanner.py 192.168.64.5
    python3 port_scanner.py 192.168.64.5 --start 1 --end 65535 --threads 200
"""
 
import argparse
import socket
import threading
import queue
import time
from datetime import datetime
 
# A small lookup of common ports -> service names for nicer output.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
    8000: "Splunk Web", 8089: "Splunk Mgmt",
}
 
print_lock = threading.Lock()
 
 
def resolve_target(target):
    """Resolve a hostname to an IP address; pass through if already an IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        raise SystemExit(1)
 
 
def scan_port(ip, port, timeout, open_ports):
    """Attempt a TCP connection to a single port; record it if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            with print_lock:
                print(f"[+] Port {port:<6} open   ({service})")
            open_ports.append(port)
    except socket.error:
        pass
    finally:
        sock.close()
 
 
def worker(ip, timeout, open_ports, port_queue):
    """Pull ports off the shared queue and scan them until it's empty."""
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, open_ports)
        port_queue.task_done()
 
 
def run_scan(target, start_port, end_port, num_threads, timeout):
    ip = resolve_target(target)
    print(f"\nScanning target: {target} ({ip})")
    print(f"Port range:      {start_port}-{end_port}")
    print(f"Threads:         {num_threads}")
    print(f"Started at:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
 
    port_queue = queue.Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
 
    open_ports = []
    threads = []
    start_time = time.time()
 
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(ip, timeout, open_ports, port_queue))
        t.daemon = True
        t.start()
        threads.append(t)
 
    port_queue.join()
    for t in threads:
        t.join(timeout=0.1)
 
    elapsed = time.time() - start_time
    print(f"\nScan complete in {elapsed:.2f} seconds.")
    print(f"Open ports found: {sorted(open_ports) if open_ports else 'None'}")
 
 
def parse_args():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP port scanner.")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--start", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="Ending port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    return parser.parse_args()
 
 
if __name__ == "__main__":
    args = parse_args()
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("[!] Invalid port range. Must be between 1 and 65535, start <= end.")
        raise SystemExit(1)
    run_scan(args.target, args.start, args.end, args.threads, args.timeout)
 