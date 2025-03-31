import subprocess
import socket
import re
import sys
from typing import List, Tuple

def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(1)

def run_traceroute(target: str) -> List[str]:
    try:
        result = subprocess.run(
            ["tracert", "-d", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            text=True
        )
        if result.returncode != 0:
            sys.exit(1)
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        sys.exit(1)

def extract_ips(traceroute_output: List[str]) -> List[str]:
    ip_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    hops = []
    for line in traceroute_output:
        if '***' in line:
            break
        match = ip_regex.findall(line)
        if match:
            hops.append(match[-1])
    return hops

def whois_lookup(ip: str) -> Tuple[str, str, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("whois.radb.net", 43))
        sock.sendall((ip + "\r\n").encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        text = response.decode(errors="ignore")
        asn = re.search(r'origin:\s*(AS\d+)', text)
        org = re.search(r'org-name:\s*(.+)', text)
        country = re.search(r'country:\s*(\w+)', text)

        return (
            asn.group(1) if asn else "N/A",
            country.group(1) if country else "N/A",
            org.group(1).strip() if org else "N/A"
        )
    except socket.timeout:
        return ("Timeout", "-", "-")
    except Exception:
        return ("Error", "-", "-")

def print_table(hops: List[str], whois_data: List[Tuple[str, str, str]]):
    print("\n№ | IP Address        | AS        | Country | Provider")
    print("--+------------------+-----------+---------+--------------------------")
    for i, (ip, (asn, country, provider)) in enumerate(zip(hops, whois_data), 1):
        print(f"{i:<2}| {ip:<16} | {asn:<9} | {country:<7} | {provider}")

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("--help", "-h"):
        print("Usage: python trace_as.py <domain_or_ip>")
        return

    target = sys.argv[1]
    resolved_ip = resolve_host(target)
    trace_result = run_traceroute(resolved_ip)
    hops = extract_ips(trace_result)

    whois_info = [whois_lookup(ip) for ip in hops]

    print_table(hops, whois_info)

if __name__ == '__main__':
    main()
