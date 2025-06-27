import requests
import re
import os
import socket
import sys
from urllib.parse import urlparse

# -------------------------
# CONFIGURATION
# -------------------------
SCAN_OUTPUT_FILE = "nmap_scan.txt"
WHATWEB_OUTPUT_FILE = "whatweb_output.txt"
CVE_OUTPUT_FILE = "cve_results.txt"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# -------------------------
# STEP 1: Run dummy scan (simulate output)
# In real use: replace this part with actual Nmap + WhatWeb tool outputs
# -------------------------
dummy_scan_data = """
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
443/tcp  open  https   nginx 1.18.0
"""

with open(SCAN_OUTPUT_FILE, "w") as f:
    f.write(dummy_scan_data)

# -------------------------
# STEP 2: Parse scan data
# -------------------------
def parse_software_versions(file_path):
    with open(file_path, "r") as f:
        content = f.read()
    
    findings = []
    pattern = re.compile(r"(\d+/tcp)\s+open\s+(\S+)\s+([^\d]*)([\d\.]+)")
    matches = pattern.findall(content)
    for port, service, software_name, version in matches:
        findings.append({
            "port": port,
            "service": service,
            "software": software_name.strip(),
            "version": version.strip()
        })
    return findings

# -------------------------
# STEP 3: Search CVEs using CIRCL CVE Search API
# -------------------------
def search_cves(software, version):
    # CIRCL API expects vendor/product, so try to use software as both
    vendor = software.lower()
    product = software.lower()
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        cve_list = []
        for item in data.get('data', [])[:5]:
            cve_id = item.get('id', 'N/A')
            desc = item.get('summary', 'No description')
            cve_list.append((cve_id, desc))
        return cve_list
    except Exception as e:
        return [("ERROR", str(e))]

# -------------------------
# STEP 4: Write results to output file
# -------------------------
def write_cve_report(findings, output_file):
    with open(output_file, "w") as f:
        for entry in findings:
            software = entry["software"]
            version = entry["version"]
            port = entry["port"]
            service = entry["service"]
            
            f.write(f"\n=== {software} {version} on {port} ({service}) ===\n")
            cves = search_cves(software, version)
            if not cves:
                f.write("No CVEs found.\n")
            else:
                for cve_id, desc in cves:
                    f.write(f"{cve_id}: {desc}\n")

# -------------------------
# NEW: Input Handling
# -------------------------
def get_urls(input_value):
    if os.path.isfile(input_value):
        with open(input_value, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [input_value.strip()]
    return urls

# -------------------------
# NEW: Resolve IP Address
# -------------------------
def resolve_ip(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"ERROR: {e}"

# -------------------------
# NEW: Basic Port Scanner
# -------------------------
def scan_ports(ip, ports=None, timeout=1):
    if ports is None:
        ports = [80, 443, 21, 22, 25, 3389, 8080, 8443, 53, 110, 143, 3306, 5432]
    open_ports = []
    filtered_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            else:
                filtered_ports.append(port)
        except Exception:
            filtered_ports.append(port)
        finally:
            s.close()
    return open_ports, filtered_ports

# -------------------------
# NEW: Get Software & Version from HTTP Headers
# -------------------------
def get_software_version(url):
    try:
        resp = requests.get(url if url.startswith('http') else 'http://' + url, timeout=3)
        server = resp.headers.get('Server', '')
        x_powered = resp.headers.get('X-Powered-By', '')
        # Try to extract version from server header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
        if match:
            return [(match.group(1), match.group(2))]
        elif server:
            return [(server, '')]
        elif x_powered:
            match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', x_powered)
            if match:
                return [(match.group(1), match.group(2))]
            else:
                return [(x_powered, '')]
        else:
            return []
    except Exception:
        return []

# -------------------------
# NEW: Basic Firewall Detection
# -------------------------
def detect_firewall(filtered_ports, total_ports):
    if len(filtered_ports) > len(total_ports) // 2:
        return "Possible firewall detected (many filtered/closed ports)"
    return "No obvious firewall detected"

# -------------------------
# MODIFIED: Main Execution
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <url or url_list.txt>")
        sys.exit(1)
    input_value = sys.argv[1]
    urls = get_urls(input_value)
    report_lines = []
    for url in urls:
        report_lines.append(f"\n===== Report for {url} =====")
        ip = resolve_ip(url)
        report_lines.append(f"IP Address: {ip}")
        if isinstance(ip, str) and ip.startswith('ERROR'):
            continue
        open_ports, filtered_ports = scan_ports(ip)
        report_lines.append(f"Open Ports: {open_ports}")
        report_lines.append(f"Filtered/Closed Ports: {filtered_ports}")
        firewall_status = detect_firewall(filtered_ports, open_ports + filtered_ports)
        report_lines.append(f"Firewall Status: {firewall_status}")
        sw_versions = get_software_version(url)
        if not sw_versions:
            report_lines.append("Software/Version: Not detected from headers.")
        for sw, ver in sw_versions:
            report_lines.append(f"Software: {sw} Version: {ver}")
            cves = search_cves(sw, ver)
            if not cves:
                report_lines.append("No CVEs found.")
            else:
                for cve_id, desc in cves[:5]:
                    report_lines.append(f"{cve_id}: {desc}")
    with open("detailed_report.txt", "w", encoding="utf-8") as f:
        for line in report_lines:
            f.write(line + "\n")
    print("[✓] Detailed report written to detailed_report.txt")

if __name__ == "__main__":
    main()
