import subprocess
import re
import requests
import os
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from collections import defaultdict

# --- Input Handling ---
def get_targets():
    if len(sys.argv) < 2:
        print("Usage: python network_cve_compare_report.py <url1> <url2> ... | <file_with_urls>")
        sys.exit(1)
    arg1 = sys.argv[1]
    if os.path.isfile(arg1):
        with open(arg1, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    return [arg for arg in sys.argv[1:] if arg.startswith('http')]

# --- Nmap Service Detection ---
def resolve_ip(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    try:
        return socket.gethostbyname(hostname)
    except:
        return hostname

def run_nmap(ip):
    nmap_exe = r"C:\\Program Files (x86)\\Nmap\\nmap.exe"
    if not os.path.isfile(nmap_exe):
        return []
    cmd = [nmap_exe, "-sV", "-p", "80,443,8080,1337,22,21,25,3389,8443,53,110,143,3306,5432", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return parse_nmap(result.stdout)
    except Exception:
        pass
    return []

def parse_nmap(nmap_output):
    services = []
    open_ports = []
    for line in nmap_output.split('\n'):
        match = re.search(r'(\d+)/(\w+)\s+open\s+(\S+)(?:\s+([\w\-.]+))?', line)
        if match:
            port, proto, service, version = match.groups()
            services.append({'port': port, 'protocol': proto, 'service': service, 'version': version or ''})
            open_ports.append(int(port))
    return services, open_ports

# --- HTTP Header Software Detection ---
def get_software_version_http(url):
    try:
        resp = requests.get(url, timeout=7, verify=False)
        server = resp.headers.get('Server', '')
        x_powered = resp.headers.get('X-Powered-By', '')
        # Try to extract from Server header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
        if match:
            return match.group(1), match.group(2)
        # Try to extract from X-Powered-By header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', x_powered)
        if match:
            return match.group(1), match.group(2)
        return server, ''
    except Exception:
        return '', ''

# --- CVE Sources (no limit) ---
def search_cves_circl(software, version):
    url = f"https://cve.circl.lu/api/search/{software.lower()}/{software.lower()}"
    try:
        resp = requests.get(url, timeout=7)
        resp.raise_for_status()
        data = resp.json()
        return [(item.get('id','N/A'), item.get('summary','')) for item in data.get('data', [])]
    except: return []
def search_cves_mitre(software, version):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={software}+{version}"
    try:
        resp = requests.get(url, timeout=7)
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for row in soup.select('table tr')[1:]:
            cols = row.find_all('td')
            if len(cols) >= 2:
                cve_id = cols[0].get_text(strip=True)
                desc = cols[1].get_text(strip=True)
                if cve_id.startswith('CVE-'):
                    cves.append((cve_id, desc))
        return cves
    except: return []
def search_cves_exploitdb(software, version):
    url = f"https://www.exploit-db.com/search?cve=1&description={software}+{version}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for row in soup.select('table#exploits-table tbody tr'):
            cols = row.find_all('td')
            if len(cols) >= 7:
                cve_id = cols[6].get_text(strip=True)
                desc = cols[2].get_text(strip=True)
                if cve_id.startswith('CVE-'):
                    cves.append((cve_id, desc))
        return cves
    except: return []
def search_cves_cvedetails(software, version):
    url = f"https://www.cvedetails.com/google-search-results.php?q={software}+{version}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for link in soup.select('a[href^="/cve/"]'):
            cve_id = link.get_text(strip=True)
            desc = link.find_next('td').get_text(strip=True) if link.find_next('td') else ''
            if cve_id.startswith('CVE-'):
                cves.append((cve_id, desc))
        return cves
    except: return []
def search_cves_packetstorm(software, version):
    url = f"https://packetstormsecurity.com/search/?q={software}+{version}&s=files"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for link in soup.select('a[href*="CVE-"]'):
            cve_id = re.search(r'CVE-\d{4}-\d+', link.get_text(strip=True))
            desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
            if cve_id:
                cves.append((cve_id.group(), desc))
        return cves
    except: return []
def search_cves_vulners(software, version):
    url = 'https://vulners.com/api/v3/search/lucene/'
    query = f"{software} {version}".strip()
    try:
        resp = requests.post(url, json={"query": query, "size": 1000}, timeout=7)
        data = resp.json()
        cves = []
        for item in data.get('data', {}).get('search', []):
            cve_id = item.get('id', 'N/A')
            desc = item.get('description', '')
            if cve_id.startswith('CVE-'):
                cves.append((cve_id, desc))
        return cves
    except: return []
def search_cves_securityfocus(software, version):
    url = f"https://www.securityfocus.com/vulnerabilities?query={software}+{version}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for link in soup.find_all('a', href=True):
            if 'cve' in link['href']:
                cve_id = link.get_text(strip=True)
                desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
                if cve_id.startswith('CVE-'):
                    cves.append((cve_id, desc))
        return cves
    except: return []
def search_cves_rapid7(software, version):
    url = f"https://www.rapid7.com/db/?q={software}+{version}&type=nexpose"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        cves = []
        for link in soup.find_all('a', href=True):
            if '/vulnerabilities/' in link['href']:
                cve_id = link.get_text(strip=True)
                desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
                if cve_id.startswith('CVE-'):
                    cves.append((cve_id, desc))
        return cves
    except: return []

cve_sources = [
    (search_cves_circl, "CIRCL"),
    (search_cves_mitre, "MITRE"),
    (search_cves_exploitdb, "Exploit-DB"),
    (search_cves_cvedetails, "CVE Details"),
    (search_cves_packetstorm, "Packet Storm"),
    (search_cves_vulners, "Vulners"),
    (search_cves_securityfocus, "SecurityFocus"),
    (search_cves_rapid7, "Rapid7")
]

def compare_cve_sets(cve_dict):
    all_sets = {src: set(cve for cve, _ in cves) for src, cves in cve_dict.items()}
    if not all_sets:
        return set(), {src: set() for src in cve_dict}
    common = set.intersection(*(s for s in all_sets.values() if s)) if all_sets else set()
    unique = {src: s - set.union(*(all_sets[o] for o in all_sets if o != src)) for src, s in all_sets.items()}
    return common, unique

def main():
    targets = get_targets()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"network_cve_compare_report_{timestamp}.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        for url in targets:
            print(f"\n===== {url} =====")
            f.write(f"===== {url} =====\n")
            ip = resolve_ip(url)
            f.write(f"IP: {ip}\n")
            print(f"IP: {ip}")
            services, open_ports = run_nmap(ip)
            f.write(f"Open Ports: {open_ports}\n")
            print(f"Open Ports: {open_ports}")
            f.write(f"Services:\n")
            for svc in services:
                f.write(f"  Port {svc['port']}/{svc['protocol']}: {svc['service']} {svc['version']}\n")
            print(f"Services: {services}")
            # Try HTTP header detection as well
            sw_http, ver_http = get_software_version_http(url)
            if sw_http:
                f.write(f"HTTP Software: {sw_http} {ver_http}\n")
                print(f"HTTP Software: {sw_http} {ver_http}")
            # Use all detected software/version pairs for CVE lookup
            sw_versions = set()
            for svc in services:
                if svc['service']:
                    sw_versions.add((svc['service'], svc['version']))
            if sw_http:
                sw_versions.add((sw_http, ver_http))
            for software, version in sw_versions:
                if not software:
                    continue
                f.write(f"\n--- CVE Comparison for {software} {version} ---\n")
                print(f"\n--- CVE Comparison for {software} {version} ---")
                cve_dict = {}
                for src_func, src_name in cve_sources:
                    cves = src_func(software, version)
                    cve_dict[src_name] = cves
                    print(f"{src_name}: {len(cves)} CVEs")
                common, unique = compare_cve_sets(cve_dict)
                f.write(f"{'Source':<16} | {'# CVEs':<6} | {'Unique CVEs':<10}\n")
                f.write('-'*40+'\n')
                for src in cve_dict:
                    f.write(f"{src:<16} | {len(cve_dict[src]):<6} | {len(unique[src]):<10}\n")
                f.write(f"Common CVEs across all sources ({len(common)}):\n")
                for cve in sorted(common):
                    f.write(f"  {cve}\n")
                for src in cve_dict:
                    f.write(f"\n[{src}]\n")
                    for cve_id, desc in cve_dict[src]:
                        f.write(f"  {cve_id}: {desc[:80]}\n")
                f.write("\n" + "-"*60 + "\n\n")
    print(f"\n[✓] Network & CVE comparative report written to {report_file}")

if __name__ == "__main__":
    main() 