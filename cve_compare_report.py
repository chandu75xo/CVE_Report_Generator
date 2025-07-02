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
import time

# --- Input Handling ---
def get_targets():
    if len(sys.argv) < 2:
        print("Usage: python cve_compare_report.py <url1> <url2> ... | <file_with_urls>")
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
    for line in nmap_output.split('\n'):
        match = re.search(r'(\d+)/(\w+)\s+open\s+(\S+)(?:\s+([\w\-.]+))?', line)
        if match:
            port, proto, service, version = match.groups()
            services.append((service, version or ''))
    return services

# --- HTTP/HTML Software Detection ---
def extract_software_versions(url):
    found = set()
    try:
        resp = requests.get(url, timeout=7, verify=False)
        # HTTP headers
        for header in ['Server', 'X-Powered-By']:
            val = resp.headers.get(header, '')
            m = re.search(r'([\w\-]+)[/ ]([\d\.]+)', val)
            if m:
                found.add((m.group(1), m.group(2)))
            elif val:
                found.add((val, ''))
        # HTML meta generator
        soup = BeautifulSoup(resp.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and meta.get('content'):
            m = re.search(r'([\w\-]+)[/ ]([\d\.]+)', meta['content'])
            if m:
                found.add((m.group(1), m.group(2)))
        # HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.Comment)))
        for comment in comments:
            m = re.search(r'([\w\-]+)[/ ]([\d\.]+)', comment)
            if m:
                found.add((m.group(1), m.group(2)))
    except Exception:
        pass
    return found

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
    non_empty_sets = [s for s in all_sets.values() if s]
    if non_empty_sets:
        common = set.intersection(*non_empty_sets)
    else:
        common = set()
    unique = {src: s - set.union(*(all_sets[o] for o in all_sets if o != src)) for src, s in all_sets.items()}
    return common, unique

def main():
    targets = get_targets()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"cve_compare_report_{timestamp}.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        for url in targets:
            print(f"\n===== {url} =====")
            f.write(f"===== {url} =====\n")
            ip = resolve_ip(url)
            f.write(f"IP: {ip}\n")
            print(f"IP: {ip}")
            services = run_nmap(ip)
            f.write(f"Services: {services}\n")
            print(f"Services: {services}")
            # Enhanced: collect all software/version pairs
            sw_versions = set(services)
            sw_versions.update(extract_software_versions(url))
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
                f.write("\n" + "="*60 + "\n\n")
    print(f"\n[✓] Comparative CVE report written to {report_file}")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f'Total runtime: {time.time() - start_time:.2f} seconds', flush=True) 