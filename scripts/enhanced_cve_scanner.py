import requests
import socket
import sys
import os
import csv
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time

COMMON_PORTS = [80, 443, 21, 22, 25, 3389, 8080, 8443, 53, 110, 143, 3306, 5432]


def get_urls(input_value):
    if os.path.isfile(input_value):
        with open(input_value, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return [input_value.strip()]


def resolve_ip(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        return socket.gethostbyname(parsed.hostname)
    except Exception:
        return ''


def scan_ports(ip, ports=COMMON_PORTS):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


def get_software_version(url):
    try:
        resp = requests.get(url if url.startswith('http') else 'http://' + url, timeout=5)
        server = resp.headers.get('Server', '')
        x_powered = resp.headers.get('X-Powered-By', '')
        # Try to extract from Server header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
        if match:
            return match.group(1), match.group(2), server, x_powered
        # Try to extract from X-Powered-By header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', x_powered)
        if match:
            return match.group(1), match.group(2), server, x_powered
        # Try meta generator
        soup = BeautifulSoup(resp.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and meta.get('content'):
            meta_match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', meta['content'])
            if meta_match:
                return meta_match.group(1), meta_match.group(2), server, x_powered
        return server, '', server, x_powered
    except Exception:
        return '', '', '', ''


def search_cves_mitre(software, version):
    if not software:
        return []
    keyword = f"{software} {version}".strip()
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword.replace(' ', '+')}"
    try:
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for row in soup.select('table tr')[1:]:
            cols = row.find_all('td')
            if len(cols) >= 2:
                cve_id = cols[0].get_text(strip=True)
                desc = cols[1].get_text(strip=True)
                if cve_id.startswith('CVE-'):
                    cve_list.append((cve_id, desc))
        return cve_list
    except Exception:
        return []


def process_url(url):
    ip = resolve_ip(url)
    open_ports = scan_ports(ip) if ip else []
    software, version, server, x_powered = get_software_version(url)
    cves = search_cves_mitre(software, version)
    tech_stack = '; '.join(filter(None, [server, x_powered]))
    return {
        'url': url,
        'ip': ip,
        'open_ports': ','.join(map(str, open_ports)),
        'software': software,
        'version': version,
        'tech_stack': tech_stack,
        'cves': cves
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python enhanced_cve_scanner.py <url or url_list.txt>")
        sys.exit(1)
    urls = get_urls(sys.argv[1])
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(process_url, urls))
    with open('enhanced_report.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'IP', 'Open Ports', 'Tech Stack', 'Software', 'Version', 'CVE ID', 'CVE Description'])
        for r in results:
            if r['cves']:
                for cve_id, desc in r['cves']:
                    writer.writerow([r['url'], r['ip'], r['open_ports'], r['tech_stack'], r['software'], r['version'], cve_id, desc])
            else:
                writer.writerow([r['url'], r['ip'], r['open_ports'], r['tech_stack'], r['software'], r['version'], '', ''])
    print('Report saved to enhanced_report.csv')

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f'Total runtime: {time.time() - start_time:.2f} seconds', flush=True) 