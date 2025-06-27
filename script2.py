import requests
import re
import os
import socket
import sys
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# -------------------------
# Input Handling
# -------------------------
def get_urls(input_value):
    if os.path.isfile(input_value):
        with open(input_value, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [input_value.strip()]
    return urls

# -------------------------
# Resolve IP Address
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
# Basic Port Scanner
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
# Improved Software & Version Detection
# -------------------------
def get_software_version(url):
    try:
        resp = requests.get(url if url.startswith('http') else 'http://' + url, timeout=5)
        server = resp.headers.get('Server', '')
        x_powered = resp.headers.get('X-Powered-By', '')
        via = resp.headers.get('Via', '')
        # Try to extract from Server header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
        if match:
            return match.group(1), match.group(2), resp.headers
        # Try to extract from X-Powered-By header
            match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', x_powered)
            if match:
                return match.group(1), match.group(2), resp.headers
        # Try to extract from Via header
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', via)
        if match:
            return match.group(1), match.group(2), resp.headers
        # Try to extract from HTML meta tags or comments
        soup = BeautifulSoup(resp.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and meta.get('content'):
            meta_match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', meta['content'])
            if meta_match:
                return meta_match.group(1), meta_match.group(2), resp.headers
        # Try to extract from HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.Comment)))
        for comment in comments:
            comment_match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', comment)
            if comment_match:
                return comment_match.group(1), comment_match.group(2), resp.headers
        # Try to extract from title or body text (very weak, fallback)
        title = soup.title.string if soup.title else ''
        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', title)
        if match:
            return match.group(1), match.group(2), resp.headers
        # Fallback: just return server or x_powered if present
        if server:
            return server, '', resp.headers
        if x_powered:
            return x_powered, '', resp.headers
        # Prompt user for manual input if running interactively
        if sys.stdin.isatty():
            print(f"[!] Could not detect software/version for {url}.")
            sw = input("Enter software name (or leave blank): ").strip()
            ver = input("Enter version (or leave blank): ").strip()
            return sw, ver, resp.headers
        return '', '', resp.headers
    except Exception:
        return '', '', {}

# -------------------------
# Basic Firewall Detection
# -------------------------
def detect_firewall(filtered_ports, total_ports):
    if len(filtered_ports) > len(total_ports) // 2:
        return "Possible firewall detected (many filtered/closed ports)"
    return "No obvious firewall detected"

# -------------------------
# CIRCL CVE Search API
# -------------------------
def search_cves_circl(software, version):
    vendor = software.lower()
    product = software.lower()
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    try:
        resp = requests.get(url, timeout=7)
        resp.raise_for_status()
        data = resp.json()
        cve_list = []
        for item in data.get('data', [])[:5]:
            cve_id = item.get('id', 'N/A')
            desc = item.get('summary', 'No description')
            cve_list.append((cve_id, desc))
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# MITRE CVE Search (HTML Scraping)
# -------------------------
def search_cves_mitre(software, version):
    keyword = f"{software} {version}".strip()
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword.replace(' ', '+')}"
    try:
        resp = requests.get(url, timeout=7)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for row in soup.select('table tr')[1:]:
            cols = row.find_all('td')
            if len(cols) >= 2:
                cve_id = cols[0].get_text(strip=True)
                desc = cols[1].get_text(strip=True)
                cve_list.append((cve_id, desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# Exploit-DB CVE Search (HTML Scraping)
# -------------------------
def search_cves_exploitdb(software, version):
    keyword = f"{software} {version}".strip()
    url = f"https://www.exploit-db.com/search?cve=1&description={keyword.replace(' ', '+')}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for row in soup.select('table#exploits-table tbody tr'):
            cols = row.find_all('td')
            if len(cols) >= 7:
                cve_id = cols[6].get_text(strip=True)
                desc = cols[2].get_text(strip=True)
                if cve_id and cve_id.startswith('CVE-'):
                    cve_list.append((cve_id, desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# CVE Details (HTML Scraping)
# -------------------------
def search_cves_cvedetails(software, version):
    keyword = f"{software} {version}".strip().replace(' ', '+')
    url = f"https://www.cvedetails.com/google-search-results.php?q={keyword}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for link in soup.select('a[href^="/cve/"]'):
            cve_id = link.get_text(strip=True)
            desc = link.find_next('td').get_text(strip=True) if link.find_next('td') else ''
            if cve_id.startswith('CVE-'):
                cve_list.append((cve_id, desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# Packet Storm (HTML Scraping)
# -------------------------
def search_cves_packetstorm(software, version):
    keyword = f"{software} {version}".strip().replace(' ', '+')
    url = f"https://packetstormsecurity.com/search/?q={keyword}&s=files"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for link in soup.select('a[href*="CVE-"]'):
            cve_id = re.search(r'CVE-\d{4}-\d+', link.get_text(strip=True))
            desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
            if cve_id:
                cve_list.append((cve_id.group(), desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# Vulners CVE Search (API)
# -------------------------
def search_cves_vulners(software, version):
    url = 'https://vulners.com/api/v3/search/lucene/'
    query = f"{software} {version}".strip()
    try:
        resp = requests.post(url, json={"query": query, "size": 5}, timeout=7)
        resp.raise_for_status()
        data = resp.json()
        cve_list = []
        for item in data.get('data', {}).get('search', []):
            cve_id = item.get('id', 'N/A')
            desc = item.get('description', 'No description')
            if cve_id.startswith('CVE-'):
                cve_list.append((cve_id, desc))
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# SecurityFocus CVE Search (HTML Scraping)
# -------------------------
def search_cves_securityfocus(software, version):
    keyword = f"{software} {version}".strip().replace(' ', '+')
    url = f"https://www.securityfocus.com/vulnerabilities?query={keyword}"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for link in soup.find_all('a', href=True):
            if 'cve' in link['href']:
                cve_id = link.get_text(strip=True)
                desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
                if cve_id.startswith('CVE-'):
                    cve_list.append((cve_id, desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# Rapid7 CVE Search (HTML Scraping)
# -------------------------
def search_cves_rapid7(software, version):
    keyword = f"{software} {version}".strip().replace(' ', '+')
    url = f"https://www.rapid7.com/db/?q={keyword}&type=nexpose"
    try:
        resp = requests.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        cve_list = []
        for link in soup.find_all('a', href=True):
            if '/vulnerabilities/' in link['href']:
                cve_id = link.get_text(strip=True)
                desc = link.find_parent('tr').get_text(strip=True) if link.find_parent('tr') else ''
                if cve_id.startswith('CVE-'):
                    cve_list.append((cve_id, desc))
            if len(cve_list) >= 5:
                break
        return cve_list, True
    except Exception as e:
        return [], False

# -------------------------
# Merge and Deduplicate CVEs
# -------------------------
def merge_cve_lists(*lists):
    seen = set()
    merged = []
    for cve_list in lists:
        for cve_id, desc in cve_list:
            if cve_id not in seen:
                seen.add(cve_id)
                merged.append((cve_id, desc))
    return merged

# -------------------------
# Per-URL Processing Function
# -------------------------
def process_url(url, url_idx):
    result = {
        'url': url,
        'ip': None,
        'open_ports': [],
        'filtered_ports': [],
        'firewall_status': None,
        'software': None,
        'version': None,
        'software_detected': False,
        'cve_results': {},
        'http_headers': {},
    }
    ip = resolve_ip(url)
    result['ip'] = ip
    if isinstance(ip, str) and ip.startswith('ERROR'):
        print(f"{url} - IP resolution failed: {ip}")
        return result, []
    open_ports, filtered_ports = scan_ports(ip)
    result['open_ports'] = open_ports
    result['filtered_ports'] = filtered_ports
    result['firewall_status'] = detect_firewall(filtered_ports, open_ports + filtered_ports)
    software, version, headers = get_software_version(url)
    if not software:
        print(f"{url} - Software/Version: Not detected")
        result['software_detected'] = False
    else:
        result['software'] = software
        result['version'] = version
        result['software_detected'] = True
    result['http_headers'] = dict(headers) if headers else {}
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
    all_cves = []
    source_status = []
    for src, src_name in cve_sources:
        cves, ok = src(software, version) if software else ([], False)
        result['cve_results'][src_name] = cves
        if ok:
            print(f"{url} - [{src_name}] - Success - {len(cves)} CVEs")
        else:
            print(f"{url} - [{src_name}] - Fail - 0 CVEs")
        source_status.append({'source': src_name, 'success': ok, 'count': len(cves)})
        all_cves.append(cves)
    result['all_cves'] = merge_cve_lists(*all_cves)
    if not software:
        result['all_cves'] = []
    return result, source_status

# -------------------------
# Main Execution
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python script2.py <url or url_list.txt>")
        sys.exit(1)
    input_value = sys.argv[1]
    urls = get_urls(input_value)
    results = []
    all_status = []
    if len(urls) == 1:
        url = urls[0]
        result, status = process_url(url, 1)
        results.append(result)
        all_status.append(status)
        print("\nSummary Table:")
        print(f"{'Source':<18} | {'Success':<7} | {'# CVEs':<6}")
        print('-'*36)
        for s in status:
            print(f"{s['source']:<18} | {str(s['success']):<7} | {s['count']:<6}")
    else:
            with ThreadPoolExecutor() as executor:
                future_to_url = {executor.submit(process_url, url, idx+1): url for idx, url in enumerate(urls)}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result, _ = future.result()
                    results.append(result)
                except Exception as exc:
                    print(f"{url} - ERROR: {exc}")
    # Write simplified plain text output
    with open("multi_source_cve_report.txt", "w", encoding="utf-8") as f:
        for result in results:
            f.write(f"===== URL: {result['url']} =====\n")
            f.write(f"IP: {result['ip']}\n")
            f.write(f"Open Ports: {result['open_ports']}\n")
            f.write(f"Software: {result['software']}\n")
            f.write(f"Version: {result['version']}\n")
            f.write(f"\n--- Top 10 Unique CVEs ---\n")
            if result['all_cves']:
                for cve_id, desc in result['all_cves'][:10]:
                    f.write(f"{cve_id}: {desc}\n")
            else:
                f.write("No unique CVEs found.\n")
            f.write("\n\n")
    print("[✓] Multi-source CVE report written to multi_source_cve_report.txt")

if __name__ == "__main__":
    main() 