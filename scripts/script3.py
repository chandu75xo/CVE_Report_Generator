import requests
import re
import os
import socket
import sys
import json
import asyncio
import aiohttp
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from datetime import datetime
import threading
from queue import Queue

# -------------------------
# Configuration
# -------------------------
TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 5
COMMON_PORTS = [80, 443, 21, 22, 25, 3389, 8080, 8443, 53, 110, 143, 3306, 5432, 27017, 6379, 9200, 11211]

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
# Enhanced IP Resolution
# -------------------------
def resolve_ip(url):
    try:
        # Clean URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return f"ERROR: Invalid hostname in {url}"
        
        # Try to resolve IP
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        return f"ERROR: DNS resolution failed - {e}"
    except Exception as e:
        return f"ERROR: {e}"

# -------------------------
# Enhanced Port Scanner
# -------------------------
def scan_ports(ip, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    filtered_ports = []
    
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
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
# Debug Function to Show All Headers
# -------------------------
def debug_headers(url):
    """Debug function to show all HTTP headers received"""
    try:
        full_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        resp = requests.get(full_url, timeout=TIMEOUT, headers=headers, allow_redirects=True)
        
        print(f"\n🔍 DEBUG HEADERS for {url}:")
        print("="*50)
        for header, value in resp.headers.items():
            print(f"{header}: {value}")
        print("="*50)
        
        return resp.headers
    except Exception as e:
        print(f"Error debugging headers: {e}")
        return {}

# -------------------------
# Enhanced Software & Version Detection
# -------------------------
def get_software_version(url):
    software_info = {
        'software': '',
        'version': '',
        'server_header': '',
        'x_powered_by': '',
        'additional_info': []
    }
    
    try:
        # Try HTTPS first, then HTTP
        protocols = ['https://', 'http://']
        
        for protocol in protocols:
            try:
                full_url = url if url.startswith(('http://', 'https://')) else protocol + url
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                resp = requests.get(full_url, timeout=TIMEOUT, headers=headers, allow_redirects=True)
                
                # Extract headers
                server = resp.headers.get('Server', '')
                x_powered = resp.headers.get('X-Powered-By', '')
                via = resp.headers.get('Via', '')
                
                software_info['server_header'] = server
                software_info['x_powered_by'] = x_powered
                
                # Priority 1: Try to extract software/version from Server header
                if server:
                    # Pattern 1: Apache/2.4.41, nginx/1.18.0, IIS/10.0
                    match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
                    if match:
                        software_info['software'] = match.group(1)
                        software_info['version'] = match.group(2)
                        break
                    
                    # Pattern 2: Apache-Coyote/1.1, Apache/2.4.41 (Ubuntu)
                    match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', server)
                    if match:
                        software_info['software'] = match.group(1)
                        software_info['version'] = match.group(2)
                        break
                    
                    # Pattern 3: Just software name without version
                    if not software_info['software']:
                        # Extract just the software name
                        match = re.search(r'^([\w\-]+)', server)
                        if match:
                            software_info['software'] = match.group(1)
                
                # Priority 2: Try X-Powered-By header (often more useful for applications)
                if x_powered:
                    # Pattern 1: PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1
                    match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', x_powered)
                    if match:
                        # If we already have a web server, keep it but add the application
                        if software_info['software'] and software_info['software'] in ['Apache', 'nginx', 'IIS']:
                            # Keep web server, but note the application
                            software_info['additional_info'].append(f"Application: {match.group(1)} {match.group(2)}")
                        else:
                            software_info['software'] = match.group(1)
                            software_info['version'] = match.group(2)
                        break
                    
                    # Pattern 2: ASP.NET, Express, etc.
                    if not software_info['software']:
                        match = re.search(r'^([\w\-\.]+)', x_powered)
                        if match:
                            software_info['software'] = match.group(1)
                
                # Priority 3: Try Via header
                if via:
                    match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', via)
                    if match:
                        software_info['software'] = match.group(1)
                        software_info['version'] = match.group(2)
                        break
                
                # Parse HTML for additional clues
                if resp.text:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    
                    # Check meta generator tag
                    meta = soup.find('meta', attrs={'name': 'generator'})
                    if meta and meta.get('content'):
                        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', meta['content'])
                        if match:
                            software_info['software'] = match.group(1)
                            software_info['version'] = match.group(2)
                            break
                    
                    # Check HTML comments for version info
                    comments = soup.find_all(string=lambda text: isinstance(text, type(soup.Comment)))
                    for comment in comments:
                        # Look for version patterns in comments
                        match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', comment)
                        if match:
                            software_info['software'] = match.group(1)
                            software_info['version'] = match.group(2)
                            break
                    
                    # Check title for version info
                    title = soup.title.string if soup.title else ''
                    match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', title)
                    if match:
                        software_info['software'] = match.group(1)
                        software_info['version'] = match.group(2)
                        break
                    
                    # Check for common software signatures in HTML
                    html_text = resp.text.lower()
                    
                    # WordPress detection
                    if 'wordpress' in html_text and 'wp-content' in html_text:
                        software_info['software'] = 'WordPress'
                        # Try to find WordPress version
                        wp_version_match = re.search(r'wp-content/themes/.*?/style\.css\?ver=([\d\.]+)', html_text)
                        if wp_version_match:
                            software_info['version'] = wp_version_match.group(1)
                        break
                    
                    # Drupal detection
                    if 'drupal' in html_text and 'drupal.js' in html_text:
                        software_info['software'] = 'Drupal'
                        # Try to find Drupal version
                        drupal_version_match = re.search(r'drupal.*?([\d\.]+)', html_text)
                        if drupal_version_match:
                            software_info['version'] = drupal_version_match.group(1)
                        break
                    
                    # Joomla detection
                    if 'joomla' in html_text and 'joomla.js' in html_text:
                        software_info['software'] = 'Joomla'
                        # Try to find Joomla version
                        joomla_version_match = re.search(r'joomla.*?([\d\.]+)', html_text)
                        if joomla_version_match:
                            software_info['version'] = joomla_version_match.group(1)
                        break
                
                # If we found something, break
                if software_info['software']:
                    break
                    
            except requests.exceptions.RequestException:
                continue
        
        # If still no software detected, try to extract from headers
        if not software_info['software']:
            if software_info['server_header']:
                # Try to extract just the software name from server header
                match = re.search(r'^([\w\-]+)', software_info['server_header'])
                if match:
                    software_info['software'] = match.group(1)
                else:
                    software_info['software'] = software_info['server_header']
            elif software_info['x_powered_by']:
                # Try to extract just the software name from X-Powered-By
                match = re.search(r'^([\w\-\.]+)', software_info['x_powered_by'])
                if match:
                    software_info['software'] = match.group(1)
                else:
                    software_info['software'] = software_info['x_powered_by']
        
        # Additional version extraction attempts
        if software_info['software'] and not software_info['version']:
            # Try to extract version from server header again with different patterns
            if software_info['server_header']:
                # Pattern for Apache/2.4.41 (Ubuntu) - extract just the version part
                match = re.search(r'[\w\-]+[/ ]([\d\.]+)', software_info['server_header'])
                if match:
                    software_info['version'] = match.group(1)
                
                # Pattern for Apache-Coyote/1.1
                if not software_info['version']:
                    match = re.search(r'[\w\-]+[/ ]([\d\.]+)', software_info['server_header'])
                    if match:
                        software_info['version'] = match.group(1)
            
            # Try to extract version from X-Powered-By header
            if software_info['x_powered_by'] and not software_info['version']:
                match = re.search(r'[\w\-]+[/ ]([\d\.]+)', software_info['x_powered_by'])
                if match:
                    software_info['version'] = match.group(1)
        
        # Special handling for cases where we have both web server and application
        if software_info['software'] in ['Apache', 'nginx', 'IIS'] and software_info['x_powered_by']:
            # If we have a web server but no version, try to get version from X-Powered-By
            if not software_info['version']:
                match = re.search(r'([\w\-]+)[/ ]([\d\.]+)', software_info['x_powered_by'])
                if match:
                    # Add application info to additional_info
                    software_info['additional_info'].append(f"Application: {match.group(1)} {match.group(2)}")
        
        return software_info
        
    except Exception as e:
        software_info['additional_info'].append(f"Error: {e}")
        return software_info

# -------------------------
# CVE Search Functions (Reliable Sources)
# -------------------------
def search_cves_circl(software, version):
    if not software:
        return []
    
    vendor = software.lower()
    product = software.lower()
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            cve_list = []
            for item in data.get('data', [])[:15]:
                cve_id = item.get('id', 'N/A')
                desc = item.get('summary', 'No description')
                if cve_id.startswith('CVE-'):
                    cve_list.append((cve_id, desc))
            return cve_list
    except Exception:
        pass
    return []

def search_cves_mitre(software, version):
    if not software:
        return []
    
    keyword = f"{software} {version}".strip()
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword.replace(' ', '+')}"
    
    try:
        resp = requests.get(url, timeout=TIMEOUT, 
                           headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            cve_list = []
            for row in soup.select('table tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 2:
                    cve_id = cols[0].get_text(strip=True)
                    desc = cols[1].get_text(strip=True)
                    if cve_id.startswith('CVE-'):
                        cve_list.append((cve_id, desc))
                if len(cve_list) >= 15:
                    break
            return cve_list
    except Exception:
        pass
    return []

def search_cves_cvedetails(software, version):
    if not software:
        return []
    
    keyword = f"{software} {version}".strip().replace(' ', '+')
    url = f"https://www.cvedetails.com/google-search-results.php?q={keyword}"
    
    try:
        resp = requests.get(url, timeout=TIMEOUT, 
                           headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            cve_list = []
            for link in soup.select('a[href^="/cve/"]'):
                cve_id = link.get_text(strip=True)
                if cve_id.startswith('CVE-'):
                    desc = link.find_next('td').get_text(strip=True) if link.find_next('td') else ''
                    cve_list.append((cve_id, desc))
                if len(cve_list) >= 15:
                    break
            return cve_list
    except Exception:
        pass
    return []

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
# Real-time Display
# -------------------------
class RealTimeDisplay:
    def __init__(self):
        self.lock = threading.Lock()
        self.results = {}
    
    def update_result(self, url, data):
        with self.lock:
            self.results[url] = data
            self.display_current_results()
    
    def display_current_results(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\n{'='*100}")
        print(f"🔍 ENHANCED PARALLEL CVE SCANNER - Real-time Results")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*100}\n")
        
        for url, data in self.results.items():
            print(f"🌐 URL: {url}")
            print(f"   📍 IP: {data.get('ip', 'N/A')}")
            print(f"   🔓 Open Ports: {data.get('open_ports', [])}")
            print(f"   🛡️  Filtered Ports: {len(data.get('filtered_ports', []))}")
            print(f"   💻 Software: {data.get('software', 'N/A')}")
            print(f"   📦 Version: {data.get('version', 'N/A')}")
            print(f"   🖥️  Server Header: {data.get('server_header', 'N/A')}")
            print(f"   ⚡ X-Powered-By: {data.get('x_powered_by', 'N/A')}")
            
            cves = data.get('all_cves', [])
            if cves:
                print(f"   🚨 CVEs Found: {len(cves)}")
                for i, (cve_id, desc) in enumerate(cves[:3], 1):
                    print(f"      {i}. {cve_id}: {desc[:70]}{'...' if len(desc) > 70 else ''}")
                if len(cves) > 3:
                    print(f"      ... and {len(cves) - 3} more")
            else:
                print(f"   ✅ No CVEs found")
            
            print(f"   📊 Status: {data.get('status', 'Processing...')}")
            print("-" * 100)

# -------------------------
# Per-URL Processing Function
# -------------------------
def process_url_parallel(url, display_queue):
    result = {
        'url': url,
        'ip': None,
        'open_ports': [],
        'filtered_ports': [],
        'software': None,
        'version': None,
        'server_header': None,
        'x_powered_by': None,
        'all_cves': [],
        'status': 'Starting...'
    }
    
    # Update display
    display_queue.update_result(url, result)
    
    # Step 1: IP Resolution
    result['status'] = '🔍 Resolving IP address...'
    display_queue.update_result(url, result)
    
    ip = resolve_ip(url)
    result['ip'] = ip
    
    if isinstance(ip, str) and ip.startswith('ERROR'):
        result['status'] = f'❌ IP resolution failed: {ip}'
        display_queue.update_result(url, result)
        return result
    
    # Step 2: Port Scanning
    result['status'] = '🔓 Scanning ports...'
    display_queue.update_result(url, result)
    
    open_ports, filtered_ports = scan_ports(ip)
    result['open_ports'] = open_ports
    result['filtered_ports'] = filtered_ports
    
    # Step 3: Software Detection
    result['status'] = '💻 Detecting software and version...'
    display_queue.update_result(url, result)
    
    software_info = get_software_version(url)
    result['software'] = software_info['software']
    result['version'] = software_info['version']
    result['server_header'] = software_info['server_header']
    result['x_powered_by'] = software_info['x_powered_by']
    
    if not software_info['software']:
        result['status'] = '⚠️ No software detected - skipping CVE search'
        display_queue.update_result(url, result)
        return result
    
    # Step 4: CVE Search (Parallel)
    result['status'] = '🚨 Searching for CVEs...'
    display_queue.update_result(url, result)
    
    cve_sources = [
        (search_cves_circl, "CIRCL"),
        (search_cves_mitre, "MITRE"),
        (search_cves_cvedetails, "CVE Details")
    ]
    
    all_cves = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_source = {
            executor.submit(source_func, software_info['software'], software_info['version']): source_name 
            for source_func, source_name in cve_sources
        }
        
        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                cves = future.result()
                all_cves.extend(cves)
                # Update display with partial results
                result['all_cves'] = merge_cve_lists(all_cves)
                result['status'] = f'🔍 Found {len(result["all_cves"])} CVEs so far...'
                display_queue.update_result(url, result)
            except Exception as e:
                print(f"Error in {source_name}: {e}")
    
    # Final result
    result['all_cves'] = merge_cve_lists(all_cves)
    result['status'] = f'✅ Complete - {len(result["all_cves"])} CVEs found'
    display_queue.update_result(url, result)
    
    return result

# -------------------------
# Main Execution
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python script3.py <url or url_list.txt> [--debug]")
        sys.exit(1)
    
    input_value = sys.argv[1]
    debug_mode = '--debug' in sys.argv
    
    urls = get_urls(input_value)
    
    if not urls:
        print("No URLs found!")
        sys.exit(1)
    
    # Debug mode: show headers for first URL
    if debug_mode and urls:
        print("🔍 DEBUG MODE: Showing headers for first URL...")
        debug_headers(urls[0])
        return
    
    print(f"🚀 Starting enhanced parallel scanner for {len(urls)} URL(s)...")
    print("Press Ctrl+C to stop\n")
    time.sleep(2)
    
    # Initialize display
    display_queue = RealTimeDisplay()
    
    # Process URLs in parallel
    results = []
    with ThreadPoolExecutor(max_workers=min(len(urls), MAX_CONCURRENT_REQUESTS)) as executor:
        future_to_url = {
            executor.submit(process_url_parallel, url, display_queue): url 
            for url in urls
        }
        
        try:
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    print(f"\n❌ Error processing {url}: {exc}")
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            executor.shutdown(wait=False)
    
    # Save results to single report file (overwrites each time)
    output_file = "cve_scan_report.txt"
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"ENHANCED PARALLEL CVE SCANNER REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"URLs Scanned: {len(urls)}\n")
        f.write("="*100 + "\n\n")
        
        for result in results:
            f.write(f"URL: {result['url']}\n")
            f.write(f"IP Address: {result['ip']}\n")
            f.write(f"Open Ports: {result['open_ports']}\n")
            f.write(f"Filtered Ports: {len(result['filtered_ports'])}\n")
            f.write(f"Software: {result['software']}\n")
            f.write(f"Version: {result['version']}\n")
            f.write(f"Server Header: {result['server_header']}\n")
            f.write(f"X-Powered-By: {result['x_powered_by']}\n")
            f.write(f"CVEs Found: {len(result['all_cves'])}\n")
            f.write("-"*60 + "\n")
            
            for cve_id, desc in result['all_cves']:
                f.write(f"{cve_id}: {desc}\n")
            f.write("\n" + "="*100 + "\n\n")
    
    print(f"\n✅ Scan completed! Results saved to: {output_file}")
    print(f"📊 Summary: {len(results)} URLs processed, {sum(len(r['all_cves']) for r in results)} total CVEs found")
    print(f"📄 Report file: {output_file} (updated with latest results)")

if __name__ == "__main__":
    main() 