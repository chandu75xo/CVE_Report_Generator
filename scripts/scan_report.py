import subprocess
import re
import requests
import os
import socket
from datetime import datetime
from urllib.parse import urlparse, quote
from bs4 import BeautifulSoup

# === CONFIG ===
targets = [
    "https://localhost:1337",  # WordPress Jetpack
    "http://localhost:8080/WebGoat"  # WebGoat
]
nmap_exe = r"C:\Program Files (x86)\Nmap\nmap.exe"  # 🔧 Replace with your nmap.exe path

# === TIMESTAMPED FILE ===
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
report_file = f"report_{timestamp}.txt"

def resolve_ip(url):
    """Extract IP from URL or resolve hostname"""
    parsed = urlparse(url)
    hostname = parsed.hostname
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except:
        return hostname

def run_nmap_scan(ip, ports=None):
    """Run Nmap scan with service detection"""
    if not os.path.isfile(nmap_exe):
        print("❌ Nmap not found, using basic port scan")
        return scan_ports_basic(ip, ports)
    
    try:
        if ports:
            port_arg = f"-p {','.join(map(str, ports))}"
        else:
            port_arg = "-p 80,443,8080,1337,22,21,25,3389,8443,53,110,143,3306,5432"
        
        cmd = [nmap_exe, "-sV", "-sS", port_arg, ip]
        print(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Nmap scan completed successfully")
            return parse_nmap_output(result.stdout)
        else:
            print(f"❌ Nmap scan failed: {result.stderr}")
            return scan_ports_basic(ip, ports)
            
    except subprocess.TimeoutExpired:
        print("❌ Nmap scan timed out")
        return scan_ports_basic(ip, ports)
    except Exception as e:
        print(f"❌ Nmap error: {e}")
        return scan_ports_basic(ip, ports)

def parse_nmap_output(nmap_output):
    """Parse Nmap output to extract service information"""
    services = []
    lines = nmap_output.split('\n')
    
    for line in lines:
        # Match port/service/version pattern
        match = re.search(r'(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.+))?', line)
        if match and match.group(3) == 'open':
            port = match.group(1)
            protocol = match.group(2)
            service = match.group(4)
            version = match.group(5) if match.group(5) else ''
            services.append({
                'port': port,
                'protocol': protocol,
                'service': service,
                'version': version.strip()
            })
    
    return services

def scan_ports_basic(ip, ports=None):
    """Basic port scan fallback"""
    if ports is None:
        ports = [80, 443, 8080, 1337, 22, 21, 25, 3389, 8443, 53, 110, 143, 3306, 5432]
    
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    
    # Convert to service format
    services = []
    for port in open_ports:
        services.append({
            'port': str(port),
            'protocol': 'tcp',
            'service': 'unknown',
            'version': ''
        })
    
    return services

def get_software_info(url):
    """Get software info from HTTP headers"""
    try:
        # Disable SSL verification for self-signed certs
        resp = requests.get(url, timeout=10, verify=False)
        server = resp.headers.get('Server', '')
        x_powered = resp.headers.get('X-Powered-By', '')
        return server, x_powered, resp.headers
    except Exception as e:
        return '', '', {}

def get_cves_circl(software, version):
    """Get CVEs from CIRCL API (Primary Source)"""
    if not software:
        return []
    
    # Clean up software name for API
    software_clean = re.sub(r'[^\w\-]', '', software.lower())
    if not software_clean:
        return []
    
    url = f"https://cve.circl.lu/api/search/{software_clean}/{software_clean}"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        cves = [(item.get('id', 'N/A'), item.get('summary', 'No description')) for item in data.get('data', [])[:5]]
        return cves
    except Exception as e:
        return []

def get_cves_mitre(software, version):
    """Get CVEs from MITRE (Backup Source)"""
    if not software:
        return []
    
    keyword = f"{software} {version}".strip()
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword.replace(' ', '+')}"
    
    try:
        resp = requests.get(url, timeout=7, headers={'User-Agent': 'Mozilla/5.0'})
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
            if len(cve_list) >= 5:
                break
        
        return cve_list
    except Exception as e:
        return []

def get_cves_reliable(software, version):
    """Get CVEs with fallback - CIRCL first, then MITRE"""
    print(f"🔍 Searching CVEs for: {software} {version}")
    
    # Try CIRCL first (most reliable)
    cves = get_cves_circl(software, version)
    if cves:
        print(f"✅ Found {len(cves)} CVEs from CIRCL")
        return cves
    
    # Fallback to MITRE
    print("🔄 CIRCL failed, trying MITRE...")
    cves = get_cves_mitre(software, version)
    if cves:
        print(f"✅ Found {len(cves)} CVEs from MITRE")
        return cves
    
    print("❌ No CVEs found from either source")
    return []

def get_wordpress_info(url):
    """Get WordPress specific information"""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        # Look for WordPress version in HTML
        wp_version_match = re.search(r'wp-content/themes/[^/]+/style\.css\?ver=([\d\.]+)', resp.text)
        wp_version = wp_version_match.group(1) if wp_version_match else 'Unknown'
        
        # Look for plugins
        plugins = re.findall(r'wp-content/plugins/([^/]+)/', resp.text)
        unique_plugins = list(set(plugins))
        
        return wp_version, unique_plugins
    except:
        return 'Unknown', []

def get_webgoat_info(url):
    """Get WebGoat specific information"""
    webgoat_paths = [
        "/WebGoat",
        "/",
        "/WebGoat/login",
        "/WebGoat/start.mvc",
        "/WebGoat/welcome.mvc"
    ]
    
    base_url = "http://localhost:8080"
    
    for path in webgoat_paths:
        try:
            test_url = base_url + path
            print(f"Testing WebGoat at: {test_url}")
            resp = requests.get(test_url, timeout=10, verify=False)
            
            if resp.status_code == 200:
                print(f"✅ WebGoat found at: {test_url}")
                # Look for WebGoat indicators in response
                if 'WebGoat' in resp.text or 'webgoat' in resp.text.lower():
                    server = resp.headers.get('Server', '')
                    return f"WebGoat detected at {path} - Server: {server}"
                else:
                    return f"Application at {path} (not WebGoat)"
            
        except Exception as e:
            print(f"❌ Failed to connect to {test_url}: {e}")
            continue
    
    # If all paths fail, try to get basic info from the port
    try:
        resp = requests.get("http://localhost:8080", timeout=5, verify=False)
        return f"Application on port 8080 - Status: {resp.status_code}"
    except:
        return "WebGoat (connection failed - check if container is running)"

# === WRITE REPORT FILE ===
with open(report_file, "w") as f:
    f.write(f"Scan Report - {timestamp}\n")
    f.write("=" * 50 + "\n\n")
    
    for target in targets:
        f.write(f"Target: {target}\n")
        f.write("-" * 30 + "\n")
        
        # Resolve IP
        ip = resolve_ip(target)
        f.write(f"IP/Hostname: {ip}\n")
        
        # Run Nmap scan
        print(f"\n🔍 Scanning {target} ({ip}) with Nmap...")
        services = run_nmap_scan(ip)
        
        f.write(f"Open Ports Found:\n")
        for service in services:
            f.write(f"  Port {service['port']}/{service['protocol']}: {service['service']} {service['version']}\n")
        
        # Get software info from HTTP
        server, x_powered, headers = get_software_info(target)
        f.write(f"HTTP Server: {server}\n")
        f.write(f"X-Powered-By: {x_powered}\n")
        
        # Get application-specific info
        if 'localhost:1337' in target:
            wp_version, plugins = get_wordpress_info(target)
            f.write(f"WordPress Version: {wp_version}\n")
            f.write(f"Plugins Detected: {plugins[:5]}\n")  # Show first 5 plugins
        elif 'localhost:8080' in target:
            webgoat_info = get_webgoat_info(target)
            f.write(f"Application: {webgoat_info}\n")
        
        # Try to get CVEs for detected software with reliable fallback
        if server:
            # Try different software names for CVE lookup
            software_names = [server.split('/')[0] if '/' in server else server]
            if 'Apache' in server:
                software_names.append('apache')
            if 'PHP' in x_powered:
                software_names.append('php')
            
            for software in software_names:
                cves = get_cves_reliable(software, '')
                if cves:
                    f.write(f"CVEs Found for {software}:\n")
                    for cve_id, desc in cves:
                        f.write(f"  {cve_id}: {desc[:100]}\n")
                    break
            else:
                f.write("No CVEs found for detected software.\n")
        
        f.write("\n" + "=" * 50 + "\n\n")

print(f"✅ Report generated: {report_file}")
print("📋 Check the report file for detailed results.")
