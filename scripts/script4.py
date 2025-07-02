import requests
import time
import sys
import json
import urllib3
from getpass import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Configuration
# -------------------------
DEFAULT_NESSUS_URL = 'https://localhost:8834'
DEFAULT_REPORT_FILE = 'tenable_report.json'

# -------------------------
# Helper Functions
# -------------------------
def nessus_login(nessus_url, access_key, secret_key):
    """Return headers for Nessus API authentication."""
    return {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
        'Content-Type': 'application/json'
    }

def create_scan(nessus_url, headers, target, scan_name="Automated Scan"): 
    """Create a new scan and return the scan id."""
    scan_data = {
        "uuid": get_basic_scan_template_uuid(nessus_url, headers),
        "settings": {
            "name": scan_name,
            "enabled": True,
            "text_targets": target,
            "launch_now": True
        }
    }
    resp = requests.post(f"{nessus_url}/scans", headers=headers, json=scan_data, verify=False)
    resp.raise_for_status()
    scan_id = resp.json()['scan']['id']
    return scan_id

def get_basic_scan_template_uuid(nessus_url, headers):
    """Fetch the UUID for the 'basic' scan template."""
    resp = requests.get(f"{nessus_url}/editor/scan/templates", headers=headers, verify=False)
    resp.raise_for_status()
    templates = resp.json()['templates']
    print("Available scan templates:")
    for t in templates:
        print(f"Title: {t['title']}, UUID: {t['uuid']}")
    # Now pick the one you want and return its UUID
    for t in templates:
        if t['title'].lower().startswith('basic'):
            return t['uuid']
    return templates[0]['uuid']

def launch_scan(nessus_url, headers, scan_id):
    resp = requests.post(f"{nessus_url}/scans/{scan_id}/launch", headers=headers, verify=False)
    resp.raise_for_status()
    return resp.json()['scan_uuid']

def wait_for_scan(nessus_url, headers, scan_id, poll_interval=10):
    """Wait for scan to finish and return the scan status."""
    while True:
        resp = requests.get(f"{nessus_url}/scans/{scan_id}", headers=headers, verify=False)
        resp.raise_for_status()
        status = resp.json()['info']['status']
        print(f"[i] Scan status: {status}")
        if status == 'completed':
            return resp.json()
        elif status in ('canceled', 'stopped', 'aborted'):
            raise Exception(f"Scan ended with status: {status}")
        time.sleep(poll_interval)

def fetch_vulnerabilities(scan_result):
    """Extract vulnerabilities from scan result."""
    vulns = scan_result['vulnerabilities']
    hosts = scan_result['hosts']
    host_vuln_map = {}
    for host in hosts:
        host_id = host['host_id']
        hostname = host.get('hostname', host.get('ip', ''))
        host_vuln_map[hostname] = []
        # Get detailed findings for this host
        for vuln in vulns:
            if vuln['host_id'] == host_id:
                host_vuln_map[hostname].append({
                    'plugin_name': vuln['plugin_name'],
                    'severity': vuln['severity'],
                    'count': vuln['count'],
                    'plugin_id': vuln['plugin_id'],
                    'cve': vuln.get('cve', ''),
                })
    return host_vuln_map

def print_report(host_vuln_map, output_file):
    print("\n=== Nessus/Tenable Scan Report ===\n")
    for host, vulns in host_vuln_map.items():
        print(f"Host: {host}")
        if not vulns:
            print("  No vulnerabilities found.")
        for v in vulns:
            print(f"  - {v['plugin_name']} (Severity: {v['severity']}, CVE: {v['cve']})")
        print()
    # Save as JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(host_vuln_map, f, indent=2)
    print(f"\nReport saved to {output_file}\n")

# -------------------------
# Main
# -------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Nessus/Tenable Automated Scanner")
    parser.add_argument('--url', default=DEFAULT_NESSUS_URL, help='Nessus server URL (default: https://localhost:8834)')
    parser.add_argument('--access-key', help='Nessus API Access Key')
    parser.add_argument('--secret-key', help='Nessus API Secret Key')
    parser.add_argument('--target', required=True, help='Target IP or URL (comma-separated for multiple)')
    parser.add_argument('--report', default=DEFAULT_REPORT_FILE, help='Report output file (default: tenable_report.json)')
    args = parser.parse_args()

    nessus_url = args.url.rstrip('/')
    access_key = args.access_key or getpass('Nessus Access Key: ')
    secret_key = args.secret_key or getpass('Nessus Secret Key: ')
    target = args.target
    output_file = args.report

    headers = nessus_login(nessus_url, access_key, secret_key)
    print(f"[+] Creating scan for target: {target}")
    scan_id = create_scan(nessus_url, headers, target)
    print(f"[+] Scan created with ID: {scan_id}")
    print(f"[+] Launching scan...")
    launch_scan(nessus_url, headers, scan_id)
    print(f"[+] Waiting for scan to complete...")
    scan_result = wait_for_scan(nessus_url, headers, scan_id)
    print(f"[+] Scan completed. Fetching vulnerabilities...")
    host_vuln_map = fetch_vulnerabilities(scan_result)
    print_report(host_vuln_map, output_file)

if __name__ == "__main__":
    main() 