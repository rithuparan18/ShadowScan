import requests
import socket
import threading
import urllib3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from Wappalyzer import Wappalyzer, WebPage

# Suppress SSL warnings globally for cleaner terminal output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ShadowScanCore:
    def __init__(self, domain, threads=40):
        self.domain = domain
        self.threads = threads
        self.subdomains = set()
        self.results = {}
        self.print_lock = threading.Lock()
        # High-value ports for offensive reconnaissance
        self.target_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080, 8443]
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowScan/2.0'

    def get_subdomains(self):
        """Passive discovery using HackerTarget API"""
        try:
            resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if resp.status_code == 200:
                for line in resp.text.split('\n'):
                    if ',' in line:
                        self.subdomains.add(line.split(',')[0].strip().lower())
        except: 
            pass

    def grab_banner(self, ip, port, service):
        """Captures service metadata for version identification"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((ip, port))
                
                # Special handling for HTTP/HTTPS to get the 'Server' header
                if port in [80, 443, 8080, 8443]:
                    request = f"HEAD / HTTP/1.1\r\nHost: {self.domain}\r\nConnection: close\r\n\r\n"
                    s.sendall(request.encode())
                    response = s.recv(1024).decode(errors='ignore')
                    for line in response.split('\r\n'):
                        if line.startswith("Server:"):
                            return line.replace("Server:", "").strip()
                
                # Generic TCP banner grab (SSH, FTP, etc.)
                return s.recv(1024).decode(errors='ignore').strip() or "No banner"
        except: 
            return "No banner"

    def fingerprint_host(self, host):
        """Analyzes tech stack using Wappalyzer (Integrated from brain.py)"""
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(f"https://{host}", verify=False, timeout=8)
            tech = wappalyzer.analyze_with_versions_and_categories(webpage)
            # Return cleaned dictionary for JSON serialization
            return {name: info.get('versions', ['?'])[0] for name, info in tech.items()}
        except:
            return {}

    def worker(self, host):
        """Thread-safe multi-tasking handler"""
        try:
            # Verify host is live via DNS
            ip = socket.gethostbyname(host)
            
            # 1. Technology Fingerprinting
            tech_stack = self.fingerprint_host(host)
            
            # 2. Port Scanning & Banner Grabbing
            open_ports = []
            for port in self.target_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        try: service = socket.getservbyport(port)
                        except: service = "unknown"
                        banner = self.grab_banner(ip, port, service)
                        open_ports.append({"port": port, "service": service, "banner": banner})

            # 3. Thread-safe results logging
            with self.print_lock:
                self.results[host] = {
                    "ip": ip, 
                    "technologies": tech_stack,
                    "open_ports": open_ports
                }
                print(f"[LIVE] {host:30} ({ip:15})")
                if tech_stack:
                    for t, v in tech_stack.items():
                        print(f"    -> Tech: {t} ({v})")
                for p in open_ports:
                    banner_str = f" -> {p['banner']}" if p['banner'] != "No banner" else ""
                    print(f"    |_ Port {p['port']}({p['service']}){banner_str}")
        except: 
            pass

    def run(self):
        self.get_subdomains()
        if not self.subdomains:
            print("[!] No subdomains found.")
            return

        print(f"[*] Starting {self.threads} threads for deep scanning...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.worker, list(self.subdomains))
