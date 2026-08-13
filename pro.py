import requests
import dns.resolver
import json
import socket
import warnings
import threading
from Wappalyzer import Wappalyzer, WebPage
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL warnings
warnings.filterwarnings("ignore")

class ShadowScanPro:
    def __init__(self, domain, threads=40):
        self.domain = domain
        self.subdomains = set()
        self.results = {}
        self.threads = threads
        self.print_lock = threading.Lock()
        self.user_agent = 'ShadowScan/Pro-1.0 (Offensive Security Tool)'
        self.target_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080, 8443]

    def get_subdomains(self):
        """Passive Enumeration via HackerTarget API"""
        print(f"[*] Enumerating {self.domain}...")
        try:
            resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if resp.status_code == 200 and "error" not in resp.text:
                for line in resp.text.split('\n'):
                    if ',' in line:
                        self.subdomains.add(line.split(',')[0].strip().lower())
        except Exception as e:
            print(f"[!] Enumeration Error: {e}")
        print(f"[+] Found {len(self.subdomains)} potential targets.")

    def scan_port(self, ip, port):
        """TCP Connect Scan logic"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return {"port": port, "service": service}
        except:
            pass
        return None

    def fingerprint_host(self, host):
        """Technology stack analysis"""
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(f"https://{host}", verify=False, timeout=8)
            tech = wappalyzer.analyze_with_versions_and_categories(webpage)
            # Serialize for JSON compatibility
            return {name: info.get('versions', ['?']) for name, info in tech.items()}
        except:
            return {}

    def worker(self, host):
        """Thread-safe worker function for scanning"""
        try:
            ip = socket.gethostbyname(host)
            host_data = {"ip": ip, "open_ports": [], "tech_stack": {}}
            
            # Port Scanning
            for port in self.target_ports:
                res = self.scan_port(ip, port)
                if res:
                    host_data["open_ports"].append(res)

            # Tech Fingerprinting
            web_ports = [80, 443, 8080, 8443]
            if any(p['port'] in web_ports for p in host_data["open_ports"]):
                host_data["tech_stack"] = self.fingerprint_host(host)

            # Thread-safe writing to results and terminal
            with self.print_lock:
                self.results[host] = host_data
                print(f"\n[LIVE] {host} ({ip})")
                for p in host_data["open_ports"]:
                    print(f"    |_ Port {p['port']}: {p['service']}")
                if host_data["tech_stack"]:
                    for tech, ver in host_data["tech_stack"].items():
                        print(f"    -> Tech: {tech} ({ver[0] if ver else '?'})")
            return True
        except:
            return False

    def run(self):
        self.get_subdomains()
        if not self.subdomains:
            return

        print(f"[*] Launching {self.threads} threads for deep scanning...")
        hosts = list(self.subdomains)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.worker, hosts)

        self.save_report()

    def save_report(self):
        filename = f"shadowscan_{self.domain.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] Scan Complete. Detailed report: {filename}")

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    if target:
        scanner = ShadowScanPro(target, threads=40)
        scanner.run()
