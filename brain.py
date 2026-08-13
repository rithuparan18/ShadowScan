import requests
import dns.resolver
import json
import warnings
from Wappalyzer import Wappalyzer, WebPage

# Suppress SSL warnings for cleaner output during scans
warnings.filterwarnings("ignore")

class ShadowScan:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.results = {}
        self.user_agent = 'ShadowScan/1.0 (Offensive Security Recon Tool)'

    def get_subdomains(self):
        """Passive Recon using crt.sh with HackerTarget fallback"""
        print(f"[*] Enumerating subdomains for: {self.domain}")
        
        # Source 1: crt.sh (Certificate Transparency Logs)
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            resp = requests.get(url, headers={'User-Agent': self.user_agent}, timeout=20)
            if resp.status_code == 200:
                for entry in resp.json():
                    names = entry['name_value'].split('\n')
                    for name in names:
                        if name.endswith(self.domain) and "*" not in name:
                            self.subdomains.add(name.strip().lower())
        except Exception as e:
            print(f"[!] crt.sh error: {e}")

        # Source 2: HackerTarget Fallback
        if len(self.subdomains) == 0:
            print("[!] crt.sh yielded no results. Checking HackerTarget...")
            try:
                resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
                if resp.status_code == 200:
                    for line in resp.text.split('\n'):
                        if ',' in line:
                            self.subdomains.add(line.split(',')[0])
            except Exception:
                pass

        print(f"[+] Found {len(self.subdomains)} potential subdomains.")

    def fingerprint_host(self, host):
        """Analyze the technology stack using Wappalyzer"""
        url = f"https://{host}"
        try:
            wappalyzer = Wappalyzer.latest()
            # Analyze page content and headers
            webpage = WebPage.new_from_url(url, verify=False, timeout=10)
            tech = wappalyzer.analyze_with_versions_and_categories(webpage)
            return tech
        except Exception:
            return None

    def run(self):
        self.get_subdomains()
        
        print(f"\n[*] Starting Scan on {len(self.subdomains)} targets...")
        print("-" * 50)

        for host in sorted(self.subdomains):
            try:
                # DNS Resolution (Check if host is live)
                dns.resolver.resolve(host, 'A')
                print(f"\n[LIVE] {host}")
                
                # Fingerprinting
                tech_stack = self.fingerprint_host(host)
                host_data = {"technologies": []}

                if tech_stack:
                    for name, info in tech_stack.items():
                        version = info.get('versions', ['Unknown'])[0]
                        category = info.get('categories', ['Other'])[0]
                        
                        # Offensive Logic: Flag outdated/risky tech
                        status = ""
                        if any(v in version for v in ["5.4", "1.0", "1.1"]): # Example outdated signatures
                            status = " [CRITICAL: OUTDATED]"
                        
                        print(f"  - {name} ({version}) | Category: {category}{status}")
                        host_data["technologies"].append({
                            "name": name, 
                            "version": version, 
                            "category": category
                        })
                
                self.results[host] = host_data

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue # Ignore dead hosts
            except Exception as e:
                print(f"  [!] Error scanning {host}")

        self.save_report()

    def save_report(self):
        filename = f"scan_{self.domain.replace('.', '_')}.json"
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print("-" * 50)
        print(f"\n[+] Scan Complete. Report saved to: {filename}")

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    if target:
        scanner = ShadowScan(target)
        scanner.run()
