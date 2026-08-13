import requests
import socket
import threading
import time
import urllib3
import dns.resolver
import logging
from concurrent.futures import ThreadPoolExecutor
from Wappalyzer import Wappalyzer, WebPage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("shadowscan.scanner")


class ShadowScanCore:
    def __init__(self, domain, threads=40):
        self.domain = domain
        self.threads = threads
        self.subdomains = set()
        self.results = {}
        self.print_lock = threading.Lock()
        self.target_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080, 8443]
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowScan/2.0"

        # Rate limiter: max 10 outbound HTTP requests in-flight at any moment.
        # Without this, 40 threads hammering a target will trigger WAF/CDN bans
        # within seconds and get your scanner IP null-routed.
        self._http_semaphore = threading.Semaphore(10)

    # ------------------------------------------------------------------
    # Subdomain Discovery
    # ------------------------------------------------------------------

    def _fetch_hackertarget(self):
        """Passive discovery via HackerTarget hostsearch API."""
        found = set()
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=10,
                headers={"User-Agent": self.user_agent},
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    if subdomain:
                        found.add(subdomain)
        except requests.exceptions.Timeout:
            logger.warning("HackerTarget timed out for %s", self.domain)
        except requests.exceptions.HTTPError as e:
            logger.warning("HackerTarget HTTP error: %s", e)
        except requests.exceptions.RequestException as e:
            logger.error("HackerTarget request failed: %s", e)
        return found

    def _fetch_crtsh(self):
        """Passive discovery via Certificate Transparency logs (crt.sh).

        Independent second source. crt.sh often surfaces staging/dev subdomains
        that HackerTarget misses because they appear in TLS certs even when
        DNS records aren't publicly indexed.
        """
        found = set()
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15,
                headers={"User-Agent": self.user_agent},
            )
            resp.raise_for_status()
            entries = resp.json()
            for entry in entries:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name and name.endswith(self.domain) and "*" not in name:
                        found.add(name)
        except requests.exceptions.Timeout:
            logger.warning("crt.sh timed out for %s", self.domain)
        except requests.exceptions.JSONDecodeError:
            logger.warning("crt.sh returned non-JSON — possibly rate-limited")
        except requests.exceptions.RequestException as e:
            logger.error("crt.sh request failed: %s", e)
        return found

    def get_subdomains(self):
        """Aggregate results from all passive sources."""
        logger.info("Running HackerTarget passive discovery...")
        ht_results = self._fetch_hackertarget()
        logger.info("HackerTarget found %d subdomains", len(ht_results))

        time.sleep(1)  # Courtesy delay between sources

        logger.info("Running crt.sh Certificate Transparency discovery...")
        crt_results = self._fetch_crtsh()
        logger.info("crt.sh found %d subdomains", len(crt_results))

        self.subdomains = ht_results | crt_results
        logger.info("Total unique subdomains after dedup: %d", len(self.subdomains))

    # ------------------------------------------------------------------
    # Active Scanning Helpers
    # ------------------------------------------------------------------

    def grab_banner(self, ip, port):
        """Captures service banner for version fingerprinting. Never raises."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((ip, port))
                if port in [80, 443, 8080, 8443]:
                    s.sendall(
                        f"HEAD / HTTP/1.1\r\nHost: {self.domain}\r\nConnection: close\r\n\r\n"
                        .encode()
                    )
                    response = s.recv(1024).decode(errors="ignore")
                    for line in response.split("\r\n"):
                        if line.lower().startswith("server:"):
                            return line.split(":", 1)[1].strip()
                    return "No Server header"
                raw = s.recv(1024).decode(errors="ignore").strip()
                return raw if raw else "No banner"
        except socket.timeout:
            return "Timeout"
        except OSError as e:
            logger.debug("Banner grab failed for %s:%d — %s", ip, port, e)
            return "No banner"

    def fingerprint_host(self, host):
        """Tech-stack fingerprinting via Wappalyzer. Respects HTTP rate limit."""
        with self._http_semaphore:
            try:
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(
                    f"https://{host}", verify=False, timeout=8
                )
                tech = wappalyzer.analyze_with_versions_and_categories(webpage)
                return {
                    name: info.get("versions", ["?"])[0]
                    for name, info in tech.items()
                }
            except Exception as e:
                logger.debug("Wappalyzer failed for %s: %s", host, e)
                return {}

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def worker(self, host):
        """Thread worker: DNS -> fingerprint -> port scan -> log results."""
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            logger.debug("DNS resolution failed for %s: %s", host, e)
            return

        tech_stack = self.fingerprint_host(host)

        open_ports = []
        for port in self.target_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        try:
                            service = socket.getservbyport(port)
                        except OSError:
                            service = "unknown"
                        banner = self.grab_banner(ip, port)

                        # "Timeout" on banner means: TCP handshake completed but
                        # the service never sent data. This is a firewall artifact
                        # (stateful firewalls accept the SYN but silently drop the
                        # connection). It's NOT an open port — reporting it creates
                        # false positives like the port-21-on-every-Cloudflare-host
                        # problem. Only report if we got actual service data.
                        if banner == "Timeout":
                            logger.debug(
                                "Port %d on %s accepted TCP but sent no data — "
                                "likely firewall, skipping", port, host
                            )
                            continue

                        open_ports.append({"port": port, "service": service, "banner": banner})
            except OSError as e:
                logger.debug("Port scan error on %s:%d — %s", host, port, e)

        with self.print_lock:
            self.results[host] = {
                "ip": ip,
                "technologies": tech_stack,
                "open_ports": open_ports,
            }
            print(f"[LIVE] {host:30} ({ip:15})")
            for t, v in tech_stack.items():
                print(f"    -> Tech: {t} ({v})")
            for p in open_ports:
                banner_str = (
                    f" -> {p['banner']}"
                    if p["banner"] not in ("No banner", "Timeout", "No Server header")
                    else ""
                )
                print(f"    |_ Port {p['port']} ({p['service']}){banner_str}")

    # ------------------------------------------------------------------
    # Entry Point
    # ------------------------------------------------------------------

    def run(self):
        self.get_subdomains()
        if not self.subdomains:
            print("[!] No subdomains found. Check the domain name or try again later.")
            return
        print(f"[*] {len(self.subdomains)} subdomains queued. Starting {self.threads} worker threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.worker, list(self.subdomains))
