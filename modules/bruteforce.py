import requests
import urllib3
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("shadowscan.bruteforce")


class DirectoryBruter:
    def __init__(self, delay=0.1, threads=10):
        self.delay = delay
        self.threads = threads

        self.wordlist = [
            # Admin & Auth
            "admin", "admin/login", "admin/dashboard", "administrator",
            "login", "logout", "signin", "signup", "auth", "oauth",
            "wp-admin", "wp-login.php", "wp-json", "wp-content",
            "phpmyadmin", "pma", "cpanel", "webmail",
            # Config & Secrets
            ".env", ".env.local", ".env.production", ".env.backup",
            "config", "config.php", "config.yml", "config.json",
            "configuration.php", "settings.php", "settings.py",
            "web.config", "app.config", "database.yml",
            # Version Control
            ".git", ".git/config", ".git/HEAD", ".gitignore",
            ".svn", ".svn/entries", ".hg", ".DS_Store",
            ".htaccess", ".htpasswd",
            # API Endpoints
            "api", "api/v1", "api/v2", "api/v3",
            "api/users", "api/admin", "api/config",
            "graphql", "graphiql", "swagger", "swagger-ui.html",
            "api-docs", "openapi.json", "openapi.yaml",
            # Backup & Dumps
            "backup", "backup.zip", "backup.tar.gz", "backup.sql",
            "db.sql", "database.sql", "dump.sql",
            "site.zip", "website.zip", "old", "archive",
            # Sensitive Files
            "phpinfo.php", "info.php", "test.php",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "security.txt", ".well-known/security.txt",
            "README.md", "CHANGELOG.md", "LICENSE",
            # Dashboards & Monitoring
            "dashboard", "dashboard/login", "console",
            "admin-console", "management", "monitor",
            "kibana", "grafana", "jenkins", "jenkins/login",
            "sonarqube", "portainer",
            # Cloud / Framework
            "actuator", "actuator/env", "actuator/health",
            "actuator/metrics", "actuator/mappings",
            "server-status", "server-info", "nginx_status",
            "elmah.axd", "trace.axd", "wp-config.php.bak",
            "Dockerfile", "docker-compose.yml",
            # Setup / Shell
            "setup", "setup.php", "install", "install.php",
            "upgrade", "update", "migrate",
        ]

    def _probe(self, url):
        """
        Returns (status_code, content_length) or None on failure.
        Catches all timeout variants — urllib3 sometimes raises the raw
        TimeoutError before requests can wrap it.
        """
        try:
            resp = requests.get(
                url,
                timeout=4,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 ShadowScan/2.0"},
            )
            return resp.status_code, len(resp.content)
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except (TimeoutError, OSError):
            # urllib3 can bubble raw TimeoutError / OSError before requests wraps them
            return None
        except requests.exceptions.RequestException as e:
            logger.debug("Probe error for %s: %s", url, e)
            return None

    def _detect_wildcard(self, base_url):
        """
        Probe a path that cannot exist. Two wildcard patterns to catch:

        Pattern A — Redirect wildcard: server returns 301/302 for everything.
          Example: blog.chess.com redirected every path to the homepage.

        Pattern B — Empty-200 wildcard: server returns 200 with 0-byte body
          for everything. Example: rs-stripe.space.com returned 200+0B for
          every single path including /wp-admin, /.git, /dump.sql — all fake.
          A real 200 response has content. 0 bytes means the server echoed
          the status but served nothing — another catch-all handler.

        Returns a description string if wildcard detected, None if host is clean.
        """
        canary = f"{base_url}/shadowscan-canary-xyz987-does-not-exist"
        result = self._probe(canary)
        if result is None:
            return None
        status, size = result
        if status in (301, 302):
            return f"redirect wildcard (canary -> {status})"
        if status == 200 and size == 0:
            return "empty-200 wildcard (canary returned 200 with 0 bytes)"
        return None

    def _probe_with_delay(self, url):
        """Wraps _probe with rate-limit delay. Used inside thread pool."""
        result = self._probe(url)
        time.sleep(self.delay)
        return url, result

    def scan(self, host):
        base = f"https://{host}"

        # --- Wildcard check first ---
        wildcard_reason = self._detect_wildcard(base)
        if wildcard_reason is not None:
            logger.info(
                "Skipping %s — %s. Results would be 100%% false positives.",
                host, wildcard_reason
            )
            return []

        found_paths = []
        urls = [f"{base}/{path}" for path in self.wordlist]

        # --- Parallel probing across paths for this host ---
        # Using a small pool per host (not global) so we don't open hundreds
        # of connections simultaneously across all hosts.
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._probe_with_delay, url): url for url in urls}
            for future in as_completed(futures):
                url, result = future.result()
                if result is None:
                    continue
                status, size = result
                if status in (200, 403):
                    # Only report 200 and 403 — these indicate the path
                    # definitively exists. We intentionally drop 301/302 here
                    # because after wildcard filtering, remaining redirects
                    # are ambiguous and not actionable without following them.
                    path = "/" + url.replace(base + "/", "")
                    found_paths.append({"path": path, "status": status, "size": size})

        return found_paths
