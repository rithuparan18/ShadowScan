import re
import requests
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("shadowscan.secrets")


class SecretFinder:
    def __init__(self):
        self.patterns = {
            "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
            "AWS Access Key ID":    r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9A-Za-z/+]{40}['\"]",
            "Firebase URL":         r"[a-z0-9-]+\.firebaseio\.com",
            "Slack Webhook":        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
            "Discord Webhook":      r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            "JWT Token":            r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "GitHub Token":         r"gh[pousr]_[A-Za-z0-9]{36}",
            "Stripe Secret Key":    r"sk_live_[0-9A-Za-z]{24,}",
            "Stripe Public Key":    r"pk_live_[0-9A-Za-z]{24,}",
            "SendGrid API Key":     r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
            "Mailgun API Key":      r"key-[0-9a-zA-Z]{32}",
            "Twilio Account SID":   r"AC[a-z0-9]{32}",
            "RSA Private Key":      r"-----BEGIN RSA PRIVATE KEY-----",
            "Generic Private Key":  r"-----BEGIN PRIVATE KEY-----",
        }

    def _get_js_links(self, base_url, html_content):
        js_links = []
        for match in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html_content):
            src = match.group(1)
            if src.startswith("http"):
                js_links.append(src)
            elif src.startswith("//"):
                js_links.append("https:" + src)
            elif src.startswith("/"):
                js_links.append(base_url.rstrip("/") + src)
        return js_links[:10]

    def _scan_content(self, content):
        findings = []
        for name, pattern in self.patterns.items():
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    findings.append({"type": name, "value": match[:120]})
            except re.error as e:
                logger.error("Regex error in pattern '%s': %s", name, e)
        return findings

    def _fetch(self, url):
        """
        Fetch a URL. Returns response text, or None on any failure.
        Critically: 404 is NOT an error — it's expected and logged at debug.
        Only genuine network/server failures are logged at warning+.
        """
        try:
            resp = requests.get(url, timeout=5, verify=False)
            # 404 / 403 / 401 are expected — not errors. Return None quietly.
            if resp.status_code in (404, 403, 401, 503):
                logger.debug("Skipping %s — HTTP %d", url, resp.status_code)
                return None
            # For anything unexpected (500, etc.) log at warning
            if resp.status_code >= 400:
                logger.warning("Unexpected HTTP %d for %s", resp.status_code, url)
                return None
            return resp.text
        except requests.exceptions.Timeout:
            logger.warning("Timeout scanning %s", url)
            return None
        except requests.exceptions.SSLError:
            logger.debug("SSL error scanning %s — skipping", url)
            return None
        except requests.exceptions.ConnectionError:
            logger.debug("Connection refused for %s — host may be down", url)
            return None
        except requests.exceptions.RequestException as e:
            logger.warning("Request failed for %s: %s", url, e)
            return None

    def scan_url(self, host):
        base_url = f"https://{host}"
        all_secrets = []

        html_content = self._fetch(base_url)
        if html_content is None:
            return []

        all_secrets.extend(self._scan_content(html_content))

        for js_url in self._get_js_links(base_url, html_content):
            js_content = self._fetch(js_url)
            if js_content:
                all_secrets.extend(self._scan_content(js_content))

        # Deduplicate
        seen = set()
        unique = []
        for s in all_secrets:
            key = (s["type"], s["value"])
            if key not in seen:
                seen.add(key)
                unique.append(s)

        return unique
