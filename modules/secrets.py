import re
import requests
import urllib3

# Suppress InsecureRequestWarning for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecretFinder:
    def __init__(self):
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Firebase URL": r".*firebaseio\.com",
            "Slack Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }

    def scan_url(self, url):
        found_secrets = []
        try:
            # verify=False is used to ensure we scan even with SSL errors
            response = requests.get(f"https://{url}", timeout=5, verify=False)
            content = response.text
            
            for name, pattern in self.patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    found_secrets.append({"type": name, "value": match})
            return found_secrets
        except:
            return []
