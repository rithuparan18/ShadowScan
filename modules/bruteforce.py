import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DirectoryBruter:
    def __init__(self):
        # Common sensitive paths to hunt for
        self.wordlist = [
            'admin', 'login', 'config', '.env', '.git', 
            'api', 'v1', 'v2', 'backup', 'wp-admin', 
            'dashboard', 'setup', 'phpinfo.php', 'root'
        ]

    def scan(self, host):
        found_paths = []
        for path in self.wordlist:
            url = f"https://{host}/{path}"
            try:
                # Use allow_redirects=False to catch the actual status code
                resp = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                if resp.status_code in [200, 301, 403]: # 403 often indicates a forbidden but existing directory
                    found_paths.append({"path": f"/{path}", "status": resp.status_code})
            except:
                continue
        return found_paths
