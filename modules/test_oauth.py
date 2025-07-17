import requests
from urllib.parse import urlparse, parse_qs


class OAuthTester:
    """
    Advanced tester for common OAuth misconfigurations:
    - Insecure or wildcard redirect_uri
    - Token/code leakage in URL
    - Missing 'state' parameter for CSRF
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

    def is_wildcard_redirect(self, redirect_uri):
        """
        Detects open wildcards in redirect_uri.
        """
        if "*" in redirect_uri or redirect_uri.endswith(".com") and "://" not in redirect_uri:
            return True
        return False

    def run(self, url_list):
        """
        Scan URLs for OAuth flows.
        """
        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            if any(p in query_params for p in ['redirect_uri', 'code', 'access_token', 'client_id']):
                print(f"[+] Possible OAuth flow found: {url}")

                # Check insecure redirect_uri
                redirect_uris = query_params.get('redirect_uri', [])
                for redirect_uri in redirect_uris:
                    if redirect_uri.startswith("http://"):
                        vuln = {
                            "url": url,
                            "param": "redirect_uri",
                            "vuln_type": "Insecure Redirect URI",
                            "severity": "High",
                            "evidence": redirect_uri
                        }
                        self.vulnerable.append(vuln)
                        print(f"[!] Insecure redirect_uri found: {redirect_uri}")

                    elif self.is_wildcard_redirect(redirect_uri):
                        vuln = {
                            "url": url,
                            "param": "redirect_uri",
                            "vuln_type": "Open Redirect (Wildcard)",
                            "severity": "High",
                            "evidence": redirect_uri
                        }
                        self.vulnerable.append(vuln)
                        print(f"[!] Wildcard redirect_uri found: {redirect_uri}")

                # Check for code/token in URL
                for param in ['code', 'access_token']:
                    if param in query_params:
                        vuln = {
                            "url": url,
                            "param": param,
                            "vuln_type": f"Sensitive {param} in URL",
                            "severity": "Medium",
                            "evidence": f"Leaked {param} in query string"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[!] OAuth {param} leaking in URL: {url}")

                # Check for missing state parameter (anti-CSRF)
                if 'code' in query_params and 'state' not in query_params:
                    vuln = {
                        "url": url,
                        "param": "state",
                        "vuln_type": "Missing state parameter (OAuth CSRF)",
                        "severity": "High",
                        "evidence": "OAuth code flow without state param"
                    }
                    self.vulnerable.append(vuln)
                    print(f"[!] Missing state parameter: {url}")

        return self.vulnerable
