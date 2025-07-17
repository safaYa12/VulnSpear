import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class IDORTester:
    """
    Advanced IDOR vulnerability tester module.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.findings = []

    def extract_ids(self, url):
        """
        Extract possible ID or resource identifiers from the URL.
        Handles numeric and UUID patterns.
        """
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        id_params = {}

        uuid_pattern = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{12}$"
        )

        for param, values in query.items():
            value = values[0]
            if any(keyword in param.lower() for keyword in ["id", "user", "account", "profile", "uid", "uuid"]):
                id_params[param] = value
            elif uuid_pattern.match(value):
                id_params[param] = value

        return parsed, id_params

    def mutate_ids(self, original_id):
        """
        Generate common ID variations for fuzzing.
        Supports numeric and UUID placeholder.
        """
        variations = []
        try:
            base = int(original_id)
            variations.extend([
                str(base + 1),
                str(base - 1 if base > 0 else 0),
                str(base + 100),
                str(base - 100 if base > 100 else 0),
                "0",
                "1",
                "9999",
                str(base * 2)
            ])
        except ValueError:
            # If it's a UUID, do simple swap (just for demonstration)
            variations.append("00000000-0000-0000-0000-000000000001")
            variations.append("11111111-1111-1111-1111-111111111111")
            # Or random other guess
            variations.append("abcdefab-cdef-abcd-efab-cdefabcdefab")
        return variations

    def test_idor(self, parsed, id_params):
        """
        Perform IDOR tests on the extracted IDs.
        Uses diff checks: status code, content length, content diff.
        """
        baseline_url = urlunparse(parsed)
        baseline_resp = self.session.get(baseline_url)
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.text)

        for param, original_id in id_params.items():
            for new_id in self.mutate_ids(original_id):
                mutated_query = parse_qs(parsed.query)
                mutated_query[param] = new_id
                new_query_encoded = urlencode(mutated_query, doseq=True)

                new_parsed = parsed._replace(query=new_query_encoded)
                test_url = urlunparse(new_parsed)

                try:
                    test_resp = self.session.get(test_url, timeout=10)
                    test_len = len(test_resp.text)

                    if test_resp.status_code == 200 and (test_resp.text != baseline_resp.text or abs(test_len - baseline_len) > 50):
                        finding = {
                            "url": test_url,
                            "vuln_type": "IDOR",
                            "param": param,
                            "original_id": original_id,
                            "test_id": new_id,
                            "severity": "High",
                            "evidence": f"Baseline len: {baseline_len}, Test len: {test_len}"
                        }
                        self.findings.append(finding)
                        print(f"[+] Possible IDOR found: {test_url}")
                except requests.RequestException as e:
                    print(f"[!] Error testing IDOR at {test_url}: {e}")

    def run(self, urls):
        """
        Run IDOR tests on a list of URLs.
        """
        for url in urls:
            parsed, id_params = self.extract_ids(url)
            if id_params:
                self.test_idor(parsed, id_params)

        return self.findings
