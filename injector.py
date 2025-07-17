import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class Injector:
    """
    Helper module for injecting payloads into forms.
    Useful for XSS, SQLi, Command Injection, etc.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()

    def test_payload(self, page_url, form_html, payload):
        """
        Inject a payload into all suitable form fields and submit.
        """
        soup = BeautifulSoup(form_html, "html.parser")
        form = soup.find("form")

        if not form:
            print(f"[!] No form found on: {page_url}")
            return None

        action = form.get("action")
        method = form.get("method", "get").lower()
        target_url = urljoin(page_url, action) if action else page_url

        inputs = {}

        for input_tag in form.find_all(["input", "textarea"]):
            name = input_tag.get("name")
            if not name:
                continue

            input_type = input_tag.get("type", "text")

            if input_type in ["text", "search", "email", "url", "hidden"] or input_tag.name == "textarea":
                inputs[name] = payload
            else:
                # Preserve default values for other input types (e.g., submit, checkbox)
                inputs[name] = input_tag.get("value", "")

        try:
            if method == "post":
                resp = self.session.post(target_url, data=inputs, timeout=10)
            else:
                resp = self.session.get(target_url, params=inputs, timeout=10)

            print(f"[+] Injection test → URL: {target_url} | Method: {method.upper()} | Payload: {payload}")
            print(f"    Injected fields: {list(inputs.keys())}")
            return resp

        except requests.RequestException as e:
            print(f"[!] Injection request failed at {target_url}: {e}")
            return None
