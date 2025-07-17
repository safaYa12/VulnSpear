import requests
from bs4 import BeautifulSoup


class CSRFTester:
    """
    Advanced tester for detecting possible CSRF vulnerabilities.
    Checks for missing tokens, unsafe methods, and state-changing operations.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

    def has_csrf_token(self, form):
        """
        Checks if a form has a CSRF token-like input.
        """
        for input_tag in form.find_all("input"):
            name = input_tag.get("name", "").lower()
            if "csrf" in name or "token" in name:
                return True
        return False

    def is_state_changing(self, form):
        """
        Heuristic: If the form uses POST or has suspicious actions like 'update', 'delete'.
        """
        action = form.get("action", "").lower()
        method = form.get("method", "get").lower()
        state_keywords = ["update", "delete", "edit", "submit", "change"]

        if method == "post":
            return True
        if any(keyword in action for keyword in state_keywords):
            return True
        return False

    def test_form(self, url, form_html):
        """
        Tests if the form is missing CSRF tokens or uses unsafe methods.
        """
        soup = BeautifulSoup(form_html, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            method = form.get("method", "get").lower()

            if method == "get" and self.is_state_changing(form):
                vuln = {
                    "url": url,
                    "vuln_type": "CSRF (Unsafe Method)",
                    "severity": "Medium",
                    "evidence": f"Form uses GET for state-changing action: {str(form)[:200]}"
                }
                self.vulnerable.append(vuln)
                print(f"[+] Possible CSRF (unsafe method) at: {url}")

            if self.is_state_changing(form) and not self.has_csrf_token(form):
                vuln = {
                    "url": url,
                    "vuln_type": "CSRF (Missing Token)",
                    "severity": "High",
                    "evidence": f"Form lacks CSRF token: {str(form)[:200]}"
                }
                self.vulnerable.append(vuln)
                print(f"[+] Possible CSRF (missing token) at: {url}")

    def run(self, forms):
        """
        Run CSRF checks for all crawled forms.
        """
        for form_info in forms:
            self.test_form(form_info['url'], form_info['form_html'])
        return self.vulnerable

