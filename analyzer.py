import re


class Analyzer:
    """
    Analyzer class for detecting evidence of various vulnerabilities
    from HTTP responses and test module results.
    """

    def __init__(self):
        # Known database error patterns for SQL Injection detection
        self.db_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"native client",
            r"PG::SyntaxError",
            r"ORA-\d{5}",  # Oracle generic pattern
            r"PostgreSQL.*ERROR",
            r"SQLite/JDBCDriver",
        ]

    def detect_xss(self, response, payload):
        """
        Detect Reflected XSS by verifying if payload is echoed back.
        """
        if response and payload in response.text:
            print(f"[+] XSS Detected: Payload reflected → {payload}")
            return True
        return False

    def detect_sqli(self, response):
        """
        Look for known DB error patterns in the response.
        """
        if response:
            for pattern in self.db_error_patterns:
                if re.search(pattern, response.text, re.I):
                    print(f"[+] SQLi Detected: Found DB error pattern → {pattern}")
                    return True
        return False

    def detect_idor(self, idor_results):
        """
        Pass through possible IDOR findings for logging.
        """
        if idor_results:
            for result in idor_results:
                print(f"[+] Possible IDOR Detected → URL: {result.get('url')}")
        return idor_results or []

    def detect_os_command_injection(self, response, delay_threshold=5):
        """
        Detect possible OS Command Injection by response delays.
        """
        if response and response.elapsed.total_seconds() >= delay_threshold:
            print(f"[+] Possible OS Command Injection: Response delayed {response.elapsed.total_seconds()}s")
            return True
        return False

    def detect_ssrf(self, response):
        """
        Placeholder for SSRF detection.
        Extend this with advanced checks: IP leak, DNS exfil, or OOB.
        """
        return False

    def detect_xxe(self, response):
        """
        Placeholder for XXE detection.
        Extend this with local file read checks or OOB detection.
        """
        return False
