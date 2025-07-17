import requests
from urllib.parse import urljoin


class RobotsTester:
    """
    Advanced tester for analyzing robots.txt for sensitive disallowed paths.
    Also attempts to probe discovered paths for accidental public access.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerable = []

        # Keywords that suggest sensitive or hidden content, including WordPress paths
        self.sensitive_keywords = [
            "admin", "wp-admin", "wp-login", "backup", "config", "private",
            "hidden", "db", "logs", "test", "dev", "secret", "password"
        ]

    def probe_path(self, base_url, path):
        """
        Try to access the disallowed path to check if it's publicly accessible.
        """
        probe_url = urljoin(base_url, path)
        try:
            resp = self.session.get(probe_url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 50:
                print(f"[!] Disallowed path appears accessible: {probe_url}")
                return True
        except requests.RequestException:
            pass
        return False

    def run(self, base_url):
        """
        Fetch robots.txt and check for sensitive disallowed paths.
        """
        robots_url = urljoin(base_url, "/robots.txt")

        try:
            resp = self.session.get(robots_url, timeout=10)
            if resp.status_code == 200:
                disallowed_paths = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        disallowed_paths.append(path)

                        matches = [
                            kw for kw in self.sensitive_keywords if kw in path.lower()
                        ]

                        if matches:
                            accessible = self.probe_path(base_url, path)

                            vuln = {
                                "url": robots_url,
                                "disallowed_path": path,
                                "vuln_type": "Sensitive Path in robots.txt",
                                "severity": "High" if accessible else ("Medium" if len(matches) == 1 else "High"),
                                "evidence": f"Disallow: {path} | Matched: {', '.join(matches)}"
                            }

                            if accessible:
                                vuln["vuln_type"] += " (Accessible!)"
                                vuln["evidence"] += " | Path accessible to public"

                            self.vulnerable.append(vuln)
                            print(f"[+] Sensitive robots.txt entry: {path} (matched: {', '.join(matches)})")

                if not disallowed_paths:
                    print(f"[i] robots.txt found at {robots_url} but no disallowed paths.")
            else:
                print(f"[i] robots.txt not found at {robots_url} (status: {resp.status_code})")

        except requests.RequestException as e:
            print(f"[!] Error fetching robots.txt at {robots_url}: {e}")

        return self.vulnerable


