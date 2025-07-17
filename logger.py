import os
import json
from datetime import datetime


class VulnerabilityLogger:
    """
    Handles logging and saving vulnerability findings,
    and generates simple HTML reports.
    """

    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.vulnerabilities = []

    def log_vulnerability(self, vuln_data):
        """
        Add a single vulnerability finding to memory and persist to disk.
        """
        self.vulnerabilities.append(vuln_data)
        print(f"[+] Vulnerability logged: {vuln_data.get('vuln_type', 'Unknown')} at {vuln_data.get('url', 'N/A')}")
        self._save_to_file(vuln_data)

    def _save_to_file(self, vuln_data):
        """
        Save the vulnerability data to a timestamped JSON log file.
        """
        timestamp = datetime.now().strftime("%Y%m%d")
        filename = os.path.join(self.log_dir, f"scan_{timestamp}.json")

        if os.path.exists(filename):
            with open(filename, "r+", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
                data.append(vuln_data)
                f.seek(0)
                json.dump(data, f, indent=4)
        else:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump([vuln_data], f, indent=4)

    def load_logged_vulnerabilities(self):
        """
        Load all logged vulnerabilities from today's scan file.
        """
        timestamp = datetime.now().strftime("%Y%m%d")
        filename = os.path.join(self.log_dir, f"scan_{timestamp}.json")
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
                return data
        else:
            return []

    def generate_report(self, output="templates/report.html"):
        """
        Generate a simple HTML report from all stored vulnerabilities.
        """
        html = "<h1>Vulnerability Scan Report</h1>\n"
        html += f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n"
        html += "<table border='1' cellpadding='5'>"
        html += "<tr><th>URL</th><th>Vulnerability</th><th>Severity</th><th>Evidence</th></tr>"

        for vuln in self.vulnerabilities:
            html += f"<tr><td>{vuln.get('url', '')}</td>"
            html += f"<td>{vuln.get('vuln_type', '')}</td>"
            html += f"<td>{vuln.get('severity', '')}</td>"
            html += f"<td><pre>{vuln.get('evidence', '')}</pre></td></tr>"

        html += "</table>"

        with open(output, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] Report generated: {output}")

    def clear_session(self):
        """
        Clear in-memory vulnerabilities for a new scan session.
        """
        self.vulnerabilities = []
