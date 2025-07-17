from flask import Flask, render_template, request
import datetime

from crawler import Crawler
from logger import VulnerabilityLogger

# ✅ Create logger ONCE for the whole app session
logger = VulnerabilityLogger()

# ✅ Import all test modules
from modules.test_idor import IDORTester
from modules.test_csrf import CSRFTester
from modules.test_ssrf import SSRFTester
from modules.test_oauth import OAuthTester
from modules.test_sql import SQLiTester
from modules.test_xss import XSSTester
from modules.test_command_injection import CommandInjectionTester
from modules.test_path_traversal import PathTraversalTester
from modules.test_xxe import XXETester
from modules.test_robots import RobotsTester

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    errors = []

    if request.method == "POST":
        target_url = request.form.get("url", "").strip()
        if not target_url or not target_url.startswith("http"):
            errors.append("Please provide a valid URL starting with http or https.")
            return render_template("index.html", results=None, errors=errors)

        # Crawl
        crawler = Crawler(target_url, max_pages=30)
        url_list, forms_list = crawler.crawl()

        if not url_list and not forms_list:
            errors.append(f"No forms or endpoints found for {target_url}.")
            return render_template("index.html", results=None, errors=errors)

        try:
            # Clear previous session data
            logger.clear_session()

            # 🔍 Run each tester module
            testers = [
                (IDORTester(), url_list, "IDOR", "High"),
                (CSRFTester(), forms_list, "CSRF", "High"),
                (SSRFTester(), url_list, "SSRF", "Critical"),
                (OAuthTester(), url_list, "OAuth Misconfig", "High"),
                (SQLiTester(), url_list, "SQL Injection", "Critical"),
                (XSSTester(), (url_list, forms_list), "XSS", "High"),
                (CommandInjectionTester(), url_list, "Command Injection", "Critical"),
                (PathTraversalTester(), url_list, "Path Traversal", "High"),
                (XXETester(), url_list, "XXE", "Critical"),
                (RobotsTester(), [target_url], "Sensitive File Exposure", "Medium"),
            ]

            for tester, input_data, vuln_type, severity in testers:
                if isinstance(input_data, tuple):
                    findings = tester.run(*input_data)
                else:
                    findings = tester.run(input_data)
                for vuln in findings:
                    vuln.setdefault("vuln_type", vuln_type)
                    vuln.setdefault("severity", severity)
                    logger.log_vulnerability(vuln)
                    results.append(vuln)

        except Exception as e:
            errors.append(f"Error running modules: {str(e)}")

        return render_template("index.html", results=results, errors=errors)

    return render_template("index.html", results=None, errors=None)


@app.route("/report")
def report():
    try:
        results = logger.load_logged_vulnerabilities()
    except Exception:
        results = []
    return render_template("report.html", results=results, now=datetime.datetime.now)


if __name__ == "__main__":
    app.run(debug=True)

