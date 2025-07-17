# ⚡ VulnSpear: The Offensive Security Scanner

VulnSpear is an advanced automated web application vulnerability scanner inspired by OWASP ZAP and Burp Suite, but handcrafted with Python 🐍 and Flask.

It performs dynamic security testing (DAST) against web applications, crawling and scanning them for critical vulnerabilities including:

- 🔓 **SQL Injection (SQLi)**
- 🔐 **Cross-Site Scripting (XSS)**
- 🔀 **Insecure Direct Object Reference (IDOR)**
- 📤 **Command Injection**
- 📎 **Cross-Site Request Forgery (CSRF)**
- 📥 **Server-Side Request Forgery (SSRF)**
- 🔧 **XML External Entity Injection (XXE)**
- 🔁 **OAuth Misconfigurations**
- 📂 **Path Traversal**
- 🤖 **Sensitive files exposure (robots.txt)**

---

## 🚀 Features

- ✅ Form and URL input fuzzing
- ✅ Smart payload injection
- ✅ SQL error pattern detection
- ✅ Reflective XSS payload testing
- ✅ Heuristic-based IDOR checks
- ✅ HTML Report Generation (dark-mode supported)
- ✅ Fully modular & extensible test architecture
- ✅ Logging of findings with severity grading

---

## 🛠️ Technologies Used

- Python 3.10+
- Flask (for the web interface)
- Requests + BeautifulSoup (crawler/injector)
- Bootstrap 4 (UI design)
- Jinja2 (templates)

---

## 🧪 Getting Started

### 🔧 Install Dependencies

```bash
pip install -r requirements.txt
