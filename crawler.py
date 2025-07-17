import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class Crawler:
    """
    Smart crawler to discover pages & forms within the same domain.
    """

    def __init__(self, base_url, max_pages=30, user_agent="Mozilla/5.0 (OWASP-Scanner)"):
        self.base_url = base_url.rstrip("/")
        self.visited = set()
        self.to_visit = [self.base_url]
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent
        })
        self.forms_found = []

    def is_valid_url(self, url):
        """
        Only crawl links within the same domain.
        """
        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return parsed_base.netloc == parsed_url.netloc

    def extract_links(self, soup, current_url):
        """
        Extract all <a href> links and resolve relative paths.
        """
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(current_url, href)
            if self.is_valid_url(full_url):
                links.append(full_url)
        return links

    def extract_forms(self, soup, current_url):
        """
        Extract all forms on the page with their action, method, and inputs.
        """
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = []

            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                inputs.append({"name": input_name, "type": input_type})

            forms.append({
                "url": current_url,
                "action": action,
                "method": method,
                "inputs": inputs,
                "form_html": str(form)  # ✅ Keep raw HTML for XSS/CSRF/Injector
            })

        return forms

    def crawl(self):
        """
        Crawl pages up to max_pages, collecting unique URLs & forms.
        """
        pages_crawled = 0
        url_list = []
        forms_list = []

        while self.to_visit and pages_crawled < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue

            try:
                resp = self.session.get(url, timeout=10)
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    print(f"[i] Skipping non-HTML: {url} ({content_type})")
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract forms
                forms = self.extract_forms(soup, url)
                forms_list.extend(forms)

                # Extract links
                new_links = self.extract_links(soup, url)
                for link in new_links:
                    if link not in self.visited and link not in self.to_visit:
                        self.to_visit.append(link)

                self.visited.add(url)
                url_list.append(url)
                pages_crawled += 1

                print(f"[+] Crawled: {url} | New forms: {len(forms)} | Queue: {len(self.to_visit)}")

            except requests.RequestException as e:
                print(f"[!] Error crawling {url}: {e}")

        print(f"✅ Crawl complete: {pages_crawled} pages crawled, {len(forms_list)} forms found.")
        return url_list, forms_list

