from bs4 import BeautifulSoup
import requests
import json
import re
import ssl
import socket
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional


class Scraper:
    """
    A class used for scraping and processing web content with security-focused features.

    Methods
    -------
    scrape_and_save(website_url, file_name="data.html")
        Scrapes the content of the given website URL and saves it to an HTML file.

    extract_links(website_url)
        Extracts all hyperlinks from the given website URL.

    save_as_json(website_url, file_name="output.json")
        Scrapes the content of the given website URL and saves it as a JSON file.

    search_in_page(website_url, keyword)
        Searches for a keyword in the content of the given website URL and returns matching sentences.

    extract_forms(website_url)
        Extracts all HTML form details (action, method, inputs) from the page.

    extract_js_files(website_url)
        Extracts all external JavaScript file URLs from the page.

    check_security_headers(website_url)
        Checks for important security headers in the HTTP response.

    extract_metadata(website_url)
        Extracts Open Graph, Twitter Cards, and other metadata from the page.

    check_ssl_certificate(website_url)
        Checks SSL/TLS certificate information and validity.

    extract_sensitive_data(website_url)
        Scans for potentially exposed sensitive information (emails, API keys, etc.).

    extract_images(website_url)
        Extracts all image URLs from the page.

    extract_css_files(website_url)
        Extracts all external CSS file URLs from the page.
    """

    def __init__(self, user_agent: Optional[str] = None, timeout: int = 10):
        """
        Initialize the Scraper with optional custom user agent and timeout.

        Parameters
        ----------
        user_agent : str, optional
            Custom user agent string. Defaults to a standard browser user agent.
        timeout : int, optional
            Request timeout in seconds. Defaults to 10.
        """
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def _make_request(self, website_url: str, **kwargs) -> Optional[requests.Response]:
        """Internal method to make HTTP requests with error handling."""
        try:
            response = self.session.get(website_url, timeout=self.timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            return None

    def scrape_and_save(self, website_url, file_name="data.html"):
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html5lib")
        html_content = soup.prettify()

        try:
            with open(file_name, "w", encoding="utf-8") as f:
                f.write(html_content)
        except IOError as e:
            return {"error": f"Failed to write to file: {e}"}

        return f"The data was successfully stored in {file_name}"

    def extract_links(self, website_url, absolute_urls=True):
        """
        Extract all hyperlinks from the given website URL.

        Parameters
        ----------
        website_url : str
            The URL of the website to scrape.
        absolute_urls : bool, optional
            If True, converts relative URLs to absolute URLs. Defaults to True.

        Returns
        -------
        dict
            Dictionary containing extracted links or error message.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if absolute_urls and href:
                href = urljoin(website_url, href)
            links.append({
                "url": href,
                "text": a.get_text(strip=True),
                "title": a.get("title", "")
            })
        return {"links": links} if links else {"message": "No links found"}

    def save_as_json(self, website_url, file_name="output.json"):
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        data = {
            "title": soup.title.string if soup.title else "No Title",
            "meta_description": (
                soup.find("meta", attrs={"name": "description"})
                ["content"] if soup.find("meta", attrs={"name": "description"}) else "No Description"
            ),
            "meta_keywords": (
                soup.find("meta", attrs={"name": "keywords"})
                ["content"] if soup.find("meta", attrs={"name": "keywords"}) else "No Keywords"
            ),
            "content": soup.get_text(separator="\n", strip=True),
            "headings": {
                "h1": [h.get_text(strip=True) for h in soup.find_all("h1")],
                "h2": [h.get_text(strip=True) for h in soup.find_all("h2")],
                "h3": [h.get_text(strip=True) for h in soup.find_all("h3")],
            }
        }

        try:
            with open(file_name, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except IOError as e:
            return {"error": f"Failed to write JSON file: {e}"}

        return f"The JSON data was successfully saved to {file_name}"

    def search_in_page(self, website_url, keyword):
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        text_content = soup.get_text()

        # Split sentences using regex for better accuracy
        sentences = re.split(r"[.!?]\s+", text_content)
        matches = [s.strip() for s in sentences if keyword.lower() in s.lower()]

        return {"matches": matches[:10]} if matches else {"message": "No matches found"}

    def extract_forms(self, website_url):
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            details = {
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            for input_tag in form.find_all("input"):
                details["inputs"].append({
                    "type": input_tag.get("type", "text"),
                    "name": input_tag.get("name")
                })
            forms.append(details)

        return {"forms": forms} if forms else {"message": "No forms found"}

    def extract_js_files(self, website_url, absolute_urls=True):
        """
        Extract all external JavaScript file URLs from the page.

        Parameters
        ----------
        website_url : str
            The URL of the website to scrape.
        absolute_urls : bool, optional
            If True, converts relative URLs to absolute URLs. Defaults to True.

        Returns
        -------
        dict
            Dictionary containing extracted JS file URLs or error message.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        scripts = []
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if absolute_urls and src:
                src = urljoin(website_url, src)
            scripts.append(src)
        return {"js_files": scripts} if scripts else {"message": "No external JS found"}

    def check_security_headers(self, website_url):
        """
        Check for important security headers in the HTTP response.

        Parameters
        ----------
        website_url : str
            The URL of the website to check.

        Returns
        -------
        dict
            Dictionary containing security headers analysis.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME type sniffing protection",
            "X-XSS-Protection": "XSS protection",
            "Content-Security-Policy": "CSP",
            "Referrer-Policy": "Referrer policy",
            "Permissions-Policy": "Permissions policy",
            "X-Permitted-Cross-Domain-Policies": "Cross-domain policy"
        }

        found_headers = {}
        missing_headers = []
        recommendations = []

        for header, description in security_headers.items():
            value = response.headers.get(header)
            if value:
                found_headers[header] = {"value": value, "description": description}
            else:
                missing_headers.append(header)
                recommendations.append(f"Missing {header} - {description}")

        security_score = len(found_headers) / len(security_headers) * 100

        return {
            "url": website_url,
            "security_score": round(security_score, 2),
            "found_headers": found_headers,
            "missing_headers": missing_headers,
            "recommendations": recommendations
        }

    def extract_metadata(self, website_url):
        """
        Extract Open Graph, Twitter Cards, and other metadata from the page.

        Parameters
        ----------
        website_url : str
            The URL of the website to scrape.

        Returns
        -------
        dict
            Dictionary containing extracted metadata.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        metadata = {
            "title": soup.title.string if soup.title else None,
            "description": None,
            "keywords": None,
            "open_graph": {},
            "twitter_card": {},
            "canonical": None
        }

        # Standard meta tags
        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag:
            metadata["description"] = desc_tag.get("content")

        keywords_tag = soup.find("meta", attrs={"name": "keywords"})
        if keywords_tag:
            metadata["keywords"] = keywords_tag.get("content")

        # Open Graph tags
        og_tags = soup.find_all("meta", attrs={"property": re.compile(r"^og:")})
        for tag in og_tags:
            prop = tag.get("property", "").replace("og:", "")
            metadata["open_graph"][prop] = tag.get("content")

        # Twitter Card tags
        twitter_tags = soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")})
        for tag in twitter_tags:
            name = tag.get("name", "").replace("twitter:", "")
            metadata["twitter_card"][name] = tag.get("content")

        # Canonical URL
        canonical = soup.find("link", attrs={"rel": "canonical"})
        if canonical:
            metadata["canonical"] = canonical.get("href")

        return metadata

    def check_ssl_certificate(self, website_url):
        """
        Check SSL/TLS certificate information and validity.

        Parameters
        ----------
        website_url : str
            The URL of the website to check.

        Returns
        -------
        dict
            Dictionary containing SSL certificate information.
        """
        try:
            parsed_url = urlparse(website_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

            if port != 443:
                return {"error": "SSL certificate check only available for HTTPS connections"}

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            return {
                "hostname": hostname,
                "port": port,
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "version": cert.get("version"),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "cipher": {
                    "name": cipher[0] if cipher else None,
                    "version": cipher[1] if cipher else None,
                    "bits": cipher[2] if cipher else None
                }
            }
        except Exception as e:
            return {"error": f"SSL certificate check failed: {str(e)}"}

    def extract_sensitive_data(self, website_url):
        """
        Scan for potentially exposed sensitive information (emails, API keys, etc.).

        Parameters
        ----------
        website_url : str
            The URL of the website to scan.

        Returns
        -------
        dict
            Dictionary containing found sensitive data patterns.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        content = response.text
        findings = {
            "emails": [],
            "api_keys": [],
            "ip_addresses": [],
            "credit_cards": [],
            "jwt_tokens": []
        }

        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        findings["emails"] = list(set(emails))[:20]  # Limit to 20 unique emails

        # API key patterns (common patterns)
        api_key_patterns = [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
            r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
            r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        ]
        for pattern in api_key_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            findings["api_keys"].extend(matches[:5])  # Limit results

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_addresses = re.findall(ip_pattern, content)
        findings["ip_addresses"] = list(set(ip_addresses))[:20]

        # Credit card pattern (basic check - may have false positives)
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        cc_matches = re.findall(cc_pattern, content)
        findings["credit_cards"] = list(set(cc_matches))[:5]

        # JWT tokens
        jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        jwt_tokens = re.findall(jwt_pattern, content)
        findings["jwt_tokens"] = list(set(jwt_tokens))[:5]

        # Remove empty findings
        findings = {k: v for k, v in findings.items() if v}

        return {
            "url": website_url,
            "findings": findings,
            "warning": "This is a basic scan. Manual verification is recommended."
        }

    def extract_images(self, website_url, absolute_urls=True):
        """
        Extract all image URLs from the page.

        Parameters
        ----------
        website_url : str
            The URL of the website to scrape.
        absolute_urls : bool, optional
            If True, converts relative URLs to absolute URLs. Defaults to True.

        Returns
        -------
        dict
            Dictionary containing extracted image URLs.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        images = []
        for img in soup.find_all("img"):
            src = img.get("src") or img.get("data-src")
            if src:
                if absolute_urls:
                    src = urljoin(website_url, src)
                images.append({
                    "url": src,
                    "alt": img.get("alt", ""),
                    "title": img.get("title", "")
                })
        return {"images": images} if images else {"message": "No images found"}

    def extract_css_files(self, website_url, absolute_urls=True):
        """
        Extract all external CSS file URLs from the page.

        Parameters
        ----------
        website_url : str
            The URL of the website to scrape.
        absolute_urls : bool, optional
            If True, converts relative URLs to absolute URLs. Defaults to True.

        Returns
        -------
        dict
            Dictionary containing extracted CSS file URLs.
        """
        response = self._make_request(website_url)
        if not response:
            return {"error": f"Failed to retrieve website: {website_url}"}

        soup = BeautifulSoup(response.content, "html.parser")
        css_files = []
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href")
            if href:
                if absolute_urls:
                    href = urljoin(website_url, href)
                css_files.append(href)
        return {"css_files": css_files} if css_files else {"message": "No external CSS found"}
