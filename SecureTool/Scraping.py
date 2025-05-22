from bs4 import BeautifulSoup
import requests
import json
import re


class Scraper:
    """
    A class used for scraping and processing web content.

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
    """

    def scrape_and_save(self, website_url, file_name="data.html"):
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

        soup = BeautifulSoup(response.content, "html5lib")
        html_content = soup.prettify()

        try:
            with open(file_name, "w", encoding="utf-8") as f:
                f.write(html_content)
        except IOError as e:
            return {"error": f"Failed to write to file: {e}"}

        return f"The data was successfully stored in {file_name}"

    def extract_links(self, website_url):
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

        soup = BeautifulSoup(response.content, "html.parser")
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        return {"links": links} if links else {"message": "No links found"}

    def save_as_json(self, website_url, file_name="output.json"):
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

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
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

        soup = BeautifulSoup(response.content, "html.parser")
        text_content = soup.get_text()

        # Split sentences using regex for better accuracy
        sentences = re.split(r"[.!?]\s+", text_content)
        matches = [s.strip() for s in sentences if keyword.lower() in s.lower()]

        return {"matches": matches[:10]} if matches else {"message": "No matches found"}

    def extract_forms(self, website_url):
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

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

    def extract_js_files(self, website_url):
        try:
            response = requests.get(website_url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": f"Failed to retrieve website: {e}"}

        soup = BeautifulSoup(response.content, "html.parser")
        scripts = [script.get("src") for script in soup.find_all("script") if script.get("src")]

        return {"js_files": scripts} if scripts else {"message": "No external JS found"}
