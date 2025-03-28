import requests
from bs4 import BeautifulSoup
import urllib.parse
import time
import logging
from typing import Optional, Callable

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class WebCrawler:
    def __init__(self, session=None):
        self.visited_urls = set()
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def fetch_page(self, url):
        """Fetch the HTML content of a page."""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
            logging.warning(f"Failed to fetch {url} (Status Code: {response.status_code})")
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
        return None

    def extract_links(self, html, base_url):
        """Extract all unique links from the HTML content."""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            link = urllib.parse.urljoin(base_url, a_tag['href'])
            if link.startswith(base_url):
                links.add(link)
        return links

    def crawl(self, url, max_depth=3, current_depth=0, 
              output_file=None, delay=1, callback: Optional[Callable] = None):
        """Recursively crawl a website with optional callback."""
        if current_depth > max_depth or url in self.visited_urls:
            return

        logging.info(f"Crawling ({current_depth}/{max_depth}): {url}")
        self.visited_urls.add(url)
        
        html = self.fetch_page(url)
        if not html:
            return

        if callback:
            callback(url)

        links = self.extract_links(html, url)
        
        if output_file:
            output_file.write(f"Depth {current_depth}: {url}\n")
            for link in links:
                output_file.write(f"  - {link}\n")
        
        for link in links:
            time.sleep(delay)
            self.crawl(link, max_depth, current_depth + 1, output_file, delay, callback)

def spider(session, url, max_depth=3, current_depth=0, output_file=None, delay=1, callback=None):
    """
    Crawl website with configurable depth and delay.
    
    Args:
        session: requests.Session object
        url: Starting URL
        max_depth: Maximum recursion depth (default: 3)
        current_depth: Current recursion depth (internal use)
        output_file: File object to write results
        delay: Seconds between requests (default: 1)
        callback: Function to call for each found URL
    """
    crawler = WebCrawler(session)
    crawler.crawl(url, max_depth, current_depth, output_file, delay, callback)

def main():
    """Standalone execution with default parameters"""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='Target website URL')
    args = parser.parse_args()

    crawler = WebCrawler()
    with open("spider_results.txt", "w") as f:
        crawler.crawl(args.url, output_file=f)

if __name__ == "__main__":
    main()