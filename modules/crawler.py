import requests
from bs4 import BeautifulSoup
import urllib.parse
import time
import logging
import json
import networkx as nx
import matplotlib.pyplot as plt
import requests.packages.urllib3  # added to disable warnings

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Set of visited URLs to avoid duplicates
visited_urls = set()

def fetch_page(session, url):
    """Fetch the HTML content of a page using session for reusability."""
    try:
        response = session.get(url, timeout=5, verify=False)  # Added verify=False to bypass SSL verification
        if response.raise_for_status() is None:  # Check if response is OK
            return response.text
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
    return None

def extract_links(html, base_url):
    """Extract all unique links from the HTML content."""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = urllib.parse.urljoin(base_url, a_tag['href'])  # Convert relative to absolute URL
        if link.startswith(base_url) and link not in visited_urls:  # Only follow internal links
            links.add(link)
    return links

def spider(session, url, max_depth=3, current_depth=0, results=None, delay=1, callback=None):
    """Recursively crawl a website up to a max depth and store results in JSON format."""
    if results is None:
        results = {}
    
    if current_depth > max_depth or url in visited_urls:
        return results

    logging.info(f"[+] Crawling ({current_depth}/{max_depth}): {url}")
    visited_urls.add(url)
    if callback:
        callback(url)
    
    html = fetch_page(session, url)
    if not html:
        return results

    links = list(extract_links(html, url))
    results[url] = links  # Store results in dictionary format
    
    for link in links:
        time.sleep(delay)  # Be polite, avoid overloading the server
        spider(session, link, max_depth, current_depth + 1, results, delay, callback)
    
    return results

def save_results(results):
    """Save crawl results to a JSON file."""
    with open("spider_results.json", "w") as outfile:
        json.dump(results, outfile, indent=4)
    logging.info("[✔] Crawl results saved to 'spider_results.json'.")

def visualize_results(results, output_filename="crawl_map.png"):
    """Visualize crawl results as a graph and save as an image."""
    G = nx.DiGraph()

    for parent, children in results.items():
        G.add_node(parent)
        for child in children:
            G.add_node(child)
            G.add_edge(parent, child)

    # Draw the graph
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.2)
    nx.draw(G, pos, with_labels=True, node_size=500, node_color="skyblue", font_size=8, edge_color="gray")
    plt.title("Website Crawl Structure")
    plt.axis("off")

    # Save the graph as a file (PNG/JPG)
    plt.savefig(output_filename, format="png", dpi=300)  # Change "png" to "jpg" if needed
    logging.info(f"[✔] Crawl map saved as '{output_filename}'")

    # Show the graph (optional)
    plt.show()
