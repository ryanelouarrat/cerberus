import builtwith
import whois
import urllib.request
import ssl
from colorama import Fore, Style

def get_technologies(url):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disables certificate verification

        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        urllib.request.install_opener(opener)

        tech_info = builtwith.builtwith(url)
        
        if tech_info:
            formatted_output = "\n".join([f"{Fore.GREEN}{key.capitalize()}:{Style.RESET_ALL} {', '.join(value)}" for key, value in tech_info.items()])
            return formatted_output
        else:
            return "No technology information found."
    except Exception as e:
        return f"Error fetching technologies: {e}"

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        formatted_output = f"""
{Fore.GREEN}Domain Name:{Style.RESET_ALL} {info.domain_name}
{Fore.GREEN}Registrar:{Style.RESET_ALL} {info.registrar}
{Fore.GREEN}Creation Date:{Style.RESET_ALL} {info.creation_date}
{Fore.GREEN}Expiration Date:{Style.RESET_ALL} {info.expiration_date}
{Fore.GREEN}Name Servers:{Style.RESET_ALL} {', '.join(info.name_servers) if info.name_servers else 'N/A'}
{Fore.GREEN}Status:{Style.RESET_ALL} {info.status}
{Fore.GREEN}Emails:{Style.RESET_ALL} {', '.join(info.emails) if info.emails else 'N/A'}
"""
        return formatted_output
    except Exception as e:
        return f"Error fetching WHOIS info: {e}"

def main(url=None):
    if url is None:
        url = input(Fore.CYAN + "Enter URL (e.g., https://example.com): " + Style.RESET_ALL)
    domain = url.split("//")[-1].split("/")[0]

    print(Fore.YELLOW + "\n[+] Gathering BuiltWith Information..." + Style.RESET_ALL)
    print(get_technologies(url))

    print(Fore.YELLOW + "\n[+] Gathering WHOIS Information..." + Style.RESET_ALL)
    print(get_whois_info(domain))

if __name__ == "__main__":
    main()
