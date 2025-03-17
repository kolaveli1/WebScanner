import requests
from bs4 import BeautifulSoup
import argparse
import colorama
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse

colorama.init(autoreset=True)

vulnerabilities = []

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy"
]


SQL_PAYLOADS = ["' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*"]


XSS_PAYLOADS = ['<script>alert("XSS")</script>', '" onmouseover="alert(\'XSS\')']


DIR_TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "../windows/win.ini"]


COMMON_ADMIN_PATHS = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]


OPEN_REDIRECT_PAYLOADS = ["http://evil.com", "//evil.com"]


def scan_url(url):
    print(f"{Fore.CYAN}Scanning {url}...{Style.RESET_ALL}")
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Fejl: {e}{Style.RESET_ALL}")
        return

    scan_headers(response.headers)  
    scan_forms(url, response.text) 
    scan_open_redirect(url) 
    scan_directory_traversal(url) 
    scan_admin_panels(url) 
    check_sensitive_files(url) 

    print_scan_summary()


def scan_headers(headers):
    print(f"\n{Fore.BLUE}Scanner HTTP-headers...{Style.RESET_ALL}")

    for header in SECURITY_HEADERS:
        if header in headers:
            print(f"{Fore.GREEN}[OK] {header}: {headers[header]}{Style.RESET_ALL}")
        else:
            msg = f"[VULN] {header} mangler"
            vulnerabilities.append(msg)
            print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


def scan_forms(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all("form")

    if not forms:
        print(f"{Fore.YELLOW}Ingen formularer fundet. SQLi og XSS tests blev ikke kørt.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}Fundet {len(forms)} formular(er). Scanner for sårbarheder...{Style.RESET_ALL}")

    for form in forms:
        scan_form(url, form)


def scan_form(url, form):
    action = form.get("action")
    full_url = urljoin(url, action) if action else url
    inputs = form.find_all("input")

    for input_tag in inputs:
        input_name = input_tag.get("name")

        if input_name:
            print(f"\nTester inputfelt: {Fore.YELLOW}{input_name}{Style.RESET_ALL}")

            for payload in SQL_PAYLOADS:
                test_data = {input_name: payload}
                if send_request(full_url, test_data, "SQLi"):
                    msg = f"[VULN] SQL Injection fundet i '{input_name}' Payload: {payload}"
                    vulnerabilities.append(msg)
                    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")

            for payload in XSS_PAYLOADS:
                test_data = {input_name: payload}
                if send_request(full_url, test_data, "XSS"):
                    msg = f"[VULN] XSS fundet i '{input_name}' Payload: {payload}"
                    vulnerabilities.append(msg)
                    print(f"{Fore.RED}{msg}{Style.RESET_ALL}")


def send_request(url, data, test_type):
    try:
        response = requests.post(url, data=data, timeout=5)
        if test_type == "SQLi":
            return any(payload in response.text for payload in SQL_PAYLOADS)
        elif test_type == "XSS":
            return any(payload in response.text for payload in XSS_PAYLOADS)
    except requests.exceptions.RequestException:
        return False


def scan_open_redirect(url):
    print(f"\n{Fore.BLUE}Tester for Open Redirects...{Style.RESET_ALL}")

    for payload in OPEN_REDIRECT_PAYLOADS:
        test_url = f"{url}?redirect={payload}"
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=True)
            if response.status_code == 200 and response.url.startswith(payload):
                msg = f"[VULN] Open Redirect fundet: {test_url}"
                vulnerabilities.append(msg)
                print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            continue


def scan_directory_traversal(url):
    print(f"\n{Fore.BLUE}Tester for Directory Traversal...{Style.RESET_ALL}")

    for payload in DIR_TRAVERSAL_PAYLOADS:
        test_url = f"{url}/{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text or "Windows" in response.text:
                msg = f"[VULN] Directory Traversal fundet: {test_url}"
                vulnerabilities.append(msg)
                print(f"{Fore.RED}{msg}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            continue


def scan_admin_panels(url):
    print(f"\n{Fore.BLUE}Søger efter admin-paneler...{Style.RESET_ALL}")

    for path in COMMON_ADMIN_PATHS:
        test_url = urljoin(url, path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.YELLOW}[INFO] Muligt admin-panel fundet: {test_url}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            continue


def check_sensitive_files(url):
    print(f"\n{Fore.BLUE}Checker efter følsomme filer (.git, .env)...{Style.RESET_ALL}")
    sensitive_files = [".git/", ".env"]

    for file in sensitive_files:
        test_url = urljoin(url, file)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.RED}[VULN] Følsom fil fundet: {test_url}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            continue


def print_scan_summary():
    print("\nScan færdig")
    if vulnerabilities:
        print("\nFundne sårbarheder:")
        for vuln in vulnerabilities:
            print(f"{Fore.RED}{vuln}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN} Ingen kritiske sårbarheder fundet{Style.RESET_ALL}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="URL på den side, der skal scannes")
    args = parser.parse_args()

    scan_url(args.url)
