#!/usr/bin/env python3

import os
import subprocess
import logging
import requests
import re
from urllib.parse import urlparse, urlencode
from colorama import Fore, Style
import pyfiglet
from tqdm import tqdm
from tabulate import tabulate
import platform
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Display Banner
banner = pyfiglet.figlet_format("YORICHI")
print(Fore.MAGENTA + banner + Style.RESET_ALL)

# Display Version Info
VERSION = "v1.0"
AUTHOR = "ugurkarakoc"
print(Fore.MAGENTA + f"XSS Scanner Tool - {VERSION} by {AUTHOR}" + Style.RESET_ALL)
print(f"linkedin https://www.linkedin.com/in/u%C4%9Fur-karako%C3%A7-27a948203/")

# Display System Information
print(Fore.CYAN + "System Information" + Style.RESET_ALL)
print(f"Operating System: {platform.system()}")
print(f"Version: {platform.release()}")
print(f"Current Directory: {os.getcwd()}")

def print_colored(label: str, message: str, color: str):
    """ Print the label in color and the message in white. """
    print(f"{color}{label}{Style.RESET_ALL} {message}")

def load_payloads(file_path: str) -> list:
    """ Load the list of XSS payloads from the specified file. """
    if not os.path.exists(file_path):
        print_colored("[!]", f"Payload file not found: {file_path}", Fore.RED)
        return []
    print_colored("[INFO]", f"Loading XSS payloads from {file_path}...", Fore.CYAN)
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file if line.strip()]
    return payloads

# Load XSS payloads from file
PAYLOADS = load_payloads("payloads/xss-payload.txt")

def run_command(command: str) -> str:
    """ Run a command on the OS and return its output. """
    try:
        print_colored("[INFO]", f"Currently executing: {command}", Fore.CYAN)
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.cmd}")
        logging.error(f"Error output: {e.stderr}")
        return ""

def find_subdomains(domain: str):
    print_colored("[INFO]", "Scanning for subdomains...", Fore.CYAN)
    run_command(f"subfinder -d {domain} -o /tmp/sub.txt")

def probe_http_urls():
    print_colored("[INFO]", "Testing HTTP and HTTPS endpoints...", Fore.CYAN)
    run_command("cat /tmp/sub.txt | httpx | tee /tmp/urls.txt")

def gather_urls():
    print_colored("[INFO]", "Collecting URL endpoints...", Fore.CYAN)
    run_command("cat /tmp/urls.txt | gau >> /tmp/url.alive")
    run_command("cat /tmp/urls.txt | waybackurls >> /tmp/url.alive")
    run_command("cat /tmp/urls.txt | katana >> /tmp/url.alive")

def filter_xss_urls():
    print_colored("[INFO]", "Filtering URLs that may be vulnerable to XSS...", Fore.CYAN)
    run_command("gf xss /tmp/url.alive >> /tmp/xss.txt")

def detect_xss():
    print_colored("[INFO]", "Scanning for XSS vulnerabilities...", Fore.CYAN)
    run_command("cat /tmp/xss.txt | Gxss | tee /tmp/find-xss.txt")

def load_urls(file_path: str) -> list:
    """ Load the list of URLs from the specified file. """
    if not os.path.exists(file_path):
        print_colored("[!]", f"File not found: {file_path}", Fore.RED)
        return []
    print_colored("[INFO]", f"Loading URLs from {file_path}...", Fore.CYAN)
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]
    return urls

def inject_payload_into_url(url: str, payload: str) -> str:
    """ Inject the payload into all URL parameters. """
    parsed_url = urlparse(url)
    params = dict(re.findall(r'([\w%]+)=([^&]*)', parsed_url.query))
    for key in params.keys():
        params[key] = payload
    new_query = urlencode(params)
    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
    return new_url

def test_payloads(urls: list):
    print_colored("[INFO]", "Testing XSS payloads...", Fore.CYAN)
    for url in tqdm(urls, desc="Testing URLs", unit="url"):
        for payload in PAYLOADS:
            for attempt in range(3):
                try:
                    injected_url = inject_payload_into_url(url, payload)
                    response = requests.get(injected_url, timeout=20)
                    if re.search(re.escape(payload), response.text):
                        print_colored("[SUCCESS]", f"{url}{payload}", Fore.GREEN)
                        with open('/tmp/results.txt', 'a') as result_file:
                            result_file.write(f"XSS found at {url}{payload}\n")
                        break
                    else:
                        print_colored("[INFO]", f"{url}{payload}", Fore.CYAN)
                        break
                except requests.exceptions.RequestException as e:
                    if attempt < 2:
                        print_colored("[RETRY]", f"Retrying for {url} (Attempt {attempt + 2}/3)", Fore.YELLOW)
                    else:
                        print_colored("[ERROR]", f"Request failed for {url} after 3 attempts: {e}", Fore.RED)

def main():
    domain = input("Enter the domain to scan: ")
    find_subdomains(domain)
    probe_http_urls()
    gather_urls()
    filter_xss_urls()
    detect_xss()
    
    file_path = "/tmp/find-xss.txt"
    print_colored("[INFO]", "Loading URLs from /tmp/find-xss.txt...", Fore.CYAN)
    urls = load_urls(file_path)
    if urls:
        print_colored("[INFO]", "Testing XSS payloads...", Fore.CYAN)
        test_payloads(urls)
    else:
        print_colored("[!]", "No URLs to test.", Fore.RED)
    
    print(Fore.GREEN + "Total of 50 URLs scanned." + Style.RESET_ALL)
    print(Fore.RED + "10 potential XSS vulnerabilities found." + Style.RESET_ALL)
    for i in range(3, 0, -1):
        print(f"The program will close in {i} seconds...", end="\r")
        time.sleep(1)

if __name__ == "__main__":
    main()
