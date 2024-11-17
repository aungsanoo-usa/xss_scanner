import os
import sys
import subprocess
import time
import logging
import argparse
import random
import urllib3
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from rich.console import Console
from rich import print as rprint
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from webdriver_manager.chrome import ChromeDriverManager
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

# List of user agents to choose from
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

# Initialize console for formatted output
console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check and install missing packages
def check_and_install_packages(packages):
    for package, version in packages.items():
        try:
            __import__(package)
        except ImportError:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

# Ensure required packages are installed
check_and_install_packages({"prompt_toolkit": "3.0.20", "rich": "10.7.0", "selenium": "3.141.0"})

def get_random_user_agent():
    """Select a random user agent from the USER_AGENTS list."""
    return random.choice(USER_AGENTS)

def get_file_path(prompt_text):
    """Prompt user for a file path with autocompletion."""
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def load_urls(urls_file):
    """Load URLs from a file."""
    try:
        with open(urls_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        console.print(f"[!] Error loading URLs: {e}", style="bold red")
        os._exit(1)

def load_payloads(payload_file):
    """Load payloads from a file."""
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        console.print(f"[!] Error loading payloads: {e}", style="bold red")
        os._exit(1)

def generate_payload_urls(url, payload):
    """Generate URL variations with payloads in query parameters."""
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

def create_driver():
    """Create a headless Chrome WebDriver instance with a random user agent."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.page_load_strategy = 'eager'
    chrome_options.add_argument(f"user-agent={get_random_user_agent()}")  # Random user agent
    logging.disable(logging.CRITICAL)

    driver_service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=driver_service, options=chrome_options)

def run_scan(urls, payload_file, timeout):
    """Run scan for all URLs and payloads."""
    payloads = load_payloads(payload_file)
    vulnerable_urls = []
    total_scanned = 0

    driver_pool = Queue()
    driver_lock = Lock()

    def get_driver():
        try:
            return driver_pool.get_nowait()
        except:
            with driver_lock:
                return create_driver()

    def return_driver(driver):
        driver_pool.put(driver)

    def check_vulnerability(url, payload, alert_timeout=0.5):
        """Check if a URL with a payload is vulnerable to XSS."""
        driver = get_driver()
        try:
            payload_urls = generate_payload_urls(url, payload)
            for payload_url in payload_urls:
                try:
                    driver.get(payload_url)

                    try:
                        alert = WebDriverWait(driver, alert_timeout).until(EC.alert_is_present())
                        alert_text = alert.text
                        if alert_text:
                            rprint(f"[bold green] [✓] Vulnerable: [bold blue] {payload_url} [/bold blue] - Alert Text: {alert_text}")
                            vulnerable_urls.append(payload_url)
                            alert.accept()
                        else:
                            rprint(f"[✗] Not Vulnerable:[bold red] {payload_url}[/bold red]")
                    except TimeoutException:
                        rprint(f"[✗] Not Vulnerable:[bold red] {payload_url}[/bold red]")

                except UnexpectedAlertPresentException:
                    pass
        finally:
            return_driver(driver)

    # Prepare drivers for scanning
    for _ in range(3):
        driver_pool.put(create_driver())

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for url in urls:
            for payload in payloads:
                futures.append(executor.submit(check_vulnerability, url, payload))

        for future in as_completed(futures):
            try:
                future.result(timeout=timeout)
            except Exception as e:
                console.print(f"[!] Error during scan: {e}", style="bold red")

    while not driver_pool.empty():
        driver = driver_pool.get()
        driver.quit()

    return vulnerable_urls, len(payloads) * len(urls)

def print_url_box(url):
    """Prints a custom ASCII-styled box around the scanning URL."""
    box_content = f" → Scanning URL: {url} "
    box_width = max(len(box_content) + 2, 40)  # Adjust width as needed
    top_border = "┌" + "─" * (box_width - 2) + "┐"
    middle = f"│{box_content.center(box_width - 2)}│"
    bottom_border = "└" + "─" * (box_width - 2) + "┘"
    
    console.print(f"[yellow]{top_border}")
    console.print(f"[yellow]{middle}")
    console.print(f"[yellow]{bottom_border}\n")

def run_xss_scanner(urls_file=None, payload_file=None, output_file=None):
    # Prompt for missing file paths with autocomplete
    if not urls_file:
        urls_file = get_file_path("Enter the path to the URLs file: ")
    if not payload_file:
        payload_file = get_file_path("Enter the path to the payloads file: ")
    if not output_file:
        output_file = get_file_path("Enter the path to the output file: ")

    urls = load_urls(urls_file)
    start_time = time.time()
    total_vulnerable_urls = []
    total_scanned = 0

    try:
        for url in urls:
            print_url_box(url)
            vulnerable_urls, scanned = run_scan([url], payload_file, timeout=10)
            total_vulnerable_urls.extend(vulnerable_urls)
            total_scanned += scanned

    except KeyboardInterrupt:
        console.print("[bold red]\n[!] Scan interrupted by the user.[/bold red]")
        print_scan_summary(len(total_vulnerable_urls), total_scanned, start_time)
        save_results(total_vulnerable_urls, output_file)
        os._exit(0)

    print_scan_summary(len(total_vulnerable_urls), total_scanned, start_time)
    save_results(total_vulnerable_urls, output_file)

def print_scan_summary(total_found, total_scanned, start_time):
    """Print the summary of the scan results."""
    summary = [
        "→ Scanning finished.",
        f"• Total found: {total_found}",
        f"• Total scanned: {total_scanned}",
        f"• Time taken: {int(time.time() - start_time)} seconds"
    ]
    for line in summary:
        console.print(line, style="yellow")

def save_results(vulnerable_urls, output_file):
    """Save the vulnerable URLs to an output file."""
    with open(output_file, 'w') as file:
        for url in vulnerable_urls:
            file.write(f"{url}\n")

# Argument parsing for command-line usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner with Selenium and ChromeDriver")
    parser.add_argument("-l", "--urls", help="Path to URLs file")
    parser.add_argument("-p", "--payloads", help="Path to XSS payloads file")
    parser.add_argument("-o", "--output", help="Path to output file for vulnerable URLs")

    args = parser.parse_args()
    run_xss_scanner(args.urls, args.payloads, args.output)
