import os
import time
import logging
import argparse
import urllib3
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from webdriver_manager.chrome import ChromeDriverManager

# Initialize console for formatted output
console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_urls(urls_file):
    """Load URLs from a file."""
    try:
        with open(urls_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        console.print(f"[!] Error loading URLs: {e}", style="bold red")
        os._exit(1)

def run_xss_scanner(urls, payload_file, output_file, concurrency=5, timeout=10):
    logging.getLogger('WDM').setLevel(logging.ERROR)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    driver_pool = Queue()
    driver_lock = Lock()

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
        """Create a headless Chrome WebDriver instance."""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.page_load_strategy = 'eager'
        logging.disable(logging.CRITICAL)

        driver_service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=driver_service, options=chrome_options)

    def get_driver():
        """Retrieve an available WebDriver instance from the pool or create a new one."""
        try:
            return driver_pool.get_nowait()
        except:
            with driver_lock:
                return create_driver()

    def return_driver(driver):
        """Return a WebDriver instance to the pool."""
        driver_pool.put(driver)

    def check_vulnerability(url, payload, vulnerable_urls, total_scanned):
        """Check if a URL with a payload is vulnerable to XSS."""
        driver = get_driver()
        try:
            payload_urls = generate_payload_urls(url, payload)
            if not payload_urls:
                return

            for payload_url in payload_urls:
                try:
                    driver.get(payload_url)
                    total_scanned[0] += 1
                    
                    try:
                        # Wait briefly for an alert to appear if vulnerability exists
                        alert = WebDriverWait(driver, 0.5).until(EC.alert_is_present())
                        alert_text = alert.text

                        # Console and file output for vulnerabilities
                        if alert_text:
                            result = f"[✓] Vulnerable: {payload_url} - Alert Text: {alert_text}"
                            console.print(result, style="bold green")
                            vulnerable_urls.append(payload_url)
                            alert.accept()
                        else:
                            result = f"[✗] Not Vulnerable: {payload_url}"
                            console.print(result, style="bold red")

                    except TimeoutException:
                        console.print(f"[✗] Not Vulnerable: {payload_url}", style="bold red")

                except UnexpectedAlertPresentException:
                    pass 
        finally:
            return_driver(driver)

    def run_scan(concurrency, timeout):
        """Run the scan across all URLs and payloads using multi-threading."""
        payloads = load_payloads(payload_file)
        vulnerable_urls = []
        total_scanned = [0]

        # Initialize a limited pool of drivers
        for _ in range(min(concurrency, 3)):
            driver_pool.put(create_driver())
        
        try:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = []
                for url in urls:
                    for payload in payloads:
                        futures.append(
                            executor.submit(
                                check_vulnerability,
                                url,
                                payload,
                                vulnerable_urls,
                                total_scanned
                            )
                        )
                
                # Process results as they complete
                for future in as_completed(futures):
                    try:
                        future.result(timeout=timeout)
                    except Exception as e:
                        console.print(f"[!] Error during scan: {e}", style="bold red")

        finally:
            # Ensure all drivers are closed after the scan
            while not driver_pool.empty():
                driver = driver_pool.get()
                driver.quit()
        
        # Write results to output file without ANSI color codes
        with open(output_file, 'w') as file:
            for url in vulnerable_urls:
                file.write(f"{url}\n")

        return vulnerable_urls, total_scanned[0]

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

    # Main execution
    start_time = time.time()
    vulnerable_urls, total_scanned = run_scan(concurrency, timeout)
    total_found = len(vulnerable_urls)
    print_scan_summary(total_found, total_scanned, start_time)
    return vulnerable_urls, total_scanned

# Argument parsing for command-line usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner with Selenium and ChromeDriver")
    parser.add_argument("-l", "--urls", required=True, help="Path to URLs file")
    parser.add_argument("-p", "--payloads", required=True, help="Path to XSS payloads file")
    parser.add_argument("-o", "--output", required=True, help="Path to output file for vulnerable URLs")
    
    args = parser.parse_args()
    urls = load_urls(args.urls)
    run_xss_scanner(urls, args.payloads, args.output)
