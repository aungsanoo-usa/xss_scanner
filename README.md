
# XSS Scanner

An advanced XSS (Cross-Site Scripting) vulnerability scanner built using Python and Selenium. This tool uses payloads to test URLs for XSS vulnerabilities by observing whether injected scripts can execute JavaScript alerts. It outputs both vulnerable and non-vulnerable URLs, allowing for efficient vulnerability analysis.

## Features
- Scans multiple URLs with XSS payloads.
- Supports multi-threading for faster scanning.
- Uses Selenium and Chrome WebDriver to detect alerts generated by XSS vulnerabilities.
- Saves the results to a specified output file.

## Requirements
- **Python 3.6+**
- **Google Chrome** (latest version recommended)
- **ChromeDriver** (automatically managed via `webdriver-manager`)

## Installation

### Clone the repository

```bash
git clone https://github.com/aungsanoo-usa/xss_scanner.git
```
```bash
cd xss_scanner
```

### Install the requirements

```bash
pip3 install -r requirements.txt
```
### Run the Script

```bash
python3 xss_scanner.py
```
### Usage

The script accepts the following command-line arguments:

- **-l, --urls: Path to a file containing the list of URLs to scan.**
- **-p, --payloads: Path to a file containing XSS payloads.**
- **-o, --output: Path to the output file where vulnerable URLs will be saved.**

### Command Example

```bash
python3 xss_scanner.py -l urls.txt -p xss_payloads.txt -o output.txt
```

### Chrome Installation

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

- If you encounter any errors during installation, use the following command:

```bash
sudo apt -f install
```

```bash
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

----

### Chrome Driver Installation

```bash
wget https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip
```
```bash
unzip chromedriver-linux64.zip
```
```bash
cd chromedriver-linux64 
```
```bash
sudo mv chromedriver /usr/bin
```

> [!WARNING]
> XSS Scanner is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.
