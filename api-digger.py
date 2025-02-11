import os
import subprocess
import threading
from queue import Queue
from tqdm import tqdm
import re
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Known vulnerable Swagger UI versions (you can add more versions to this list)
VULNERABLE_VERSIONS = ["3.0.0", "3.1.0", "3.1.6"]

def run_feroxbuster(subdomain, wordlist, output_queue, progress_bar):
    try:
        feroxbuster_command = f"feroxbuster --url {subdomain} -w {wordlist} --depth 1 --silent --dont-extract-links --no-state"
        process = subprocess.Popen(feroxbuster_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            output_queue.put(stdout.decode('utf-8').splitlines())
        else:
            output_queue.put([])
    finally:
        progress_bar.update(1)

def run_ffuf(ferox_result, output_file, ffuf_progress_bar):
    try:
        ffuf_command = f"feroxbuster --url {ferox_result} -w swagger.txt --depth 1 --silent --dont-extract-links --no-state | tail -n +2"
        process = subprocess.Popen(ffuf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            results = stdout.decode('utf-8')
            with open(output_file, 'a') as f:
                f.write(f"\n")
                f.write(results + "\n")
    finally:
        ffuf_progress_bar.update(1)

def extract_html_endpoints(output_file):
    """Extracts URLs containing 'html' from the results file."""
    if not os.path.exists(output_file):
        return []  # If the output file doesn't exist, return an empty list
    
    with open(output_file, 'r') as file:
        lines = file.readlines()

    html_endpoints = [line.strip() for line in lines if 'html' in line.lower()]
    return html_endpoints

def check_swagger_version(url):
    """Uses Selenium to check the Swagger UI version from the target URL."""
    try:
        # Setup Selenium WebDriver (Chrome)
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # Run headless (no GUI)
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        
        # Open the URL in the browser
        driver.get(url)

        # Execute JavaScript to get the Swagger UI version
        script = 'return JSON.stringify(versions);'
        version_info = driver.execute_script(script)

        # Parse and extract the version
        match = re.search(r'"version":"([^"]+)"', version_info)
        if match:
            version = match.group(1)
            if version in VULNERABLE_VERSIONS:
                return version, True
            else:
                return version, False
        return None, False
    except Exception as e:
        print(f"Error checking Swagger version for {url}: {e}")
        return None, False
    finally:
        driver.quit()

def process_subdomains(subdomains_file, wordlist, output_file):
    """Processes subdomains with Feroxbuster, then runs FFUF on valid results."""
    output_queue = Queue()

    # Open or create the output file for writing results
    if os.path.exists(output_file):
        os.remove(output_file)  # If the file exists, remove it to start fresh
    
    with open(subdomains_file, 'r') as file:
        subdomains = file.read().splitlines()

    with tqdm(total=len(subdomains), desc="Running Dir enumeration", ncols=100) as ferox_progress:
        threads = []
        for subdomain in subdomains:
            thread = threading.Thread(target=run_feroxbuster, args=(subdomain, wordlist, output_queue, ferox_progress))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    ferox_results = []
    while not output_queue.empty():
        ferox_results.extend(output_queue.get())

    with tqdm(total=len(ferox_results), desc="Finding domains related to swagger", ncols=100) as ffuf_progress:
        for result in ferox_results:
            run_ffuf(result, output_file, ffuf_progress)

    # After all results are written, process the file to find 'html' endpoints
    html_endpoints = extract_html_endpoints(output_file)
    
    with open(output_file, 'a') as f:
        f.write("\n[+] HTML Endpoints found:\n")
        for endpoint in html_endpoints:
            f.write(endpoint + "\n")
            # Check Swagger version for each endpoint
            version, vulnerable = check_swagger_version(endpoint)
            if version:
                status = "VULNERABLE" if vulnerable else "Not Vulnerable"
                f.write(f"Swagger UI Version: {version} - {status}\n")

if __name__ == "__main__":
    subdomains_file = input("Enter the name of the subdomains file: ")

    use_custom_wordlist = input("Do you want to use a custom wordlist for dir enumeration? (y/n): ").strip().lower()
    if use_custom_wordlist == 'y':
        wordlist = input("Enter the path to your custom wordlist: ").strip()
    else:
        wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt"

    output_file = input("Enter the output file name: ").strip()

    process_subdomains(subdomains_file, wordlist, output_file)

    print(f"\n[+] All results have been saved to: {output_file}")
