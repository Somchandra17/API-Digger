import os
import subprocess
import threading
from queue import Queue
import re
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from colorama import init, Fore, Style
from tqdm import tqdm
import json
import platform
import resource
from tabulate import tabulate
import sys
import concurrent.futures

# kitty terminal colors
init(autoreset=True)

# vulnerable awagger UI versions source - synk
VULNERABILITY_TABLE = [
    {"Severity": "M", "Vulnerability": "Server-side Request Forgery (SSRF)", "Versions": ["<4.1.3"]},
    {"Severity": "M", "Vulnerability": "Insecure Defaults", "Versions": ["<3.26.1"]},
    {"Severity": "M", "Vulnerability": "Relative Path Overwrite (RPO)", "Versions": ["<3.23.11"]},
    {"Severity": "M", "Vulnerability": "Cross-site Scripting (XSS)", "Versions": [">=2.0.3 <2.0.24", ">=3.0.0 <3.0.13", "<2.2.1", "<3.20.9", "<3.4.2", "<2.2.3"]},
    {"Severity": "M", "Vulnerability": "Reverse Tabnabbing", "Versions": ["<3.18.0"]},
    {"Severity": "C", "Vulnerability": "Cross-site Scripting (XSS)", "Versions": ["<2.1.0"]},
    {"Severity": "H", "Vulnerability": "Cross-site Scripting (XSS)", "Versions": ["<2.2.1"]}
]

# threads dont go above 25
MAX_THREADS = 20
PROCESS_DELAY = 0.05

def print_banner():
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Fore.GREEN}    _    ____  ___       {Fore.YELLOW}____  ___ ____ ____ _____ ____  {Fore.CYAN}     ║
║ {Fore.GREEN}   / \\  |  _ \\|_ _|     {Fore.YELLOW}|  _ \\|_ _/ ___/ ___| ____|  _ \\ {Fore.CYAN}     ║
║ {Fore.GREEN}  / _ \\ | |_) || |_____ {Fore.YELLOW}| | | || | |  | |  _|  _| | |_) |{Fore.CYAN}     ║
║ {Fore.GREEN} / ___ \\|  __/ | |_____]{Fore.YELLOW}| |_| || | |__| |_| | |___|  _ < {Fore.CYAN}     ║
║ {Fore.GREEN}/_/   \\_\\_|   |___|     {Fore.YELLOW}|____/|___\\____\\____|_____|_| \\_\\{Fore.CYAN}     ║
║                                                               ║
║ {Fore.WHITE}API-Digger: Swagger UI Vulnerability Scanner v2  {Fore.CYAN}             ║
║ {Fore.WHITE}Discover and analyze vulnerable Swagger UI endpoints{Fore.CYAN}          ║
║                                                     {Fore.MAGENTA}By: 0xs0m {Fore.CYAN}║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def increase_file_limit():
    """
    Increase the maximum number of open files.
    This helps prevent 'Too many open files' errors when running many threads.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Set the soft limit to the hard limit or 4096, whichever is lower
        new_soft = min(hard, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        print(f"{Fore.CYAN}[*] File limit increased from {soft} to {new_soft}")
    except (ValueError, resource.error) as e:
        print(f"{Fore.YELLOW}[!] Could not increase file limit: {e}")
        print(f"{Fore.YELLOW}[!] If you encounter 'Too many open files' errors, try running 'ulimit -n 4096' before starting the script")

def check_prerequisites():
    """Check if required tools are installed"""
    prerequisites = {
        "feroxbuster": "Feroxbuster not found. Install it with: 'cargo install feroxbuster'"
    }
    
    missing_tools = []
    for tool, message in prerequisites.items():
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing_tools.append(message)
    
    if missing_tools:
        print(f"{Fore.RED}[!] Missing prerequisites:")
        for message in missing_tools:
            print(f"{Fore.RED}    - {message}")
        return False
    return True

def is_version_vulnerable(version, version_constraints):
    """
    Check if a version is vulnerable based on version constraints.
    
    Args:
        version (str): The version to check
        version_constraints (list): List of version constraints like ["<3.0.0", ">=2.0.0 <2.1.0"]
    
    Returns:
        bool: True if vulnerable, False otherwise
    """
    if not version:
        return False
    
    # tuple conv.
    try:
        version_parts = list(map(int, version.split('.')))
    except ValueError:
        # ver. format check here
        return False
    
    # Pad with zeros to ensure consistent comparison
    while len(version_parts) < 3:
        version_parts.append(0)
    
    for constraint in version_constraints:
        # Parse constraints like "<3.0.0" or ">=2.0.0 <2.1.0"
        parts = constraint.split()
        
        if len(parts) == 1:
            # by default
            operator = constraint[0:2] if constraint[1] in ['=', '>'] else constraint[0]
            compare_version = constraint[len(operator):].strip()
            try:
                compare_parts = list(map(int, compare_version.split('.')))
            except ValueError:
                continue
            
            # Pad with zeros
            while len(compare_parts) < 3:
                compare_parts.append(0)
            
            if operator == "<" and version_parts < compare_parts:
                return True
            elif operator == "<=" and version_parts <= compare_parts:
                return True
            elif operator == ">" and version_parts > compare_parts:
                return True
            elif operator == ">=" and version_parts >= compare_parts:
                return True
            elif operator == "==" and version_parts == compare_parts:
                return True
        else:
            
            all_match = True
            
            for part in parts:
                operator = part[0:2] if part[1] in ['=', '>'] else part[0]
                compare_version = part[len(operator):].strip()
                try:
                    compare_parts = list(map(int, compare_version.split('.')))
                except ValueError:
                    all_match = False
                    break
                
                # Pad with zeros
                while len(compare_parts) < 3:
                    compare_parts.append(0)
                
                if operator == "<" and not (version_parts < compare_parts):
                    all_match = False
                    break
                elif operator == "<=" and not (version_parts <= compare_parts):
                    all_match = False
                    break
                elif operator == ">" and not (version_parts > compare_parts):
                    all_match = False
                    break
                elif operator == ">=" and not (version_parts >= compare_parts):
                    all_match = False
                    break
                elif operator == "==" and not (version_parts == compare_parts):
                    all_match = False
                    break
            
            if all_match:
                return True
    
    return False

def get_identified_vulnerabilities(version):
    """
    Identify vulnerabilities for a given version.
    
    Args:
        version (str): Swagger UI version
    
    Returns:
        list: List of identified vulnerabilities
    """
    vulnerabilities = []
    
    for vuln in VULNERABILITY_TABLE:
        if any(is_version_vulnerable(version, [v_constraint]) for v_constraint in vuln["Versions"]):
            vulnerabilities.append({
                "Severity": vuln["Severity"],
                "Vulnerability": vuln["Vulnerability"]
            })
    
    return vulnerabilities

def spinner_task(stop_event):
    """Display a spinner animation"""
    spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{Fore.CYAN}[{spinners[i % len(spinners)]}] Processing... ")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()

def run_command(command):
    """Run a command and return the output"""
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return stdout.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {e}"

def run_feroxbuster(subdomain, wordlist):
    """Run feroxbuster on a subdomain to discover endpoints"""
    feroxbuster_command = f"feroxbuster --url {subdomain} -w {wordlist} --depth 1 --silent --dont-extract-links --no-state"
    output = run_command(feroxbuster_command)
    
    if output:
        return output.splitlines()
    return []

def run_ffuf(ferox_result, swagger_wordlist):
    """Run feroxbuster with swagger-specific wordlist on discovered endpoints"""
    ffuf_command = f"feroxbuster --url {ferox_result} -w {swagger_wordlist} --depth 1 --silent --dont-extract-links --no-state | tail -n +2"
    output = run_command(ffuf_command)
    
    if output and output.strip():
        return {ferox_result: output.strip().splitlines()}
    return {}

def process_subdomain(subdomain, wordlist, progress_bar=None):
    """Process a single subdomain and return results"""
    results = run_feroxbuster(subdomain, wordlist)
    if progress_bar:
        progress_bar.update(1)
    return results

def process_ferox_result(result, swagger_wordlist, progress_bar=None):
    """Process a single feroxbuster result and return swagger results"""
    results = run_ffuf(result, swagger_wordlist)
    if progress_bar:
        progress_bar.update(1)
    return results

def extract_html_endpoints(scan_results):
    """Extract HTML endpoints from scan results"""
    html_endpoints = []
    
    for base_url, results in scan_results.items():
        for line in results:
            if 'html' in line.lower():
                # Extract the URL from the feroxbuster output line
                url_match = re.search(r'(https?://[^\s]+)', line)
                if url_match:
                    html_endpoints.append(url_match.group(1))
    
    return html_endpoints

def check_swagger_version(url):
    """
    Use Selenium to check the Swagger UI version from the target URL.
    
    Args:
        url (str): URL to check
    
    Returns:
        tuple: (version, vulnerabilities, error_message)
    """
    try:
        # selenium headless
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        
        # Specify user agent as i was getting blocked by AWF many a times
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36")
        
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        
        # Set a timeout for page load
        driver.set_page_load_timeout(10)
        
        driver.get(url)
        
        # Wait for the page to load
        time.sleep(2)
        
        # methods to get the swagger ui version inc. version 2 
        version_methods = [
            'return window.versions ? JSON.stringify(window.versions) : null;',
            'return document.querySelector(".version") ? document.querySelector(".version").innerText : null;',
            'return document.querySelector("footer") ? document.querySelector("footer").innerText : null;'
        ]
        
        version = None
        execution_results = []
        
        for script in version_methods:
            try:
                result = driver.execute_script(script)
                execution_results.append(result)
                if result:
                    # Look for version pattern in the result
                    version_match = re.search(r'(\d+\.\d+\.\d+)', result)
                    if version_match:
                        version = version_match.group(1)
                        break
            except Exception as e:
                execution_results.append(f"Error: {str(e)}")
                continue
        
        # Check if we found a version
        if version:
            vulnerabilities = get_identified_vulnerabilities(version)
            return version, vulnerabilities, None
        
        # No version found but page loaded - this is an error case - False Positibe Check
        error_message = "Version detection failed. All methods returned null or undefined."
        
        # For debugging purposes, include execution results in the error message
        debug_info = " | ".join([str(r) for r in execution_results])
        return None, [], f"{error_message} Results: {debug_info}"
    
    except Exception as e:
        error_message = f"Error checking Swagger version: {str(e)}"
        print(f"{Fore.YELLOW}[!] {error_message} for {url}")
        return None, [], error_message
    finally:
        try:
            driver.quit()
        except:
            pass

def generate_swagger_wordlist():
    """Generate a wordlist of common Swagger UI endpoints"""
    swagger_paths = [
        "swagger-ui.html",
        "swagger/index.html",
        "swagger-ui/index.html",
        "api/swagger-ui.html",
        "api-docs/swagger-ui.html",
        "swagger/ui/index.html",
        "swagger-resources",
        "v2/api-docs",
        "v1/api-docs",
        "api/v1/api-docs",
        "api/v2/api-docs",
        "swagger/v1/swagger.json",
        "api/swagger.json",
        "application/swagger.json",
        "swagger/docs/v1",
        "swagger/docs/v2",
        "api-docs",
        "docs/"
    ]
    
    # Create the swagger wordlist file
    with open("swagger.txt", "w") as f:
        for path in swagger_paths:
            f.write(f"{path}\n")
    
    return "swagger.txt"

def process_subdomains(subdomains_file, wordlist, output_file):
    """Process subdomains with proper resource management to avoid 'Too many open files' errors."""
    # Generate swagger wordlist if it doesn't exist
    swagger_wordlist = generate_swagger_wordlist()
    
    # del output file if it exists
    if os.path.exists(output_file):
        os.remove(output_file)
    
    # subdomains here initial
    with open(subdomains_file, 'r') as file:
        subdomains = [line.strip() for line in file.readlines() if line.strip()]
    
    if not subdomains:
        print(f"{Fore.RED}[!] No subdomains found in {subdomains_file}")
        return
    
    print(f"{Fore.GREEN}[+] {len(subdomains)} subdomains loaded from {subdomains_file}")
    
    # Initialize results
    ferox_results = []
    
    print(f"{Fore.CYAN}[*] Starting directory enumeration with {MAX_THREADS} concurrent threads")
    with tqdm(total=len(subdomains), desc=f"{Fore.CYAN}Running directory enumeration", ncols=100, 
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # Submit all tasks
            future_to_subdomain = {
                executor.submit(process_subdomain, subdomain, wordlist, progress_bar): subdomain 
                for subdomain in subdomains
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    results = future.result()
                    for result in results:
                        url_match = re.search(r'(https?://[^\s]+)', result)
                        if url_match:
                            ferox_results.append(url_match.group(1))
                except Exception as e:
                    print(f"{Fore.RED}[!] Error processing {subdomain}: {e}")
    
    if not ferox_results:
        print(f"{Fore.YELLOW}[!] No directories found. Try using a different wordlist.")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(ferox_results)} potential directories to scan")
    
    # again feroxbuster with swagger wordlist on each result
    scan_results = {}
    
    print(f"{Fore.CYAN}[*] Starting Swagger UI endpoint discovery with {MAX_THREADS} concurrent threads")
    with tqdm(total=len(ferox_results), desc=f"{Fore.CYAN}Finding Swagger UI endpoints", ncols=100, 
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # Submit tasks in batches to avoid resource exhaustion
            batch_size = 20
            for i in range(0, len(ferox_results), batch_size):
                batch = ferox_results[i:i+batch_size]
                
                # Submit batch of tasks
                future_to_result = {
                    executor.submit(process_ferox_result, result, swagger_wordlist, progress_bar): result 
                    for result in batch
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_result):
                    result = future_to_result[future]
                    try:
                        results = future.result()
                        scan_results.update(results)
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error processing {result}: {e}")
                
                # Add a small delay between batches to allow resources to be freed can bust anytime. not tested much
                if i + batch_size < len(ferox_results):
                    time.sleep(0.5)
    
    # Extract HTML endpoints 
    html_endpoints = extract_html_endpoints(scan_results)
    
    if not html_endpoints:
        print(f"{Fore.YELLOW}[!] No potential Swagger UI endpoints found")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(html_endpoints)} potential Swagger UI endpoints")
    
    # wagger UI version and vulnerabilities
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_spinner,))
    spinner_thread.daemon = True
    spinner_thread.start()
    
    vulnerable_endpoints = []
    errored_endpoints = []  # List to track endpoints with errors
    
    try:
        # Process endpoints sequentially to avoid browser driver issues
        for endpoint in html_endpoints:
            version, vulnerabilities, error = check_swagger_version(endpoint)
            
            if error:
                # Add to errored_endpoints if any error occurred during version checking
                errored_endpoints.append({
                    "URL": endpoint,
                    "Error": error
                })
            elif version and vulnerabilities:
                vulnerable_endpoints.append({
                    "URL": endpoint,
                    "Version": version,
                    "Vulnerabilities": vulnerabilities
                })
    finally:
        stop_spinner.set()
        spinner_thread.join()
    
    # Save results to file
    with open(output_file, 'w') as f:
        f.write(f"API-DIGGER SCAN RESULTS\n")
        f.write(f"=====================\n\n")
        
        f.write(f"SCAN SUMMARY\n")
        f.write(f"------------\n")
        f.write(f"Subdomains scanned: {len(subdomains)}\n")
        f.write(f"Directories discovered: {len(ferox_results)}\n")
        f.write(f"Potential Swagger UI endpoints: {len(html_endpoints)}\n")
        f.write(f"Vulnerable Swagger UI endpoints: {len(vulnerable_endpoints)}\n")
        f.write(f"Endpoints with errors: {len(errored_endpoints)}\n\n")
        
        if html_endpoints:
            f.write(f"POTENTIAL SWAGGER UI ENDPOINTS\n")
            f.write(f"-----------------------------\n")
            for endpoint in html_endpoints:
                f.write(f"- {endpoint}\n")
            f.write("\n")
        
        if vulnerable_endpoints:
            f.write(f"VULNERABLE SWAGGER UI ENDPOINTS\n")
            f.write(f"------------------------------\n")
            for endpoint in vulnerable_endpoints:
                f.write(f"URL: {endpoint['URL']}\n")
                f.write(f"Version: {endpoint['Version']}\n")
                f.write(f"Vulnerabilities:\n")
                for vuln in endpoint['Vulnerabilities']:
                    f.write(f"  - [{vuln['Severity']}] {vuln['Vulnerability']}\n")
                f.write("\n")
        
        if errored_endpoints:
            f.write(f"ENDPOINTS WITH ERRORS\n")
            f.write(f"--------------------\n")
            for endpoint in errored_endpoints:
                f.write(f"URL: {endpoint['URL']}\n")
                f.write(f"Error: {endpoint['Error']}\n")
                f.write("\n")
    
    # Print results to console
    if vulnerable_endpoints:
        print(f"\n{Fore.GREEN}[+] {len(vulnerable_endpoints)} vulnerable Swagger UI endpoints found:")
        
        for endpoint in vulnerable_endpoints:
            print(f"\n{Fore.CYAN}[*] {endpoint['URL']}")
            print(f"{Fore.YELLOW}    Version: {endpoint['Version']}")
            print(f"{Fore.RED}    Vulnerabilities:")
            
            for vuln in endpoint['Vulnerabilities']:
                severity_color = Fore.YELLOW
                if vuln['Severity'] == 'H':
                    severity_color = Fore.RED
                elif vuln['Severity'] == 'C':
                    severity_color = Fore.MAGENTA
                
                print(f"      {severity_color}[{vuln['Severity']}] {vuln['Vulnerability']}")
    else:
        print(f"\n{Fore.YELLOW}[!] No vulnerable Swagger UI endpoints found")
    
    # Print errored endpoints count
    if errored_endpoints:
        print(f"\n{Fore.YELLOW}[!] {len(errored_endpoints)} endpoints encountered errors during version checking")
        print(f"{Fore.YELLOW}[!] Check the output file for details to manually investigate these endpoints")
    
    print(f"\n{Fore.GREEN}[+] All results have been saved to: {output_file}")

def display_vulnerability_table():
    """Display the table of vulnerabilities and affected versions"""
    headers = ["Severity", "Vulnerability", "Vulnerable Versions"]
    table_data = []
    
    for vuln in VULNERABILITY_TABLE:
        table_data.append([
            f"{Fore.RED if vuln['Severity'] == 'H' else Fore.YELLOW if vuln['Severity'] == 'M' else Fore.MAGENTA}{vuln['Severity']}{Style.RESET_ALL}", 
            vuln['Vulnerability'], 
            ", ".join(vuln['Versions'])
        ])
    
    print("\nSwagger UI Known Vulnerabilities:")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print()

def main():
    """Main function to run the tool"""
    print_banner()
    
    # Try to increase file limit to prevent "Too many open files" errors
    increase_file_limit()
    
    if not check_prerequisites():
        sys.exit(1)
    
    print(f"{Fore.CYAN}[*] API-Digger: Swagger UI Vulnerability Scanner")
    
    # Display the vulnerability table
    display_vulnerability_table()
    
    # Get user input
    subdomains_file = input(f"{Fore.GREEN}[?] Enter the name of the subdomains file: {Style.RESET_ALL}")
    
    # Check if the file exists
    if not os.path.exists(subdomains_file):
        print(f"{Fore.RED}[!] File not found: {subdomains_file}")
        sys.exit(1)
    
    use_custom_wordlist = input(f"{Fore.GREEN}[?] Do you want to use a custom wordlist for directory enumeration? (y/n): {Style.RESET_ALL}").strip().lower()
    if use_custom_wordlist == 'y':
        wordlist = input(f"{Fore.GREEN}[?] Enter the path to your custom wordlist: {Style.RESET_ALL}").strip()
        # Check if the wordlist exists if it's a local file
        if not wordlist.startswith(('http://', 'https://')) and not os.path.exists(wordlist):
            print(f"{Fore.RED}[!] Wordlist not found: {wordlist}")
            sys.exit(1)
    else:
        wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt"
        print(f"{Fore.CYAN}[*] Using default wordlist: {wordlist}")
    
    # Get the number of concurrent threads to use
    try:
        global MAX_THREADS
        thread_input = input(f"{Fore.GREEN}[?] Enter maximum number of concurrent threads (default: {MAX_THREADS}): {Style.RESET_ALL}").strip()
        if thread_input:
            max_threads = int(thread_input)
            if max_threads < 1:
                max_threads = MAX_THREADS
                print(f"{Fore.YELLOW}[!] Invalid thread count, using default: {MAX_THREADS}")
            else:
                MAX_THREADS = max_threads
    except ValueError:
        print(f"{Fore.YELLOW}[!] Invalid input, using default thread count: {MAX_THREADS}")
    
    output_file = input(f"{Fore.GREEN}[?] Enter the output file name: {Style.RESET_ALL}").strip()
    
    # Process the subdomains
    process_subdomains(subdomains_file, wordlist, output_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}")
        sys.exit(1)