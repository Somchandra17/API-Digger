import os
import subprocess
import gc
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
MAX_THREADS = 15  # Reduced from 20 to prevent resource exhaustion
PROCESS_DELAY = 0.05
MAX_BATCH_SIZE = 100  # Maximum number of subdomains to process in a batch

def print_banner():
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║ {Fore.GREEN}    _    ____  ___       {Fore.YELLOW}____  ___ ____ ____ _____ ____  {Fore.CYAN}     ║
║ {Fore.GREEN}   / \\  |  _ \\|_ _|     {Fore.YELLOW}|  _ \\|_ _/ ___/ ___| ____|  _ \\ {Fore.CYAN}     ║
║ {Fore.GREEN}  / _ \\ | |_) || |_____ {Fore.YELLOW}| | | || | |  | |  _|  _| | |_) |{Fore.CYAN}     ║
║ {Fore.GREEN} / ___ \\|  __/ | |_____]{Fore.YELLOW}| |_| || | |__| |_| | |___|  _ < {Fore.CYAN}     ║
║ {Fore.GREEN}/_/   \\_\\_|   |___|     {Fore.YELLOW}|____/|___\\____\\____|_____|_| \\_\\{Fore.CYAN}     ║
║                                                               ║
║ {Fore.WHITE}API-Digger: Swagger UI Vulnerability Scanner v3  {Fore.CYAN}             ║
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
        # Try to set a much higher limit for handling many subdomains
        new_soft = min(hard, 8192)  # Increased from 4096 to 8192
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        print(f"{Fore.CYAN}[*] File limit increased from {soft} to {new_soft}")
        
        # Check if the limit might still be too low based on the OS limits
        if new_soft < 4096:
            print(f"{Fore.YELLOW}[!] Warning: File limit might be too low for large subdomain lists")
            print(f"{Fore.YELLOW}[!] Consider running 'ulimit -n 8192' before starting this script")
    except (ValueError, resource.error) as e:
        print(f"{Fore.YELLOW}[!] Could not increase file limit: {e}")
        print(f"{Fore.YELLOW}[!] For processing large subdomain lists, run 'ulimit -n 8192' before starting the script")
        
        # Check current ulimit value and provide specific guidance
        try:
            current_limit = int(subprocess.check_output("ulimit -n", shell=True).decode().strip())
            if current_limit < 4096:
                print(f"{Fore.RED}[!] Current ulimit is only {current_limit}. This is too low for large subdomain lists!")
                if platform.system() == "Linux" or platform.system() == "Darwin":  # Linux or macOS
                    print(f"{Fore.YELLOW}[!] Run these commands to increase limits temporarily:")
                    print(f"{Fore.WHITE}    ulimit -n 8192")
                    print(f"{Fore.YELLOW}[!] Or add this to your ~/.bashrc or ~/.zshrc for persistence:")
                    print(f"{Fore.WHITE}    ulimit -n 8192")
        except:
            pass

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
    
    if (missing_tools):
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
    
    # Handle the case where version is just "2.x"
    if version == "2.x":
        # Check if any of the version constraints affect 2.x versions
        for constraint in version_constraints:
            if "<2" in constraint or "2." in constraint:
                return True
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
    driver = None
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
        
        driver.set_page_load_timeout(2)
        
        driver.get(url)
        
        # Wait for the page to load
        time.sleep(2)
        
        # Enhanced version detection methods including Swagger UI 2.x detection
        version_methods = [
            'return window.versions ? JSON.stringify(window.versions) : null;',
            'return document.querySelector(".version") ? document.querySelector(".version").innerText : null;',
            'return document.querySelector("footer") ? document.querySelector("footer").innerText : null;',
            # Method for detecting Swagger UI 2.x
            '''
            (function() {
              try {
                // Method 1: Check for Swagger 2.x specific DOM elements
                const swaggerSection = document.querySelector('.swagger-section');
                const swagger2Container = document.querySelector('#swagger-ui-container');
                
                if (swagger2Container || swaggerSection) {
                  return JSON.stringify({
                    method: "dom-detection",
                    version: "2.x",
                    major: "2.x"
                  });
                }
                
                // Method 2: Check for 2.x specific global object without SwaggerUIBundle
                if (window.SwaggerUI && !window.SwaggerUIBundle) {
                  return JSON.stringify({
                    method: "swagger-ui-global",
                    version: "2.x",
                    major: "2.x"
                  });
                }
                
                // Method 3: Check script sources for version 2 indicators
                const scripts = document.querySelectorAll('script[src]');
                for (let i = 0; i < scripts.length; i++) {
                  const src = scripts[i].getAttribute('src');
                  if (src && (src.includes('swagger-ui-2') || src.includes('swagger-ui@2'))) {
                    return JSON.stringify({
                      method: "script-src-detection",
                      version: "2.x",
                      major: "2.x"
                    });
                  }
                }
                return null;
              } catch (e) {
                return JSON.stringify({error: e.toString()});
              }
            })()
            '''
        ]
        
        version = None
        execution_results = []
        
        for script in version_methods:
            try:
                result = driver.execute_script(script)
                
                # Skip null/undefined results
                if not result:
                    continue
                
                execution_results.append(result)
                
                # For the Swagger UI 2.x detection (JSON object response)
                if isinstance(result, str) and result.startswith('{'):
                    try:
                        json_result = json.loads(result)
                        if 'version' in json_result:
                            version = json_result['version']
                            print(f"{Fore.GREEN}[+] Detected Swagger UI version {version} via {json_result.get('method', 'JSON detection')} method")
                            break
                    except json.JSONDecodeError:
                        pass
                
                # Regular version pattern detection - using the simpler approach from api-digger.py
                version_match = re.search(r'(\d+\.\d+\.\d+)', result)
                if (version_match):
                    version = version_match.group(1)
                    print(f"{Fore.GREEN}[+] Detected Swagger UI version {version} via script execution")
                    break
            except Exception as e:
                execution_results.append(f"Error: {str(e)}")
                continue
        
        # Check if we found a version
        if version:
            vulnerabilities = get_identified_vulnerabilities(version)
            return version, vulnerabilities, None
        
        # No version found but page loaded - check if it's a 404 or other error
        try:
            # Check if the page title contains '404' or 'error'
            title = driver.title.lower()
            if '404' in title or 'error' in title or 'not found' in title:
                return None, [], f"Page error: {title}"
        except:
            pass
        
        # Last resort detection for Swagger UI - using approach from api-digger.py
        try:
            # Check for common Swagger UI elements and patterns
            has_swagger_ui = driver.execute_script('''
                return Boolean(
                    document.querySelector('.swagger-section') || 
                    document.querySelector('#swagger-ui-container') ||
                    document.querySelector('.swagger-ui') ||
                    window.SwaggerUI ||
                    document.querySelector('script[src*="swagger-ui"]') ||
                    document.body.innerText.includes('Swagger UI') ||
                    document.body.innerText.includes('swagger-ui')
                );
            ''')
            
            if has_swagger_ui:
                # If it looks like Swagger UI but we couldn't detect version,
                # default to 2.x since it's common and detection is more difficult
                version = "2.x"
                print(f"{Fore.YELLOW}[!] Detected likely Swagger UI 2.x but couldn't determine exact version")
                vulnerabilities = get_identified_vulnerabilities(version)
                return version, vulnerabilities, None
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Last resort detection failed: {str(e)}")
            pass
            
        # For debugging purposes, include execution results in the error message
        debug_info = " | ".join([str(r) for r in execution_results if r])
        if not debug_info:
            debug_info = "All methods returned null or undefined"
            
        error_message = f"Version detection failed. {debug_info}"
        return None, [], error_message
    
    except Exception as e:
        error_message = f"Error checking Swagger version: {str(e)}"
        print(f"{Fore.YELLOW}[!] {error_message} for {url}")
        return None, [], error_message
    finally:
        try:
            if driver:
                driver.quit()
                del driver  # Keep this from digger.py to free memory
        except:
            pass
        # Keep gc.collect() for memory management
        gc.collect()

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
    
    total_subdomains = len(subdomains)
    print(f"{Fore.GREEN}[+] {total_subdomains} subdomains loaded from {subdomains_file}")
    
    # Initialize results
    all_ferox_results = []
    
    # Determine if we need batching based on subdomain count
    use_batching = total_subdomains > 500
    batch_size = MAX_BATCH_SIZE if use_batching else total_subdomains
    total_batches = (total_subdomains + batch_size - 1) // batch_size
    
    if use_batching:
        print(f"{Fore.CYAN}[*] Processing {total_subdomains} subdomains in {total_batches} batches of up to {batch_size} each")
    
    # Process subdomains in batches to manage resources better
    for batch_num, i in enumerate(range(0, total_subdomains, batch_size)):
        batch = subdomains[i:i+batch_size]
        
        if use_batching:
            print(f"{Fore.CYAN}[*] Processing batch {batch_num+1}/{total_batches} ({len(batch)} subdomains)")
        
        # Run directory enumeration for this batch
        print(f"{Fore.CYAN}[*] Starting directory enumeration with {MAX_THREADS} concurrent threads")
        batch_desc = f"{Fore.CYAN}Running directory enumeration" + (f" (batch {batch_num+1}/{total_batches})" if use_batching else "")
        
        with tqdm(total=len(batch), desc=batch_desc, ncols=100, 
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
            
            batch_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                # Submit all tasks
                future_to_subdomain = {
                    executor.submit(process_subdomain, subdomain, wordlist, progress_bar): subdomain 
                    for subdomain in batch
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        results = future.result()
                        for result in results:
                            url_match = re.search(r'(https?://[^\s]+)', result)
                            if url_match:
                                batch_results.append(url_match.group(1))
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error processing {subdomain}: {e}")
            
            # Add batch results to overall results
            all_ferox_results.extend(batch_results)
            
            # Brief pause between batches to free up resources
            if i + batch_size < total_subdomains:
                print(f"{Fore.CYAN}[*] Batch complete. Releasing resources before next batch...")
                time.sleep(3)  # Allow time for resources to be freed
                # Force garbage collection to free memory
                gc.collect()
    
    # Update ferox_results with all collected results
    ferox_results = all_ferox_results
    
    if not ferox_results:
        print(f"{Fore.YELLOW}[!] No directories found. Try using a different wordlist.")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(ferox_results)} potential directories to scan")
    
    # Apply similar batching approach to Swagger UI endpoint discovery
    all_scan_results = {}
    
    # Determine batch size for ferox results
    ferox_batch_size = min(50, MAX_BATCH_SIZE // 2)  # Smaller batches for second stage
    total_ferox_batches = (len(ferox_results) + ferox_batch_size - 1) // ferox_batch_size
    
    print(f"{Fore.CYAN}[*] Starting Swagger UI endpoint discovery with {MAX_THREADS} concurrent threads")
    
    # Add a summary progress bar for overall batch progress
    with tqdm(total=len(ferox_results), desc="Overall Progress", ncols=100,
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as overall_progress:
        
        # Process in batches
        for batch_num, i in enumerate(range(0, len(ferox_results), ferox_batch_size)):
            batch = ferox_results[i:i+ferox_batch_size]
            
            # Only print batch info if verbose mode is enabled (could add a flag for this)
            # print(f"{Fore.CYAN}[*] Processing directory batch {batch_num+1}/{total_ferox_batches} ({len(batch)} directories)")
            
            batch_desc = f"Batch {batch_num+1}/{total_ferox_batches}"
            
            # Process this batch
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                # Submit batch of tasks
                futures = []
                for result in batch:
                    future = executor.submit(process_ferox_result, result, swagger_wordlist, None)
                    futures.append(future)
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        results = future.result()
                        all_scan_results.update(results)
                        # Update the overall progress
                        overall_progress.update(1)
                    except Exception as e:
                        # Silently handle errors to avoid cluttering output
                        pass
            
            # Brief pause between batches to free up resources, but don't print a message
            if i + ferox_batch_size < len(ferox_results):
                time.sleep(1.5)  # Allow time for resources to be freed
                gc.collect()
    
    # Update scan_results with all collected results
    scan_results = all_scan_results
    
    # Extract HTML endpoints 
    html_endpoints = extract_html_endpoints(scan_results)
    
    if not html_endpoints:
        print(f"{Fore.YELLOW}[!] No potential Swagger UI endpoints found")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(html_endpoints)} potential Swagger UI endpoints")
    
    # Swagger UI version and vulnerabilities
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=spinner_task, args=(stop_spinner,))
    spinner_thread.daemon = True
    spinner_thread.start()
    
    vulnerable_endpoints = []
    errored_endpoints = []  # List to track endpoints with errors
    
    try:
        # Process endpoints sequentially to avoid browser driver issues
        # This approach from api-digger.py is more reliable for detection
        print(f"{Fore.CYAN}[*] Checking {len(html_endpoints)} potential Swagger UI endpoints for vulnerabilities")
        
        with tqdm(total=len(html_endpoints), desc="Checking Swagger UI versions", ncols=100,
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as progress_bar:
            
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
                
                # Update progress bar
                progress_bar.update(1)
    finally:
        stop_spinner.set()
        spinner_thread.join()
    
    # Rest of the function remains the same...
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
    
    # Existing code...
    
    # Add batch size configuration option
    global MAX_BATCH_SIZE
    batch_size_input = input(f"{Fore.GREEN}[?] Enter batch size for large subdomain lists (default: {MAX_BATCH_SIZE}): {Style.RESET_ALL}").strip()
    if batch_size_input:
        try:
            batch_size = int(batch_size_input)
            if (batch_size > 0):
                MAX_BATCH_SIZE = batch_size
            else:
                print(f"{Fore.YELLOW}[!] Invalid batch size, using default: {MAX_BATCH_SIZE}")
        except ValueError:
            print(f"{Fore.YELLOW}[!] Invalid input, using default batch size: {MAX_BATCH_SIZE}")
    
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