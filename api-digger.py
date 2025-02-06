import os
import subprocess
import threading
from queue import Queue
from tqdm import tqdm

def run_feroxbuster(subdomain, wordlist, output_queue, progress_bar):
    """Runs Feroxbuster and stores the discovered URLs in a queue."""
    try:
        feroxbuster_command = f"feroxbuster --url {subdomain} -w {wordlist} --depth 1 --silent"
        process = subprocess.Popen(feroxbuster_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            output_queue.put(stdout.decode('utf-8').splitlines())
        else:
            output_queue.put([])
    finally:
        progress_bar.update(1)

def run_ffuf(ferox_result, output_file, ffuf_progress_bar):
    """Runs FFUF on the Feroxbuster results and saves only FFUF output."""
    try:
        ffuf_command = f"ffuf -u {ferox_result}/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/swagger.txt -v -fc 400,401,402,403,404,501,500,502,503,504"
        process = subprocess.Popen(ffuf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            results = stdout.decode('utf-8')
            with open(output_file, 'a') as f:
                f.write(f"\n[+] FFUF results for {ferox_result}:\n")
                f.write(results + "\n")
    finally:
        ffuf_progress_bar.update(1)

def process_subdomains(subdomains_file, wordlist, output_file):
    """Processes subdomains with Feroxbuster, then runs FFUF on valid results."""
    output_queue = Queue()

    with open(subdomains_file, 'r') as file:
        subdomains = file.read().splitlines()

    with tqdm(total=len(subdomains), desc="Running Feroxbuster", ncols=100) as ferox_progress:
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

    with tqdm(total=len(ferox_results), desc="Running FFUF", ncols=100) as ffuf_progress:
        for result in ferox_results:
            run_ffuf(result, output_file, ffuf_progress)

if __name__ == "__main__":
    subdomains_file = input("Enter the path to the subdomains file: ")

    use_custom_wordlist = input("Do you want to use a custom wordlist? (y/n): ").strip().lower()
    if use_custom_wordlist == 'y':
        wordlist = input("Enter the path to your custom wordlist: ").strip()
    else:
        wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt"

    output_file = input("Enter the output file path (including file name): ").strip()

    if os.path.exists(output_file):
        os.remove(output_file)  # Ensures a fresh output file

    process_subdomains(subdomains_file, wordlist, output_file)

    print(f"\n[+] All FFUF results have been saved to: {output_file}")
