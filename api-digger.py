import os
import subprocess
import threading
from queue import Queue
from tqdm import tqdm

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

def process_subdomains(subdomains_file, wordlist, output_file):
    """Processes subdomains with Feroxbuster, then runs FFUF on valid results."""
    output_queue = Queue()

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

    with tqdm(total=len(ferox_results), desc="Finding domains realted to swagger", ncols=100) as ffuf_progress:
        for result in ferox_results:
            run_ffuf(result, output_file, ffuf_progress)

if __name__ == "__main__":
    subdomains_file = input("Enter the name of the subdomains file: ")

    use_custom_wordlist = input("Do you want to use a custom wordlist for dir enumeration? (y/n): ").strip().lower()
    if use_custom_wordlist == 'y':
        wordlist = input("Enter the path to your custom wordlist: ").strip()
    else:
        wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt"

    output_file = input("Enter the output file name: ").strip()

    if os.path.exists(output_file):
        os.remove(output_file)

    process_subdomains(subdomains_file, wordlist, output_file)

    print(f"\n[+] All results have been saved to: {output_file}")
