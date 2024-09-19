import os
import subprocess
import threading
from queue import Queue
from tqdm import tqdm

def run_feroxbuster(subdomain, output_queue, progress_bar):
    try:
        feroxbuster_command = f"feroxbuster --url {subdomain} -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt --depth 1 --silent"
        process = subprocess.Popen(feroxbuster_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            output_queue.put(stdout.decode('utf-8').splitlines())
        else:
            output_queue.put([])

    finally:
        progress_bar.update(1)

def run_ffuf(ferox_result, public_api_file, ffuf_progress_bar):
    try:
        ffuf_command = f"ffuf -u {ferox_result}/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/swagger.txt -v -fc 400,401,402,403,404,501,500,502,503,504 | grep '| URL |' | awk -F '|' '{{print $3}}'"
        process = subprocess.Popen(ffuf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stdout:
            with open(public_api_file, 'a') as f:
                f.write(stdout.decode('utf-8'))
    finally:
        ffuf_progress_bar.update(1)

def process_subdomains(subdomains_file, public_api_file):
    output_queue = Queue()

    with open(subdomains_file, 'r') as file:
        subdomains = file.read().splitlines()

    with tqdm(total=len(subdomains), desc="Processing Feroxbuster", ncols=100) as ferox_progress:
        threads = []
        for subdomain in subdomains:
            thread = threading.Thread(target=run_feroxbuster, args=(subdomain, output_queue, ferox_progress))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    ferox_results = []
    while not output_queue.empty():
        ferox_results.extend(output_queue.get())

    with tqdm(total=len(ferox_results), desc="Processing FFUF", ncols=100) as ffuf_progress:
        for result in ferox_results:
            run_ffuf(result, public_api_file, ffuf_progress)

if __name__ == "__main__":
    subdomains_file = input("Enter the path to the subdomains file: ")

    public_api_file = "public_api.txt"

    if os.path.exists(public_api_file):
        os.remove(public_api_file)

    process_subdomains(subdomains_file, public_api_file)
