# API-Digger

This tool is designed to automate the process of discovering public APIs across multiple subdomains. It uses Feroxbuster for initial directory enumeration and FFUF for targeted API endpoint discovery.

## Features

- Multi-threaded Feroxbuster scanning for efficient subdomain processing
- FFUF scanning to identify potential API endpoints
- Progress bars to track the status of both Feroxbuster and FFUF scans
- Output results saved to a file for easy review

## Prerequisites

- Python 3.x
- [Feroxbuster](https://github.com/epi052/feroxbuster)
- [FFUF](https://github.com/ffuf/ffuf)
- tqdm (Python library for progress bars)
- [Seclist](https://github.com/danielmiessler/SecLists)
- Update the path of Seclist in the code

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/Somchandra17/API-Digger.git
   cd API-Digger
   ```

2. Install the required Python library:
   ```
   pip install tqdm
   ```

3. Ensure Feroxbuster and FFUF are installed and accessible in your system PATH.

## Usage

1. Prepare a file containing a list of subdomains, one per line.

2. Run the script:
   ```
   python api_discovery.py
   ```

3. When prompted, enter the path to your subdomains file.

4. The script will process the subdomains and save the results in `public_api.txt`.

## How it works

1. The script reads the list of subdomains from the provided file.
2. It runs Feroxbuster on each subdomain using multi-threading for improved performance.
3. The Feroxbuster results are then processed using FFUF to identify potential API endpoints.
4. Results are saved to `public_api.txt`.

## Configuration

- Feroxbuster uses the RAFT medium directories wordlist from SecLists.
- FFUF uses the Swagger wordlist from SecLists.
- You can modify the wordlists and other parameters in the script as needed.

## Note

This tool is intended for authorized security testing only. Always ensure you have permission to scan the target subdomains.

## License

[MIT](https://choosealicense.com/licenses/mit/)
