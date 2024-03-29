# DomainDigger

DomainDigger is a Python tool used for processing IP addresses from a CSV file, performing a reverse DNS lookup, fetching passive DNS replication from VirusTotal, and calculating a maliciousness score for each IP.

The resulting DataFrame will contain the IP addresses, the resolved domains, the most recent passive DNS resolution, last resolution date, a count of all domain resolutions and a maliciousness score ranging from 1 to 10.
Prerequisites

Make sure you have installed the following Python packages:

```
    pandas
    socket
    os
    requests
    python-dotenv
    argparse
```

You can install above packages using pip:

```
pip install -r requirements.txt
```

Or install a virtual python environment by running the 'installer.bat' script on Windows machines.

# Getting Started

To use DomainDigger, make sure you have a CSV file with a list of the IP addresses. The column should be called "IPs".

You should also have an API key from VirusTotal to fetch the passive DNS replication data, and include it in a .env file in the same directory as your Python script. The key-value pair in .env should look like this:

VTKEY=your_api_key

Replace your_api_key with your actual API key.

# Usage

You would run it from the command-line like this:

python resolver.py path_to_your_file.csv

# Output

The DataFrame will contain the following columns:

    IPs: The original IP addresses from your CSV.
    domain: The domains found from reverse DNS lookup.
    passive_resolution: The most recent domain that the IP resolved to according to VirusTotal.
    total_score: The calculated maliciousness score.
    last_resolved: The last time that the IP resolved to the passive resolution.
    domain_resolution_count: The number of all domain resolutions found for the IP.
    domain_hits: The number of malicious hits found for the passive resolution domain.
    high_res_count_score: Score influence factor based on a high number of resolutions.
    recent_resolution_score: Score influence factor based on how recent the last resolution was.
    passive_resolution_score: Score influence factor based on the presence of a resolution.
    malicious_hits_score: Score influence factor based on the number of malicious hits detected for the resolution domain.

The script will automatically save this DataFrame to a CSV file in the same directory.