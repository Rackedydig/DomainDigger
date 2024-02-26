import pandas as pd
import argparse
import socket
import sys
import os
from vt_check import get_passive_dns, get_domain_score
from scoring import score_high_resolution_count, score_recent_resolution, score_resolution_presence, calculate_malicious_score
from dotenv import load_dotenv
from datetime import datetime


# Load environment variables from .env file
load_dotenv()

# Get the API key for VirusTotal
api_key = os.getenv('VTKEY')

# define function to get Hostname
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def main(args):

    # Define the argument parser and the argument
    parser = argparse.ArgumentParser(description='Process IP addresses from a CSV file and assign a maliciousness score.')
    parser.add_argument('csv_file', type=str, help='The file path of the CSV file containg IP addresses.')

    # Parse the arguments
    args = parser.parse_args()

    # Check if the file exists
    if not os.path.isfile(args.csv_file):
        print(f"The file {args.csv_file} does not exist.")
        sys.exit()

    # load the CSV
    frame = pd.read_csv(args.csv_file)
    # apply function to CSV
    frame['domain'] = frame['IPs'].apply(get_domain)
    frame['resolutions'] = frame['IPs'].apply(lambda x: get_passive_dns(api_key, x))

    # Unpack 'most_recent' into 'hostname' and 'last_resolved' columns
    frame[['passive_resolution', 'last_resolved']] = frame['resolutions'].apply(lambda x: x['most_recent']).apply(pd.Series)

    # Create a separate column 'pair_count'
    frame['domain_resolution_count'] = frame['resolutions'].apply(lambda x: x['pair_count'])
    frame = frame.drop(columns=['resolutions'])

    # extract malicious score for resolved domain
    frame['domain_hits'] = frame['passive_resolution'].apply(lambda x: get_domain_score(api_key, x))

    # scoring
    frame['high_res_count_score'] = frame.apply(score_high_resolution_count, axis=1)
    frame['recent_resolution_score'] = frame.apply(score_recent_resolution, axis=1)
    frame['passive_resolution_score'] = frame.apply(score_resolution_presence, axis=1)
    frame['malicious_hits_score'] = frame.apply(calculate_malicious_score, axis=1)

    # Calculate total_score
    frame['total_score'] = frame['high_res_count_score'].astype(int) + frame['recent_resolution_score'].astype(int) + frame['passive_resolution_score'].astype(int) + frame['malicious_hits_score'].astype(int)

    # Scale total_score from 1-10
    frame['total_score'] = frame['total_score'] + 1

    # rearrange columns
    order = ['IPs', 'domain','passive_resolution','total_score','last_resolved', 'domain_resolution_count', 'domain_hits','high_res_count_score', 'recent_resolution_score', 'passive_resolution_score', 'malicious_hits_score']
    frame = frame[order]

    # Save DataFrame to a CSV file
    current_time = datetime.now().strftime('%Y-%m-%d_%H-%M')
    frame.to_csv(f'output_{current_time}.csv', index=False)
    print(f"Results were saved to output_{current_time}.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process IP addresses from a CSV file and assign a maliciousness score.')
    parser.add_argument('csv_file', type=str, help='The file path of the CSV file containg IP addresses.')
    args = parser.parse_args()
    main(args)
