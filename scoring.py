import pandas as pd
from datetime import datetime

def score_high_resolution_count(row):
    # Assume that more than 2 resolutions is high
    if row['domain_resolution_count'] > 3:
        return 3
    return 0

def score_recent_resolution(row):
    # Assume a resolution is recent if it was in the last year
    if pd.notnull(row['last_resolved']):
        last_resolved_date = datetime.strptime(row['last_resolved'], '%Y-%m-%d %H:%M:%S').date()
        if (datetime.now().date() - last_resolved_date).days <= 365:
            return 2
    return 0

def score_resolution_presence(row):
    # If there is a resolution, increase score
    if pd.notnull(row['passive_resolution']):
        return 1
    return 0

def calculate_malicious_score(row):
    # modify score based on number of malicious hits
    if pd.isnull(row['domain_hits']):
        return 0
    if row['domain_hits'] > 4:
        return 3
    elif row['domain_hits'] > 2:
        return 2
    elif row['domain_hits'] > 0:
        return 1
    else:
        return 0