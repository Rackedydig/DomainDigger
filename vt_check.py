import requests
import time

# We have to contend to a limited request quota for Limited, standard free public API lookups from VirusTotal

# Request rate 	4 lookups / min
# Daily quota 	5.8 K lookups / day
# Monthly quota 	178.6 K lookups / month 

def get_passive_dns(API_key, ip_address):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': ip_address, 'apikey': API_key}
    response = requests.get(url, params=params)
    time.sleep(15)
    if response.status_code == 200:
        data = response.json().get('resolutions', [{}])
        # result = sorted(data, key=lambda x: x['last_resolved'], reverse=True)[0]
        # return result       
        most_recent = sorted(data, key=lambda x: x.get('last_resolved', ''), reverse=True)[0] if data else {}
        result = {'most_recent': most_recent, 'pair_count': len(data)}
        return result
    else:
        return []
    
def get_domain_score(API_key, domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_key,
              "accept": "application/json"
              }
    response = requests.get(url, headers=headers)
    time.sleep(15)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_stats']['malicious']
    else:
        return 0  



