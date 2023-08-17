_help="""Python script for converting given CVEs to their corresponding CWEs using the NVD API.
If there is no corresponding CWE or the CWE is CWE-Other the CWE will be CWE-unknown. The script
also contains functionality for converting a GHSA to its corresponding CWE. In order to do this
a Github token must be given as an argument.

Command line arguments
--list (-l): a string of CVEs seperated by commas ie; CVE-2020-123,CVE-2022-456,CVE-2018-789
--api_key (-k): a filepath pointing to a .txt file containing an NVD api key on a single line.
--github_token (-g): a filepath pointing to a .txt file containing a github token on a single line. This is only needed if there are GHSA IDs to convert to CWEs.
"""

import argparse
import requests
import time
import os
import json

cache = {}

def ghsa_to_cwe(ghsa, github_token):
    query = f"""query {{
        securityAdvisory(ghsaId: "{ghsa}") {{
            ghsaId
            summary
            cwes(first : 1) {{ nodes {{ cweId }} }}
        }}
    }}"""
    if github_token == '':
        print("Error - GHSA ID present in vulnerabilities to process but no Github token was given.",
              "In order to process GHSA IDs a Github token is needed. Use --help for more information")

    response = requests.post(url='https://api.github.com/graphql', json={'query': query}, headers={'Authorization': 'token %s' % github_token})
    if response.status_code != 200:
        return "Bad Request - " + str(response.status_code)
    else:
        ghsa_data = response.json()
        if len(ghsa_data['data']['securityAdvisory']['cwes']['nodes']) > 0:
            return ghsa_data['data']['securityAdvisory']['cwes']['nodes'][0]['cweId']
        else:
            return "CWE-unknown"

def get_cwe(cve, api_key='', github_token=''):
    if cve[:4] == "GHSA":
        return ghsa_to_cwe(cve, github_token)

    if cve in cache:
        return cache[cve]

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

    if api_key == '':
        response = requests.get(url=url)
    else:
        response = requests.get(url=url, headers={"apiKey" : api_key})

    if response.status_code != 200:
        return "Bad Request - " + str(response.status_code)
    else:
        data = response.json()
        if len(data['vulnerabilities']) != 0 and 'cve' in data['vulnerabilities'][0] and 'weaknesses' in data['vulnerabilities'][0]['cve']:
            for w in data['vulnerabilities'][0]['cve']['weaknesses']:
                if 'description' in w and len(w['description']) != 0:
                    if w['description'][0]['value'] == "NVD-CWE-noinfo" or w['description'][0]['value'] == "NVD-CWE-Other":
                        cache[cve] = "CWE-unknown"
                        return "CWE-unknown"
                    cache[cve] = w['description'][0]['value']
                    return w['description'][0]['value']

    cache[cve] = "CWE-unknown"
    return "CWE-unknown"

def get_cwe_for_cves(cve_list, api_key='', github_token=''):
    results = []
    for cve in cve_list:
        if cve[:4] == "GHSA":
            cve = '-'.join(cve.split("-", 4)[:4])
        else:
            cve = '-'.join(cve.split("-", 3)[:3])
        if api_key == '':
            cwe = get_cwe(cve)
            results.append((cve,cwe))
            time.sleep(6.0)
        else:
            s = time.time()
            cwe = get_cwe(cve, api_key, github_token)
            f = time.time()
            if f - s < 0.6:
                time.sleep(0.6 - (f - s))
            results.append((cve,cwe))
    return results

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-l", "--list", dest="cve_list", default="", help="CVE List")
    parser.add_argument("-k", "--api_key", dest="api_key", default="", help="API Key")
    parser.add_argument("-g", "--github_token", dest="github_token", default="", help="Github Token")
    parser.add_argument("-c", "--cache", dest="cve_cache", default="", help="CVE Cache")

    args = parser.parse_args()
    cves = args.cve_list.split(',')
    api_key_path = args.api_key
    github_token_path = args.github_token
    cache_path = args.cve_cache

    if os.path.exists(cache_path):
        with open(cache_path, "r") as json_file:
            cache = json.load(json_file)

    # try opening nvd key and github token files
    try:
        with open(github_token_path) as f:
            github_token = f.readline().rstrip()
        with open(api_key_path) as f:
            api_key = f.readline().rstrip()
    except Error as e:
        print(f"Error - opening github token or nvd api key. {e}")

    result = get_cwe_for_cves(cves, api_key, github_token=github_token)

    for c in result:
        print(c[1])
        print(" ")

    with open(cache_path, "w") as json_file:
        json.dump(cache, json_file)

main()
