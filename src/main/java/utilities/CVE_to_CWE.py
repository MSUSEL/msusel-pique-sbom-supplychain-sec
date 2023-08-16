_help="""Python script for converting given CVEs to their corresponding CWEs using the NVD API.
If there is no corresponding CWE or the CWE is CWE-Other the CWE will be CWE-unknown. The script
also contains functionality for converting a GHSA to its corresponding CWE. In order to do this
a Github token must be given as an argument. T

Command line arguments
Required
--single (-s): a CVE id in the standard CVE id format.
or
--list (-l): a filepath pointing to a .txt file containing CVE ids. the file most be formatted with one CVE id per line.

Optional
--api_key (-k): a filepath pointing to a .txt file containing an NVD api key on a single line. 
--github_token (-g): a filepath pointing to a .txt file containing a github token on a single line. This is only needed if there are GHSA IDs to convert to CWEs.
--destination (-d): a filepath pointing to where results when using --list should be saved. Results are saved in the format 
                    CVE-id,CWE-id per line for each CVE-id present in the inputted list.


If either both --single and --list are used or neither are used program execution will stop. 
If using --single the result is printed to standard out in the format CVE-id,CWE-id.
If using --list and no --destination is specified the results will be printed to standard out otherwise results are saved to the destination file location.

If --api_key is not used then requests will be limited to 5 per 30 seconds.
"""

import argparse
import requests
import time

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
    parser.add_argument("-s", "--single", dest="single", default="", help="Single CVE")
    parser.add_argument("-l", "--list", dest="cve_list", default="", help="CVE List")
    parser.add_argument("-k", "--api_key", dest="api_key", default="", help="API Key")
    parser.add_argument("-g", "--github_token", dest="github_token", default="", help="Github Token")
    parser.add_argument("-d", "--destination", dest="destination", default="", help="Destination")
    parser.add_argument("-h", "--help", dest="help", default="", action="store_true", help="Help")

    args = parser.parse_args()
    cve = args.single
    cve_list_path = args.cve_list
    api_key_path = args.api_key
    github_token_path = args.github_token
    destination = args.destination

    if args.help != "":
        print(_help)
        exit()
    
    # check that either a single CVE or filepath to list of CVEs is given
    if cve == "" and cve_list_path == "":
        print("Input error - please use --help (-h) or either the --single (-s) or --list (-l) flag")
        exit()
    if cve != "" and cve_list_path != "":
        print("Input error - please use one of the two flags --single (-s) or --list (-l) but not both")
        exit()

    github_token = ""
    if github_token_path != "":
        with open(github_token_path) as f:
            github_token = f.readline().rstrip()

    # a single CVE inputted 
    if cve != "":
        if api_key_path == "":
            print("Warning - no NVD API key inputted, please note that requests will be limited to 5 per 30 seconds")
            result = get_cwe(cve,github_token=github_token)
        else:
            with open(api_key_path) as f:
                api_key = f.readline().rstrip()
            result = get_cwe(cve, api_key,github_token=github_token)

        print(cve+','+result)
        return

    # file path to a list of CVEs inputted
    else:
        try:
            with open(cve_list_path) as f:
                cves = [line.rstrip() for line in f]
        except:
            print("Error - issue opening cve list file")

        if api_key_path == "":
            print("Warning - no NVD API key inputted, please note that requests will be limited to 5 per 30 seconds")
            result = get_cwe_for_cves(cves, github_token=github_token)
        else:
            with open(api_key_path) as f:
                api_key = f.readline().rstrip()
            result = get_cwe_for_cves(cves, api_key, github_token=github_token)

        if destination != '':
            with open(destination, 'w') as f:
                for t in result:
                    line = ','.join(str(item) for item in t) + '\n'
                    f.write(line)
        else:
            for t in result:
                line = ','.join(str(item) for item in t)
                print(line)

main()
