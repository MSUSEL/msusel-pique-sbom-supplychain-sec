_help="""Python script for converting given CVEs to their corresponding CWEs using the a local copy of the NVD.
If there is no corresponding CWE or the CWE is unknown the CVE will be mapped CWE-unknown. The script
also contains functionality for converting a GHSA to its corresponding CWE. In order to do this
a Github token must be given as an argument.

Calling convention:
    python3 CVE_to_CWE.py --list [vulnerabilities_list] --github_token [github_token_path] --nvdDict [nvd_dict_path]

Command line arguments:
--list (-l): a string of CVEs seperated by commas ie; CVE-2020-123,CVE-2022-456,CVE-2018-789
--github_token (-g): a filepath pointing to a .txt file containing a github token on a single line. This is only needed if there are GHSA IDs to convert to CWEs.
--nvdDict (-n): a filepath pointing to a .json file containing a downloaded version of the NVD saved as a dictionary with CVE IDs as keys.
"""

import argparse
import requests
import json

#
# Converts a GHSA to its mapped CWE the github graphql api.
#
# Parameters:
# vul: a GHSA in the format GHSA-x-x-x where x can be any combination of digits
# github_token: a string containing a github api token
#
# Returns:
# list of all CWEs that map to the given GHSA
#
def ghsa_to_cwe(ghsa, github_token):
    # construct graphql query
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

    # send http request with graphql query
    response = requests.post(url='https://api.github.com/graphql', json={'query': query}, headers={'Authorization': 'token %s' % github_token})

    if response.status_code != 200:
        return "Bad Request - " + str(response.status_code)
    else:
        ghsa_data = response.json()
        result = []

        # parse complex json returned from github 
        if len(ghsa_data['data']['securityAdvisory']['cwes']['nodes']) > 0:
            for node in ghsa_data['data']['securityAdvisory']['cwes']['nodes']:
                result.append(ghsa_data['data']['securityAdvisory']['cwes']['nodes'][0]['cweId'])
            return result
        else:
            result.append("CWE-unknown")
            return result

#
# Converts a single CVE or GHSA to its mapped CWE using a local copy of the NVD and the github graphql api.
#
# Parameters:
# vul: a single CVE or GHSA in the format CVE-x-x or GHSA-x-x-x where x can be any combination of digits
# github_token: a string containing a github api token
# nvd_dict: a dictionary containing the entire NVD downloaded using their api
#
# Returns:
# list of all CWEs that map to the given CVE or GHSA
#
def get_cwe(vul, github_token, nvd_dict):
    if vul[:4] == "GHSA":
        return ghsa_to_cwe(vul, github_token)

    result = []
    if vul in nvd_dict:
        if 'weaknesses' in nvd_dict[vul]:
            for w in nvd_dict[vul]['weaknesses'][:1]:
                cwe = w['description'][0]['value']
                if cwe == 'NVD-CWE-Other' or cwe == 'NVD-CWE-noinfo':
                    result.append('CWE-unknown')
                else:
                    result.append(cwe)
        else:
            result.append('CWE-unknown')

    return result


#
# Converts a given list of CVEs and/or GHSAs to CWEs using a local copy of the NVD and the github graphql api.
#
# Parameters:
# vulnerabilities: a list of CVEs and/or GHSAs in the format CVE-x-x or GHSA-x-x-x where x can be any combination of digits
# github_token: a string containing a github api token
# nvd_dict: a dictionary containing the entire NVD downloaded using their api
#
# Returns:
# list of CWEs
#
def get_cwe_for_vulnerabilities(vulnerabilities, github_token, nvd_dict):
    # build a list of all CWEs
    results = []
    for vul in vulnerabilities:
        # tools grype and trivy include package name the CVE or GHSA was found in, thus we must trim it off
        if vul[:4] == "GHSA":
            vul = '-'.join(vul.split("-", 4)[:4])
        else:
            vul = '-'.join(vul.split("-", 3)[:3])

        cwe = get_cwe(vul, github_token, nvd_dict=nvd_dict)
        results.extend(cwe) # a list is returned because a CVE can map to multiple CWEs

    return results

#
# Entry point for the script. Expects command line arguments:
# --list (-l): a string of CVEs seperated by commas ie; CVE-2020-123,CVE-2022-456,CVE-2018-789
# --github_token (-g): a filepath pointing to a .txt file containing a github token on a single line. This is only needed if there are GHSA IDs to convert to CWEs.
# --nvdDict (-n): a filepath pointing to a .json file containing a downloaded version of the NVD saved as a dictionary with CVE IDs as keys.
#
# Trys to open github token file and nvd file if either throw an error prints message as well as error information, exits with code 1.
#
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-l", "--list", dest="vulnerabilities", default="", help="Vulnerabilities List")
    parser.add_argument("-g", "--github_token", dest="github_token", default="", help="Github Token File Path")
    parser.add_argument("-n", "--nvdDict", dest="nvd_dict", default="", help="NVD Dictionary File Path")

    args = parser.parse_args()
    vulnerabilities = args.vulnerabilities.split(',')
    github_token_path = args.github_token
    nvd_dict_path = args.nvd_dict

    # try github token file
    try:
        with open(github_token_path) as f:
            github_token = f.readline().rstrip()
    except Error as e:
        print(f"Error - opening github token file, please supply valid filepath to .txt file containing only a github api token.\n{e}")
        exit(1)

    # try nvd dictionary file
    try:
        with open(nvd_dict_path, "r") as json_file:
            nvd_dict = json.load(json_file)
    except Error as e:
            print(f"Error - opening nvd dictionary json file.\n{e}")
            exit(1)

    result = get_cwe_for_vulnerabilities(vulnerabilities, github_token, nvd_dict)

    # need to print out results to standard out for PIQUE to capture
    for c in result:
        print(c)
        print(" ")

main()
