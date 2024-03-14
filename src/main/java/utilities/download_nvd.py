#
# command line python script for downloading the most recent version of the NVD using their 2.0 http API.
# calling convention:
#       python3 download_nvd.py [output_file] [total_cve_count] [api_key_filepath]
#
# Command line arguments:
# output_file: file path to a .json file in which the NVD dictionary should be saved
# total_cve_count: count of all CVEs in the NVD, ideally will update this to pull the total count when the script is run
# api_key_filepath: file path to a .txt file containing an NVD api key, file should contain the api key on a single line
#


import requests
import time
import json
import sys

nvd_dictionary = {}

#
# Utilizes the NVD API pages http request to pull the maximum page size (2000) and saves the data to nvd_dictionary.
#
# Parameters:
# i: index of the page to access for the request
# api_key: string containing NVD api key
#
def batch_cve_request(i, api_key):
    request_status = False
    attempts = 1
    while request_status == False:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex={i}"
        response = requests.get(url=url, headers={"apiKey": api_key})

        print(f"response code - {response.status_code}")
        if response.status_code != 200:
            print(f"NVD API request failures are occurring; retrying request for the {attempts} time")
            attempts += 1
            time.sleep(1.0)
            if attempts > 50:
                print("reached retry limit -- exiting")
            continue

        if response.status_code == 200:
            request_status = True

        data = response.json()
        for cve_data in data['vulnerabilities']:
            ID = cve_data['cve']["id"]
            nvd_dictionary[ID] = cve_data['cve']

def main():
    if len(sys.argv) != 4:
        print("Incorrect Arguments - input: NVD total CVE count")
        exit(1)

    downloadPath = sys.argv[1]
    nvd_cve_count = int(sys.argv[2])
    api_key_path = sys.argv[3]
    try:
        with open(api_key_path) as f:
            API_KEY = f.readline().rstrip()
    except OSError as e:
            print(f"Error - opening NVD api key file, please supply valid filepath to .txt file containing only a NVD api key.\n{e}")
            exit(1)

    n = 1
    for i in range(0, nvd_cve_count, 2000): # NVD API largest and optimal page size is 2000
        s = time.time()
        batch_cve_request(i, API_KEY)
        f = time.time()

        # ensure we do not exceed NVD API rate limit (50 requests per 30 seconds)
        if f - s < 0.6:
            time.sleep(0.6 - (f - s))

        n += 1

    # save results to path command line argument
    json.dump(nvd_dictionary, open(downloadPath, 'w'))
    print("true")


main()

