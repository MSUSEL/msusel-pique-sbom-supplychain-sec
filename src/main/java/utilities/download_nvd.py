import requests
import time
import json
import sys

nvd_dictionary = {}
def batch_cve_request(i, api_key):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex={i}"

    response = requests.get(url=url, headers={"apiKey": api_key})
    if response.status_code != 200:
        print(response.status_code)
        exit(1)

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

    with open(api_key_path) as f:
        API_KEY = f.readline().rstrip()

    n = 1
    for i in range(0, nvd_cve_count, 2000): # NVD API largest and optimal page size is 2000
        s = time.time()
        batch_cve_request(i, API_KEY)
        f = time.time()
        if f - s < 0.6:
            time.sleep(0.6 - (f - s))  # ensure we do not exceed rate limit
        n += 1

    json.dump(nvd_dictionary, open(downloadPath, 'w'))
    print("true")


main()

