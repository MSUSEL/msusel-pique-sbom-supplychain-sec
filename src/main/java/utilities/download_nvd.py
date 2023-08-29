import requests
import time
import json
import sys

api_key = "1da8de83-0e00-468f-ad6f-00fd0f351c18"

nvd_dictionary = {}
def batch_cve_request(i):
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
    if len(sys.argv) != 2:
        print("Incorrect Arguments - input: NVD total CVE count")
        exit(1)

    n = 1
    nvd_cve_count = int(sys.argv[1])
    for i in range(0, nvd_cve_count, 2000):
        print(f"start request: {n}")
        s = time.time()
        batch_cve_request(i)
        f = time.time()
        if f - s < 0.6:
            time.sleep(0.6 - (f - s))  # ensure we do not exceed rate limit
        n += 1

    json.dump(nvd_dictionary, open('nvd-dictionary.json', 'w'))


main()

