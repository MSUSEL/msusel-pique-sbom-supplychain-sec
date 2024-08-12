#################### DEPRECATED ####################
# This script is no longer used

#
# Command line python script for keeping a copy of the NVD open locally. This script communications with CVE_to_CWE.py
# using RESTful API calls.
#
# calling convention:
#       python3 query_nvd.py [nvd_dict] [port]
#
# Command line arguments:
# nvd_dict: a filepath pointing to a .json file containing a downloaded version of the NVD saved as a dictionary with CVE IDs as keys.
# port: the port to run the flask server on

from flask import Flask, jsonify, request
import json
import sys

app = Flask(__name__)

nvd_dict = {}

# Endpoint to retrieve CWEs based on a given CVE
@app.route('/get_cwes', methods=['GET'])
def get_cwes():
    vul = request.args.get('cve', '')

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
    return jsonify({"cwes": result})


def main():
    if len(sys.argv) != 3:
        print("Incorrect Arguments - input: NVD dictionary path, port")
        exit(1)

    nvd_dict_path = sys.argv[1]
    port = int(sys.argv[2])

    global nvd_dict
    try:
        with open(nvd_dict_path, "r") as json_file:
            nvd_dict = json.load(json_file)
    except OSError as e:
        print(f"Error - opening nvd dictionary json file.\n{e}")
        exit(1)

    print(f"\n\n\n\n STARTING SERVER \n\n\n\n")
    app.run(port=port)

main()


