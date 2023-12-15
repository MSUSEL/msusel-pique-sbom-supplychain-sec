# MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC
## Introduction
This project is an operationalized PIQUE model for the assessment of security quality in software supply chains utilizing SBOM technology.

PIQUE is not yet added to the Maven central repository, so this project will need to be built and installed (via Maven) before it can be used as a library.
___
## Tools
These will be automatically installed when the docker image is built.

- [grype v0.65.2][https://github.com/anchore/grype]
- [Trivy v0.44.1][https://github.com/aquasecurity/trivy]
___

## Run Environment
Docker (built using v24.0.4)
___

## API Key Requirments
A API key from the National Vulnerability Database and a Github personal access token. Save the NVD API key in a text file, nvd_key.txt, save the Github token in a text file, github_token.txt, then place these files in the input/keys directory. 
- [NVD API key][https://nvd.nist.gov/developers/request-an-api-key]
- [Github Token][https://docs.github.com/en/enterprise-server@3.6/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens]
___

## Running 

___

## Funding Agency:

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)
