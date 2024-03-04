# MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC
## Introduction
This project is an operationalized PIQUE model for the assessment of security quality in software supply chains utilizing SBOM technology.

PIQUE is not yet added to the Maven central repository, so this project will need to be built and installed (via Maven) before it can be used as a library.
___
## Tools
These will be automatically installed when the docker image is built.

* [Grype](https://github.com/anchore/grype) version 0.72.0
* [Trivy](https://github.com/aquasecurity/trivy) version 0.44.1
* [Sbomqs](https://github.com/interlynk-io/sbomqs) version 0.0.17
* [Maven](https://github.com/apache/maven) version 3.9.6
* [PIQUE-core](https://github.com/MSUSEL/msusel-pique) version 0.9.4
___

## Run Environment
#### Docker
docker engine 20.10.24 (not tested with versions 21+)

The image for this project is hosted on dockerhub 
[here](https://hub.docker.com/repository/docker/msusel/pique-cloud-dockerfile/general). Instructions to download 
and run are supplied [below](https://github.com/MSUSEL/msusel-pique-cloud-dockerfile/tree/master#running)


#### not Docker
It is not suggested to run PIQUE-cloud-dockerfile without the pre-built docker image, but all files and configs 
are supplied on this repository. 

___

## API Key Requirments
A API key from the National Vulnerability Database and a Github personal access token are needed. See [running](ttps://github.com/MSUSEL/msusel-pique-sbom-supplychainsec/tree/master#running) for details
- [NVD API key][https://nvd.nist.gov/developers/request-an-api-key]
- [Github Token][https://docs.github.com/en/enterprise-server@3.6/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens]
___

## Running 
1. Download and install [Docker engine](https://docs.docker.com/engine/install/)
2. With Docker engine installed, pull the latest version of this project:
`docker pull msusel/pique-sbom-supplychainsec:latest`
3. Navigate to a working directory for this project
4. Create two directories, "input" and "output". Inside the "input directory", create two directories "keys" and "projects"
5. Generate an NVD API key [here](https://nvd.nist.gov/developers/request-an-api-key) and save the text of the key to a file 'nvd-api-key.txt'
6. Generate a [Github API token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) and save the text of the key to a file 'github-token.txt' 
7. Move the files 'nvd-api-key.txt' and 'github-token.txt' to the 'input/keys' directory.
8. Place any number of SBOMs to be analyzed in input/projects.
10. The resulting directory structure should look like this:
```
├── $WORKDIR
│   ├── input
│   │   ├── keys
│   │   │   ├── github-token.txt
│   │   │   ├── nvd-api-key.txt
│   │   ├── projects
│   │   │   ├── place SBOMs to analyze here
│   ├── output
```
11. Run the command `docker run -it --rm -v "/var/run/docker.sock:/var/run/docker.sock:rw" -v /path/to/working/directory/input:/input -v /path/to/working/directory/output:/output pique-sbom-supplychainsec:latest`
12. Results will be generated in the 'output' directory
___

## Funding Agency:

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)
