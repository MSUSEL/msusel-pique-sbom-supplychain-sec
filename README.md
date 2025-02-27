# MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC
## Introduction
The MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC project offers an operationalized Platform for Investigative Quality
Understanding and Evaluation (PIQUE) model designed to assess security quality within software
supply chains using Software Bill of Materials (SBOM) technology. To address challenges
associated with various development environments and third-party applications, this project
is also available as a standalone Docker image. That image is available That image is available [here](https://hub.docker.com/repository/docker/msusel/pique-sbom-supply-chain-sec/general)..

## Features
* Security Assessment: Evaluates the security posture of software supply chains by analyzing SBOMs.
* Tool Integration: Incorporates multiple security tools to provide comprehensive analysis.
* Docker Support: Offers a Docker image for simplified deployment and environment consistency.
___
## Tools
The project relies on the following tools. These will be automatically installed when the Docker image is built, but must 
be manually installed if not using the Docker image.

* [Grype](https://github.com/anchore/grype) version 0.87.0
* [Trivy](https://github.com/aquasecurity/trivy) version 0.59.1
* [Maven](https://github.com/apache/maven) version 3.9.6
* [PIQUE-core](https://github.com/MSUSEL/msusel-pique) version 1.0.1
* [PIQUE-data](https://github.com/MSUSEL/msusecl-pique-data) version 1.1.0
___

## Run Environment
#### Docker
docker engine 20.10.24 (not tested with versions 21+)

The image for this project is hosted on dockerhub 
[here](https://hub.docker.com/repository/docker/msusel/pique-sbom-supplychain-sec/general). Instructions to download 
and run are supplied [below](https://github.com/MSUSEL/msusel-sbom-supplychain-sec/tree/master#running)


#### not Docker
It is not suggested to run PIQUE-SBOM-SUPPLYCHAIN-SEC without the pre-built docker image, but all files and configs 
are supplied on this repository. 

___

## API Key Requirments
A API key from the National Vulnerability Database and a Github personal access token are needed. See [running](ttps://github.com/MSUSEL/msusel-pique-sbom-supplychainsec/tree/master#running) for details.
- [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
- [Github Token](https://docs.github.com/en/enterprise-server@3.6/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
___

## Running 
1. Download and install [Docker engine](https://docs.docker.com/engine/install/)
2. With Docker engine installed, pull the latest version of this project:
```
docker pull msusel/pique-sbom-supply-chain-sec:latest
```
4. Navigate to a working directory for this project
5. Create two directories, "input" and "out". Inside the "input directory", create two directories "keys" and "projects"
6. Generate an NVD API key [here](https://nvd.nist.gov/developers/request-an-api-key) and save the text of the key to a file 'nvd-api-key.txt'
7. Generate a [Github API token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) and save the text of the key to a file 'github-token.txt' 
8. Move the files 'nvd-api-key.txt' and 'github-token.txt' to the 'input/keys' directory.
9. There are two options for input projects. If you have already generated SBOMs
   place any number of SBOMs to be analyzed in input/projects/SBOM. If you wish to assess the
   software supply chain security quality of a project but you haven't built an SBOM simply place
   the root folder of the project in input/projects/sourceCode. The resulting SBOMs will be 
   placed in input/projects/SBOM and the model will continue as normal.
10. The resulting directory structure should look like this:
```
├── $WORKDIR
│   ├── input
│   │   ├── keys
│   │   │   ├── github-token.txt
│   │   │   ├── nvd-api-key.txt
│   │   ├── projects
│   │   │   ├── SBOM
│   │   │   │   ├── place SBOMs to analyze here (SPDX or CycloneDX in json format)
│   │   │   ├── sourceCode
│   │   │   │   ├── place source code file systems to generate SBOMs for here 
│   │   │   ├── images
│   │   │   │   ├── place text files with docker image name and tag here ([name]:[tag])
│   ├── out
```
11. Run the command (replace `/path/to/working/directory` to absolute path of `$WORKDIR`)
```
docker run -it --rm -v "/var/run/docker.sock:/var/run/docker.sock:rw" -v /path/to/working/directory/input:/input -v /path/to/working/directory/out:/out msusel/pique-sbom-supply-chain-sec:latest
```
12. Results will be generated in the 'out' directory
___

## Funding Agency:

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)
