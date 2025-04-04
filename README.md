# MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC
## Introduction
The MSUSEL-PIQUE-SBOM-SUPPLYCHAIN-SEC project offers an operationalized Platform for Investigative Quality
Understanding and Evaluation (PIQUE) model designed to assess security quality within software
supply chains using Software Bill of Materials (SBOM) technology. To address challenges
associated with various development environments and third-party applications, this project
is also available as a standalone Docker image. That image is available That image is available [here](https://hub.docker.com/repository/docker/msusel/pique-sbom-supply-chain-sec/general).

## Features
* Security Assessment: Evaluates the security posture of software supply chains by analyzing SBOMs.
* Tool Integration: Incorporates multiple security tools to provide comprehensive analysis.
* Docker Support: Offers a Docker image for simplified deployment and environment consistency.
___
## Tools
The project relies on the following tools. These will be automatically installed when the Docker image is built, but must 
be manually installed if not using the Docker image.

* [Maven](https://github.com/apache/maven) version 3.9.6
* [PIQUE-core](https://github.com/MSUSEL/msusel-pique) version 1.0.1
* [PIQUE-data](https://github.com/MSUSEL/msusecl-pique-data) version 1.1.0
* [Grype](https://github.com/anchore/grype) version 0.87.0
* [Trivy](https://github.com/aquasecurity/trivy) version 0.59.1
___
## Benchmark Repository
The project is derived on two benchmark repositories. The repositories of SBOMs are avaliable here: [SBOMs](https://zenodo.org/records/15122007)

* NPM repository - 531 popular NPM projects from NPM Registry. Generation tool: [cyclonedx-npm](https://www.npmjs.com/package/@cyclonedx/cyclonedx-npm) version 1.19.3
* Docker Image repsoitory - 995 popular Docker imags from Docker Hub. Generation tools: [Trivy](https://github.com/aquasecurity/trivy) version 0.59.1, [Syft](https://github.com/anchore/syft) version 1.16.0 

___
## Run Environment
#### Docker
docker engine 20.10.24 (not tested with versions 21+)

The image for this project is hosted on dockerhub 
[here](https://hub.docker.com/repository/docker/msusel/pique-sbom-supplychain-sec/general). Instructions to download 
and run are supplied [below](https://github.com/MSUSEL/msusel-sbom-supplychain-sec/tree/master#running)

It is important to note, that the docker image cannot be run without the [msusel/nvd-mirror](https://hub.docker.com/repository/docker/msusel/nvd-mirror/general) image. A docker-compose file is provided that handles this, see Running below.


#### not Docker
It is not suggested to run PIQUE-SBOM-SUPPLYCHAIN-SEC without the pre-built docker image, but all files and configs 
are supplied on this repository. 

___

## API Key Requirments
A Github personal access token are needed. See [running](ttps://github.com/MSUSEL/msusel-pique-sbom-supplychainsec/tree/master#running) for details.
- [Github Token](https://docs.github.com/en/enterprise-server@3.6/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
___

## Running 
1. Download and install [Docker engine](https://docs.docker.com/engine/install/)
2. Navigate to a working directory for this project
2. Run the following command to download the docker-compose file:
```
curl -o docker-compose.yml https://raw.githubusercontent.com/MSUSEL/msusel-pique-sbom-supplychain-sec/refs/heads/master/docker-compose.yml
```
5. Generate a [Github API token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) and save the text of the key to a file 'github-token.txt'
6. Place the Github API token in a file named `.env` in the format `GITHUB_PAT=[your token]`
6. Create two directories, "input" and "out". Inside the "input directory", create a directory "projects" inside "projects" create three directories "SBOM", "sourceCode", and "images"
8. There are three options for input projects. If you have already generated SBOMs
   place any number of SBOMs to be analyzed in input/projects/SBOM. If you wish to assess the
   software supply chain security quality of a project but you haven't built an SBOM simply place
   the root folder of the project in input/projects/sourceCode. The resulting SBOMs will be 
   placed in input/projects/SBOM and the model will continue as normal. If you wish to assess the software supply
    chain security quality of a docker image, place a text file with the name and tag of the image in input/projects/images.
9. Select derived model to use via the command line argument `--derived_model`: `npm, npm-trimmed, docker, docker-trimmed` (this is found in the docker-compose.yml file, the default is `npm-trimmed`)
   - `npm` - uses the model derived from the NPM benchmark repository
   - `npm-trimmed` - uses the model derived from the NPM benchmark repository with tree trimming
   - `docker` - uses the model derived from the Docker image benchmark repository
   - `docker-trimmed` - uses the model derived from the Docker image benchmark repository with tree trimming
10. The resulting directory structure should look like this:
```
├── $WORKDIR
│   ├── input
│   │   ├── projects
│   │   │   ├── SBOM
│   │   │   │   ├── place SBOMs to analyze here (SPDX or CycloneDX in json format)
│   │   │   ├── sourceCode
│   │   │   │   ├── place source code file systems to generate SBOMs for here 
│   │   │   ├── images
│   │   │   │   ├── place text files with docker image name and tag here ([name]:[tag])
│   ├── out
│   ├── .env
```
11. Run the command:
```
docker compose up
```

12. Once the tool has finished running, exit the environment with `CTRL-C`.

13. Results will be generated in the 'out' directory (permissions for outputted files may need to be changed with `sudo chown -R $USER:$USER [file name]`)
___

## Funding Agency:

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)
