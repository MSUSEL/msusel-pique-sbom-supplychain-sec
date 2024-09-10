FROM msusel/pique-core:latest

## dependency and library versions
ARG PIQUE_SBOM_VERSION=1.0
ARG GRYPE_VERSION=0.72.0
ARG CVE_BIN_TOOL_VERSION=3.2.1
ARG TRIVY_VERSION=0.44.1
ARG SBOMQS_VERSION=0.0.30


#--------------------------------------------------------#
RUN apk update && apk upgrade && apk add --update --no-cache \
    curl python3 py3-pip dpkg docker openrc wget go

# add user to docker group
RUN addgroup root docker
RUN rc-update add docker boot

# move to home for a fresh start
WORKDIR "/home"

## grype installs
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v$GRYPE_VERSION

## trivy installs
RUN wget "https://github.com/aquasecurity/trivy/releases/download/v"$TRIVY_VERSION"/trivy_"$TRIVY_VERSION"_Linux-64bit.deb"
RUN dpkg --add-architecture amd64
RUN dpkg -i "trivy_"$TRIVY_VERSION"_Linux-64bit.deb"
RUN rm "trivy_"$TRIVY_VERSION"_Linux-64bit.deb"

## todo add CVE-bin-tool install

##################################################
############ pique SBOM install ##################
##################################################

# python dependency installs
# [IMPORTANT the venv declaration is important because the host environment (pique-cloud) might have conflicting dependencies]
RUN python3 -m venv .venv
RUN source .venv/bin/activate
RUN python3 -m pip install argparse requests flask cve-bin-tool==$CVE_BIN_TOOL_VERSION --break-system-packages

WORKDIR "/home"
RUN git clone https://github.com/MSUSEL/msusel-pique-sbom-supplychain-sec
WORKDIR "/home/msusel-pique-sbom-supplychain-sec"


# build pique sbom supply chain sec
RUN mvn package -Dmaven.test.skip

#
### sbomqs install
#WORKDIR "/home/msusel-pique-sbom-supplychain-sec/src/main/resources"
#RUN curl -LJ -o sbomqs releases/download/v$SBOMQS_VERSION/sbomqs-linux-amd64
#RUN chmod a+x sbomqs
ENV PATH=${PATH}:/usr/local/go/bin
ENV GOPATH="${HOME}/go"
ENV PATH="${GOPATH}/bin:${PATH}"
ENV INTERLYNK_DISABLE_VERSION_CHECK=true
RUN go install github.com/interlynk-io/sbomqs@v$SBOMQS_VERSION
WORKDIR "/home/msusel-pique-sbom-supplychain-sec"

# create input directory
RUN mkdir "/input"

# input for project files
VOLUME ["/input"]

# output for model
VOLUME ["/out"]

# symlink to jar file for cleanliness
RUN ln -s "/home/msusel-pique-sbom-supplychain-sec/target/msusel-pique-sbom-supplychain-sec-"$PIQUE_SBOM_VERSION"-SNAPSHOT-jar-with-dependencies.jar" \
        "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar"

##### secret sauce
ENTRYPOINT ["java", "-jar", "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar", "--runType", "evaluate"]
