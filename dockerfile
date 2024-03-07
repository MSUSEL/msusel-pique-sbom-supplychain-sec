FROM msusel/pique-core:0.9.5_2

## dependency and library versions
ARG GRYPE_VERSION=0.72.0
ARG PIQUE_SBOM_VERSION=1.0.0
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

##################################################
############ pique SBOM install ##################
##################################################

# python dependency installs
# [IMPORTANT the venv declaration is important because the host environment (pique-cloud) might have conflicting dependencies]
RUN python3 -m venv .venv
RUN source .venv/bin/activate
RUN python3 -m pip install argparse requests flask --break-system-packages

WORKDIR "/home"
RUN git clone https://github.com/MSUSEL/msusel-pique-sbom-supplychain-sec
WORKDIR "/home/msusel-pique-sbom-supplychain-sec"


# build pique sbom supply chain sex
RUN mvn package -Dmaven.test.skip

#
### sbomqs install
#WORKDIR "/home/msusel-pique-sbom-supplychain-sec/src/main/resources"
#RUN export INTERLYNK_DISABLE_VERSION_CHECK=true
#RUN curl -LJ -o sbomqs releases/download/v$SBOMQS_VERSION/sbomqs-linux-amd64
#RUN chmod a+x sbomqs
#WORKDIR "/home/msusel-pique-sbom-supplychain-sec"

# create input directory
RUN mkdir "/input"

# input for project files
VOLUME ["/input"]

# output for model
VOLUME ["/out"]

# symlink to jar file for cleanliness
RUN ln -s "/home/msusel-pique-sbom-supplychain-sec/target/msusel-pique-sbom-supplychain-sec-"$PIQUE_SBOM_VERSION"-jar-with-dependencies.jar" \
        "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar"

##### secret sauce
#ENTRYPOINT ["java", "-jar", "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar", "--runType", "evaluate"]
