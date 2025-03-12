#
# MIT License
#
# Copyright (c) 2023 Montana State University Software Engineering Labs
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

FROM msusel/pique-core:1.0.1

## dependency and library versions
ARG PIQUE_SBOM_VERSION=2.0
ARG GRYPE_VERSION=0.87.0
ARG TRIVY_VERSION=0.59.1


#--------------------------------------------------------#
RUN apk update && apk upgrade && apk add --update --no-cache \
    curl python3 py3-pip dpkg docker openrc wget go docker-compose

# add user to docker group
RUN addgroup root docker
RUN rc-update add docker boot

# move to home for a fresh start
WORKDIR "/home"

##################################################
############ SBOM analysis tool install ##########
##################################################

## grype installs
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v$GRYPE_VERSION
RUN grype db update

## trivy installs
RUN wget "https://github.com/aquasecurity/trivy/releases/download/v"$TRIVY_VERSION"/trivy_"$TRIVY_VERSION"_Linux-64bit.deb"
RUN dpkg --add-architecture amd64
RUN dpkg -i "trivy_"$TRIVY_VERSION"_Linux-64bit.deb"
RUN rm "trivy_"$TRIVY_VERSION"_Linux-64bit.deb"

RUN trivy image --download-db-only
RUN trivy image --download-java-db-only

##################################################
############ pique data install ##################
##################################################

ENV PG_DRIVER="jdbc:postgresql"
ENV PG_HOSTNAME="localhost"
ENV PG_PORT="5433"
ENV PG_DBNAME="nvd_mirror"
ENV PG_USERNAME="postgres"
ENV PG_PASS="postgres"

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

## REMOVE
RUN git fetch origin deployment2
RUN git checkout deployment2

# build pique sbom supply chain sec
RUN mvn package -Dmaven.test.skip

# create input directory
RUN mkdir "/input"

# input for project files
VOLUME ["/input"]

# output for model
VOLUME ["/out"]

# symlink to jar file for cleanliness
#RUN chmod +x "/home/msusel-pique-sbom-supplychain-sec/target/msusel-pique-sbom-supplychain-sec-"$PIQUE_SBOM_VERSION"-jar-with-dependencies.jar"
RUN ln -s "/home/msusel-pique-sbom-supplychain-sec/target/msusel-pique-sbom-supplychain-sec-"$PIQUE_SBOM_VERSION"-jar-with-dependencies.jar" \
        "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar"
#RUN chmod +x /home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar

#RUN ls "/home/msusel-pique-sbom-supplychain-sec"

##### secret sauce
#ENTRYPOINT ["java", "-jar", "/home/msusel-pique-sbom-supplychain-sec/docker_entrypoint.jar", "--runType", "evaluate"]
#ENTRYPOINT ["ls", "/home/msusel-pique-sbom-supplychain-sec"]
#CMD ["--gen_tool", "none"]
