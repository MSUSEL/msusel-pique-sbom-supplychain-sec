FROM alpine:3.14

	    # COPIED FROM PIQUE-BIN-DOCKER #
#--------------------------------------------------------#
RUN apk update && apk add \
	## pique sbom content
	openjdk8 \
	git \
	py3-pip \
	maven \
	## grype
	curl \
	## trivy
	wget \
	dpkg

# move to home for a fresh start
WORKDIR "/home"

## python package installs
RUN pip install argparse requests

## grype installs
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v0.65.2

## trivy installs
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.44.1/trivy_0.44.1_Linux-64bit.deb
RUN dpkg --add-architecture amd64
RUN dpkg -i trivy_0.44.1_Linux-64bit.deb
RUN rm trivy_0.44.1_Linux-64bit.deb

## PIQUE ##
# maven install - install in opt
WORKDIR "/opt"
RUN wget "https://dlcdn.apache.org/maven/maven-3/3.8.8/binaries/apache-maven-3.8.8-bin.tar.gz"
RUN tar xzvf apache-maven-3.8.8-bin.tar.gz
RUN rm apache-maven-3.8.8-bin.tar.gz
RUN export PATH="/opt/apache-maven-3.8.3/bin:$PATH"

# pique install
WORKDIR "/home"
RUN git clone https://github.com/MSUSEL/msusel-pique.git
WORKDIR "/home/msusel-pique"
RUN mvn --version
RUN mvn install -Dmaven.test.skip

# pique sbom supply chain sec (docker) install
#WORKDIR "/home"
#RUN git clone https://github.com/MSUSEL/msusel-pique-sbom-supplychainsec.git
#WORKDIR "/home/msusel-pique-sbom-supplychainsec"
#RUN mvn package -Dmaven.test.skip
#
### sbomqs install
#WORKDIR "/home/msusel-pique-sbom-supplychainsec/src/main/resources"
#RUN export INTERLYNK_DISABLE_VERSION_CHECK=true
#RUN curl -LJ -o sbomqs https://github.com/interlynk-io/sbomqs/releases/download/v0.0.17/sbomqs-linux-amd64
#RUN chmod a+x sbomqs
#WORKDIR "/home/msusel-pique-sbom-supplychainsec"

# create input directory
RUN mkdir "/input"
# input for project files
VOLUME ["/input"]

# create output directory
RUN mkdir "/output"
# output for model
VOLUME ["/output"]

RUN chmod -R +x /input
RUN chmod -R +x /output

##### secret sauce
#ENTRYPOINT ["java", "-jar", "/home/msusel-pique-bin-docker/target/msusel-pique-bin-0.0.1-jar-with-dependencies.jar"]
