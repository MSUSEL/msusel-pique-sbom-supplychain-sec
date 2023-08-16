FROM alpine:3.14

RUN echo "start"

	    # COPIED FROM PIQUE-BIN-DOCKER #
#--------------------------------------------------------#
# need for tzdata config
# might delet don't think i need rust?
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
ENV RUST_VERSION=1.60.0
#add rust to PATH
ENV PATH="/root/.cargo/bin:/opt/apache-maven-3.8.5/bin:$PATH"

RUN echo "start apk update"

RUN apk update && apk add \
	## pique bin
	openjdk8 \
	## commenting for now because no operational PIQUE model uses GAMs
	# r-base \
	# r-base-core \
	# r-recommended \
	# r-base-dev \
	## sbomqs  # deleted lines relating to tools in pique-bin, currenlty i think wget is the only thing needed (possibly tar?)
	wget

RUN echo "start go"


# move to home for a fresh start and create directories
WORKDIR "/home"

## go installs
RUN wget "https://go.dev/dl/go1.20.5.linux-amd64.tar.gz"
RUN tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
RUN export PATH=$PATH:/usr/local/go/bin
RUN export GOPATH="$HOME/go"
PATH="$GOPATH/bin:$PATH"

RUN echo "start sbomqs"

## sbomqs installs
RUN go install "github.com/interlynk-io/sbomqs@v0.0.17"
RUN export INTERLYNK_DISABLE_VERSION_CHECK=true

RUN echo "start scorecard"

## sbom-scorecard installs
RUN go install "github.com/ebay/sbom-scorecard/cmd/sbom-scorecard@0.0.7"

RUN echo "finish"










