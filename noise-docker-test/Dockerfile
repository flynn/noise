# BASE DOCKER IMAGE
FROM ubuntu:jammy

# VARIABLES
#ARG VER=${VER}

# download from the staging server since pre-releases are present there
#ARG URL=https://app.staging.emc.enclave.cipherloc.net/agents/downloads/v${VER}/
#ARG FIL=enclave-cli_${VER}_x64.deb

# MOVE FILES INTO POSITION
COPY ./_docker.sh /home
RUN mkdir /home/lib
COPY ./lib /home/lib
COPY ./nebula /home
COPY ./nebula-cert /home
COPY ./*.crt /home/
COPY ./*.key /home/
COPY ./*.yml /home/
COPY ./run.sh /home/

# SET DEFAULT DIRECTORY
WORKDIR /home

# INSTALL DEPENDENCIES
RUN apt update
RUN apt install -y \
  curl \
  libfido2-dev \
  libssl-dev \
  iputils-ping \
  netcat \
  net-tools \
  systemctl \
  nano \
  iperf3

# START CLI
CMD tail -f /dev/null