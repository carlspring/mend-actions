FROM ubuntu:23.10

LABEL Description="This is Docker image with some intentional vulnerabilities for testing purposes."
LABEL authors="martin.todorov@sap.com"

ARG user=ubuntu

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_MAJOR=18

RUN mkdir -p /etc/apt/keyrings

# Install core tools, so that we can add more repositories and do a non-repetitive apt update later on
RUN apt-get update && \
    apt-get install -y curl \
                       expect \
                       gnupg \
                       gnupg2 \
                       libssl-dev \
                       sudo \
                       wget

# Update the package lists and install necessary packages
RUN apt-get update && \
    apt-get install -y apt-transport-https \
                       apt-utils \
                       bash \
                       ca-certificates \
                       git \
                       jq \
                       mc \
                       python3-apt \
                       python3-dev \
                       python3-pip \
                       python3-venv \
                       tree \
                       unzip \
                       vim \
                       yq \
                       && \
    apt-get clean

ARG GNUPGHOME=/tmp/gnupg

# Clean up
RUN apt autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# List the versions of the installed tools
RUN bash --version && \
    git --version

USER ${user}
