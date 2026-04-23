FROM jenkins/jenkins:lts

USER root

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    git \
    python3 \
    python3-pip \
    python-is-python3 \
  && rm -rf /var/lib/apt/lists/*

USER jenkins

