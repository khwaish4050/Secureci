FROM python:3.12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssh-client git ca-certificates \
  && python -m pip install --no-cache-dir ansible==10.7.0 \
  && rm -rf /var/lib/apt/lists/*

