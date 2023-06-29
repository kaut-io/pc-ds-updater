# ARG arch
# FROM --platform=linux/${arch} python:3.11-alpine
FROM FROM --platform=${BUILDPLATFORM:-linux/amd64} python:3.11-alpine

ARG BUILDPLATFORM

LABEL MAINTAINER="lonkaut@gmail.com"
RUN apk update \
&& apk add curl \
&& curl -L -o /usr/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl \
&& chmod a+x /usr/bin/kubectl

USER nobody

RUN python3 -m venv /tmp/updater/venv

COPY requirements.txt /tmp/updater/
RUN . /tmp/updater/venv/bin/activate && pip install -r /tmp/updater/requirements.txt

COPY main.py /tmp/updater/

CMD . /tmp/updater/venv/bin/activate && exec python3 -u /tmp/updater/main.py