FROM mcr.microsoft.com/devcontainers/python:0-${VARIANT} AS langchain-dev-base

USER vscode

RUN sudo apt-get update && sudo apt-get install -y \
    wget \
    unzip \
    libglib2.0-0 \
    libnss3 \
    libgconf-2-4 \
    libfontconfig1 \
ARG CHROME_DRIVER_VERSION=118.0.5993.70
RUN sudo wget https://chromedriver.storage.googleapis.com/$CHROME_DRIVER_VERSION/chromedriver_linux64.zip \
    && sudo unzip chromedriver_linux64.zip -d /usr/local/bin \
    && sudo rm chromedriver_linux64.zip
FROM python:3.11.5

COPY . /app

WORKDIR /app
RUN pip install -r requirements.txt

CMD python updater.py && web_server.py

