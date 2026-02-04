#!/usr/bin/env bash

# run forever, even if we fail
# TLS mode is auto-detected: uses TLS if cert/gemini_cert.pem exists, otherwise plaintext
# To force plaintext mode, uncomment: export GEMINI_PLAINTEXT="1"

while true; do
    git pull
    go build -tags release -o kitty
    ./kitty
    sleep 1
done