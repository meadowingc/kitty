#!/usr/bin/env bash

# run forever, even if we fail
export GEMINI_PLAINTEXT="1"

while true; do
    git pull
    go build -tags release -o kitty
    ./kitty
    sleep 1
done