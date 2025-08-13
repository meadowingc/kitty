#!/usr/bin/env bash

# run forever, even if we fail
while true; do
    git pull
    ./tailwindcss -i assets/css/tailwind.css -o assets/css/main.css --minify
    go build -tags release -o kitty
    ./kitty
    sleep 1
done