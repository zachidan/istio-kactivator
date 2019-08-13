#!/bin/bash
set -e
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o kactivator cmd/main.go
docker rmi kactivator || true
docker rmi registry.eu-gb.bluemix.net/hrl-istio/kactivator-adapter || true
docker build -t kactivator .
docker tag kactivator registry.eu-gb.bluemix.net/hrl-istio/kactivator-adapter
