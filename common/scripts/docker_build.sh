#!/bin/bash

version=$(git rev-parse HEAD)

echo "Building version: $version" 

docker build --network=host -t "$1" -t "$1:$version" ${DOCKER_EXTRA} .
