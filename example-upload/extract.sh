#!/bin/bash

docker build . -t example-upload-build
id=$(docker create example-upload-build)
docker cp $id:/app/example-upload .
docker rm -v $id
