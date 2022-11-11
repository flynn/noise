#!/bin/bash
cd ../
cp -fv cipher_suite.go ~/go/pkg/mod/github.com/cipherloc/noise@v1.0.0/
cd ../nebula
echo "Building Nebula"
go build ./cmd/nebula
cp -fv nebula ../noise/noise-docker-test/
sleep 3
cd ../noise/noise-docker-test
docker-compose build
docker-compose up