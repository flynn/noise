#!/bin/bash
cd ../
cp -fv cipher_suite.go ~/go/pkg/mod/github.com/cipherloc/noise@v1.0.0/
cd ../nebula
echo "Building Nebula"
go build ./cmd/nebula
sleep 3
cp -fv nebula ../noise-docker-test/
cd ../noise/noise-docker-test
docker-compose build
docker-compose up