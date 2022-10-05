#!/bin/bash

FILE=/out/make/cli/cipherloc-cli-linux
if [ -f "$FILE" ]
then
  echo "Running from local build"
  $FILE start --emc-url $EMC_URL --token $AGENT_TOKEN; $FILE logs -f;
else
  echo "Running from downloaded bundle"
  enclave-cli start --emc-url $EMC_URL --token $AGENT_TOKEN; enclave-cli logs -f;
fi
