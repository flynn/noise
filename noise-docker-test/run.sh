#!/bin/bash
VAL=$1
if [ $VAL = "1" ]; then
  echo "Loading the Lighthouse"
  LD_LIBRARY_PATH=/home/lib ./nebula -config lighthouse1_config.yml
fi
if [ $VAL = "2" ]; then
  echo "Loading Node1"
  LD_LIBRARY_PATH=/home/lib ./nebula -config node1_config.yml
fi
if [ $VAL = "3" ]; then
  echo "loading Node2"
  LD_LIBRARY_PATH=/home/lib ./nebula -config node2_config.yml
fi