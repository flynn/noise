#!/bin/bash

PACKAGE_JSON=`pwd | sed 's/\/packages\/.*//g'`/package.json

# VERSION PARAMETERS NEEDED TO PROCESS
if (($# < 1))
then
    VER=`jq -r .version $PACKAGE_JSON`
    echo "No arguments passed. Defaulting to the version in the package.json file. VER=$VER PROOF=0"
    PROOF=0
elif (($# == 1))
then
    echo "Params will be used. VER=${1} PROOF=0"
    VER=$1
    PROOF=0
elif (($# == 2))
then
    echo "Params will be used. VER=${1} PROOF=${2}"
    VER=$1
    PROOF=$2
fi

# CONSTANTS
IP_1=10.100.0.2
IP_2=10.100.0.3

cleanup() {
    #echo
    # echo "**** CLEANING UP CONTAINERS ****"
    docker-compose --project-directory . stop
}

trap cleanup EXIT

runPingTest () {
    echo
    echo "**** RUNNING TESTS ****"
    echo
    echo "**** PING TEST ****"

    # ---------------------------------
    # NODE #1
    # ---------------------------------
    # PING NODE-2
    # SHOULD SUCCEED
    if !docker exec smoke_node-1_1 ping -c 1 -w 5 $IP_2 &> /dev/null; then
        echo "✗ Ping from node-1 to node-2 failed when it should have succeeded."
        exit 1
    else
        echo "✓ Ping from node-1 to node-2 succeeded"
    fi

    # ---------------------------------
    # NODE #2
    # ---------------------------------
    # echo
    # echo "**** TESTING PING FROM NODE-2 ****"

    # PING NODE-1
    # SHOULD SUCCEED
    if !docker exec smoke_node-2_1 ping -c 1 -w 5 $IP_1 &> /dev/null; then
        echo "✗ Ping from node-2 to node-1 failed when it should have succeeded."
        exit 1
    else
        echo "✓ Ping from node-2 to node-1 succeeded"
    fi
}

runPerfTest() {
    echo
    echo "**** IPERF3 TEST ****"

    # RUN IPERF SERVER IN BKGD PROCESS
    docker exec smoke_node-1_1 iperf3 -s -B $IP_1 -1 &
   
    # CLEAR THE TEMP FILE
    docker exec smoke_node-2_1 rm -f /home/temp.txt

    # RUN IPERF CLIENT
    docker exec smoke_node-2_1 iperf3 -c $IP_1 -t 5 --connect-timeout 30000 --forceflush --logfile /home/temp.txt
    
    # SEE VARS TO SET PROOF AS NEEDED
    if [ "$PROOF" -eq "1" ]; then
        echo
        echo "**** PRINTING PROOF ****"
        docker exec smoke_node-2_1 ls -al /home
        docker exec smoke_node-2_1 cat /home/temp.txt
    fi

    # SCAN TEMP.TXT FOR ERRORS
    echo
    echo "**** IPERF RESULTS ****"
    if docker exec smoke_node-2_1 grep -qi "error" /home/temp.txt; then
        echo "✗ iPerf3 failed"
        exit 1
    else
        echo "✓ iPerf3 succeeded"
    fi
    echo "***********************"
    echo
}

# SET WORKING DIRECTORY
cd $(dirname "$0")

# START THE AGENTS
echo "**** STARTING AGENTS ****"
docker-compose build --build-arg VER=$VER
docker-compose -f ./docker-compose.yml up -d

# CHECK IF CONTAINERS ARE RUNNING
if docker ps | grep -q "smoke_node-1_1"; then
    echo "CONTAINER smoke_node-1_1 IS UP"; 
else 
    echo "CONTAINER smoke_node-1_1 IS DOWN"
    echo "SMOKE TEST FAILED"
    exit 1 
fi

if docker ps | grep -q "smoke_node-2_1"; then 
    echo "CONTAINER smoke_node-2_1 IS UP"
else 
    echo "CONTAINER smoke_node-2_1 IS DOWN"
    echo "SMOKE TEST FAILED"
    exit 1
fi

# WAIT FOR THE CONTAINERS TO START
# AND RECEIVE THEIR SECOND POST
echo
echo "**** WAITING FOR INITIAL CERT DISTRIBUTION (20 SECONDS) ****"
sleep 20

# RUN PING TEST
runPingTest

# RUN IPERFS TEST
runPerfTest
