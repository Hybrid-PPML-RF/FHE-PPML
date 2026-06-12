#!/bin/bash

PROGRAM="bench_fhe-15-3-4"
COMPILEF="bench_fhe.py"
BASE_DIR="/home/ubuntu/PPML-HYBRID-MPC"
TIMESTAMP=$(date +"%Y%m%d_%H%M")

# Compile files
#for i in $(seq 0 9); do
#  ssh party$i "
#  cd $BASE_DIR &&
#  ./compile.py $COMPILEF"
#  #./compile.py  -P 115792089237316195423570985008687907853269984665640564039457584007913129640233 $COMPILEF"
#done


# Launch parties
for i in $(seq 0 9); do
  LOG_FILE="logs/party$i-$TIMESTAMP.log"
  if [ "$i" -eq 0 ]; then
    #ssh party$i "
      cd $BASE_DIR &&
      mkdir -p logs &&
      nohup ./sy-shamir-party.x --verbose  -p $i -N 10 $PROGRAM > $LOG_FILE 2>&1 
    # Wait briefly to let the log file be created
    sleep 1
    ssh party$i "tail -n +1 -f $BASE_DIR/$LOG_FILE" &
  else
    #ssh party$i "
      cd $BASE_DIR &&
      mkdir -p logs &&
      nohup ./sy-shamir-party.x -p $i -N 10 $PROGRAM > $LOG_FILE 2>&1 
      #nohup ./malicious-shamir-party.x -ip ip_parties.txt -p $i -N 10 $PROGRAM > $LOG_FILE 2>&1 &" &
  fi
done
