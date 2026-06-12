#!/bin/bash

PROGRAM="bench_fhe"
BASE_DIR="/home/ubuntu/PPML-MP-SPDZ"
#N_C_LIST=("18,3" "16,3" "44,3" "32,3" "108,3" "48,2" "136,10" "64,10")
N_C_LIST=("16,3" "32,3" "48,2" "64,10")

DEPTH_LIST=(4 5 6)
TIMESTAMP=$(date +"%Y%m%d_%H%M")

for NC in "${N_C_LIST[@]}"; do
  IFS=',' read -r N C <<< "$NC"
  for DEPTH in "${DEPTH_LIST[@]}"; do

    EXECUTABLE="${PROGRAM}-${N}-${C}-${DEPTH}"
    echo ">>> Running $EXECUTABLE"

    # Kill old processes
    for i in $(seq 0 9); do
      ssh pkill -f sy-shamir-party.x || true
    done
    sleep 2

    # Launch all 10 parties in parallel
    for i in $(seq 0 9); do
      LOG_FILE="logs/party$i-${EXECUTABLE}-${TIMESTAMP}.log"

      if [ "$i" -eq 0 ]; then
          cd $BASE_DIR &&
          mkdir -p logs &&
          nohup ./sy-shamir-party.x -ip ip_parties.txt -lgp 282 -p 0 -N 10 -B 4 $EXECUTABLE > $LOG_FILE 2>&1 & &
        # Optionally follow logs:
        sleep 1
        ssh party0 "tail -n +1 -f $BASE_DIR/$LOG_FILE" &
      else
          cd $BASE_DIR &&
          mkdir -p logs &&
          nohup ./sy-shamir-party.x -ip ip_parties.txt -lgp 282 -p $i -N 10 -B 4 $EXECUTABLE > $LOG_FILE 2>&1 & &
      fi
    done

    echo "Waiting for $EXECUTABLE to finish..."
    # Wait for all parties to finish
    while true; do
      sleep 5
      ALL_DONE=true
      for i in $(seq 0 9); do
        if  pgrep -f sy-shamir-party.x > /dev/null; then
          ALL_DONE=false
          break
        fi
      done
      if $ALL_DONE; then
        break
      fi
    done

    echo " Done: $EXECUTABLE"
    echo
  done
done
