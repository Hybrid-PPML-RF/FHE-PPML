#!/bin/bash

PROGRAM="bench_fhe_naive"
BASE_DIR="/home/ubuntu/PPML-MP-SPDZ"

#X_LIST=(12600 36652 205200 3435768 11200 26656 91200 1616823)
X_LIST=(3435768 11200 26656 91200 1616823)

DEPTH_LIST=(4)
TIMESTAMP=$(date +"%Y%m%d_%H%M")

for X in "${X_LIST[@]}"; do
  for DEPTH in "${DEPTH_LIST[@]}"; do

    EXECUTABLE="${PROGRAM}-${X}-${DEPTH}"
    echo ">>> Running $EXECUTABLE"

    # Kill old processes
    for i in $(seq 0 9); do
      ssh party$i "pkill -f sy-shamir-party.x" || true
    done
    sleep 2

    # Launch all 10 parties in parallel
    for i in $(seq 0 9); do
      LOG_FILE="logs/party$i-${EXECUTABLE}-${TIMESTAMP}.log"

      if [ "$i" -eq 0 ]; then
        ssh party$i "
          cd $BASE_DIR &&
          mkdir -p logs &&
          nohup ./sy-shamir-party.x -ip ip_parties.txt -lgp 128 -p 0 -N 10 -B 4 $EXECUTABLE > $LOG_FILE 2>&1 &" &
        # Optionally follow logs:
        sleep 1
        ssh party0 "tail -n +1 -f $BASE_DIR/$LOG_FILE" &
      else
        ssh party$i "
          cd $BASE_DIR &&
          mkdir -p logs &&
          nohup ./sy-shamir-party.x -ip ip_parties.txt -lgp 128 -p $i -N 10 -B 4 $EXECUTABLE > $LOG_FILE 2>&1 &" &
      fi
    done

    echo "Waiting for $EXECUTABLE to finish..."
    # Wait for all parties to finish
    while true; do
      sleep 5
      ALL_DONE=true
      for i in $(seq 0 9); do
        if ssh party$i pgrep -f sy-shamir-party.x > /dev/null; then
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
