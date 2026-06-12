#!/bin/bash


#!/bin/bash

PROGRAM="bench_fhe_naive"
COMPILEF="bench_fhe_naive.py"
BASE_DIR="/home/ubuntu/PPML-MP-SPDZ"

TIMESTAMP=$(date +"%Y%m%d_%H%M")

X_LIST=(12600 36652 205200 3435768 11200 26656 91200 1616823)
DEPTH_LIST=(4 5 6)

# Compile for each combination
for X in "${X_LIST[@]}"; do
  for DEPTH in "${DEPTH_LIST[@]}"; do
    echo "Compiling for X=$X, DEPTH=$DEPTH"

    for i in $(seq 0 9); do
      ssh party$i "
        cd $BASE_DIR &&
        ./compile.py $COMPILEF $X $DEPTH" &
    done

    wait  # Wait for all SSHs to complete before the next set
  done
done
