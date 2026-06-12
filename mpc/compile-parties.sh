#!/bin/bash

PROGRAM="bench_fhe"
COMPILEF="bench_fhe.py"
BASE_DIR="/home/ubuntu/PPML-MP-SPDZ"

# Define N_C_LIST as an array of "n,c" strings
N_C_LIST=("18,3" "16,3" "44,3" "32,3" "108,3" "48,2" "136,10" "64,10")
DEPTH_LIST=(4 5 6)

# Compile for each combination
for NC in "${N_C_LIST[@]}"; do
  IFS=',' read -r N C <<< "$NC"
  for DEPTH in "${DEPTH_LIST[@]}"; do
    echo "Compiling for N=$N, C=$C, DEPTH=$DEPTH"

    for i in $(seq 0 9); do
      ssh party$i "
        cd $BASE_DIR &&
        ./compile.py $COMPILEF $N $C $DEPTH" &
    done

    wait  # Wait for all SSHs to complete before the next set
  done
done
