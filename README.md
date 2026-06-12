# Secure Private Random Forest Training via FHE and MPC

This README provides step by step instructions to reproduce our main results.


## Dependencies


- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/microsoft/SEAL) library 4.1 and all its dependencies
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies,\
  as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead.
- (Optional) [HEXL](https://github.com/intel/hexl) library 1.2.3 (this would accelerate the SEAL operations with an Intel AVX-512 processor)

### Scripts to install the dependencies and build the binary
Notice that the following instructions are based on installation steps on a AWS c6i.32xlarge.
```
# If permission required, please add sudo before the commands as needed

sudo apt-get update && sudo apt-get install build-essential
sudo apt-get install autoconf
sudo apt-get install cmake
sudo apt-get install libgmp3-dev
sudo apt-get install libntl-dev # specify version to be 11.4.3-1build1 if not found
sudo apt install gitc
sudo apt-get install unzip
sudo apt-get install clang git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libsodium-dev libssl-dev libtool python3

# With the ppml.zip, put it under ~/PPML and unzip it into FHE-PPML dir

 # change build_path to where you want the dependency libraries installed
PPMLDIR=~/PPML  
BUILDDIR=$PPMLDIR/FHE-PPML/build

cd $PPMLDIR && git clone -b v1.11.9 https://gitlab.com/palisade/palisade-release
cd palisade-release
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$BUILDDIR -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc
make
make install


cd $PPMLDIR && git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR -DSEAL_USE_INTEL_HEXL=ON 
cmake --build build
cmake --install build

# Optional
# Notice that although we 'enable' hexl via command line, it does not take much real effect on GCP instances
# and thus does not have much impact on our runtime
cd $PPMLDIR && git clone --branch 1.2.3 https://github.com/intel/hexl
cd hexl
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR
cmake --build build
cmake --install build

cd $BUILDDIR
cmake .. -DCMAKE_PREFIX_PATH=$BUILDDIR
make
```

## To Run

```
cd $BUILDDIR
# ./ppml <dataset_no> <depth> <is_bin> <is_sqrt>
./ppml 1 4 1 1
```

### Sample output
After running the command ```./ppml 1 6 1 1```, one should see logs similar to the following:
```
Encoding inputs to 1 ciphertexts...
Preprocessing for all possible threshold values...
   Input X preprocessed.
   Input Y preprocessed.
Preprocess time: 1165791 us.
	Training for level 0 with 1 nodes...
	Training for level 1 with 2 nodes...
	Training for level 2 with 4 nodes...
	Training for level 3 with 8 nodes...
	Training for level 4 with 16 nodes...
	Training for level 5 with 32 nodes...
Calculating the labeling for leaf nodes...
Simulate the packing and extraction...
Training + labeling + packing total runtime: 37384826 us.
```



## To Run MPC
(For a more detailed instruction, see a separate README under mpc folder)
```
echo "MOD = -DGFP_MOD_SZ=5" >> CONFIG.mine
```
- setup MP-SPDZ and SSL connections for 10 parties
- on every party machine:
  Programs/Source/bench_fhe.py
  Programs/Source/random_matrix.py
  Compiler/SC_fun.py
  ip_parties.txt   (in the MP-SPDZ root)

```
make setup
./Scripts/setup-ssl.sh 10
bash compile_bench.sh
bash run_bench.sh
```
- project built at /home/ubuntu/PPML-MP-SPDZ (commit: <your git hash>)


Logs per party in logs/party<i>-bench_fhe-<params>-<timestamp>.log
Look for "Time" lines in party0's log for wall-clock timings.



### Simulating the WAN setting:
We recomment having access to 10 different machines to simulate the communication in a WAN setting. We assume the servers are called `party0, party1, ..., party9` and that we have `ssh` access to them.
   It is also assumed that the SSH login is possible without password. This
   can be achieved using password-less SSH keys. See [this
   tutorial](https://www.digitalocean.com/community/tutorials/how-to-configure-ssh-key-based-authentication-on-a-linux-server)
   for more information.
If the benchmarks are run locally skip to 'Local Simulation'

### Running bench_fhe

1.  Edit  `CONFIG.mine` to run for larger fields:
```
echo "MOD = -DGFP_MOD_SZ=5" >> CONFIG.mine
```

2. Execute the following for the underlying setup and sharing mechanism:

```
make setup
./Scripts/setup-ssl.sh 10
make -j8 sy-shamir-party.x
./compile-parties.sh
./launch-parties.sh
```
Setup-ssl will create the necessary keys for each party. 
The easiest way for benchmarks in multiple machines is to copy all Pi.pem, Pi.key to all machines.

Compile the program to obtain the executable for each party:
   ```
   ./compile-parties-comp.sh
   ./launch-parties-comp.sh
   ```
