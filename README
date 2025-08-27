# Private Random Forest Training via FHE and MPC

This README provides step by step instructions to reproduce our main results.


### Absrtact

Random forests are among the most widely used machine learning methods, offering strong predictive performance and natural parallelism--properties which make them particularly attractive in collaborative environments. However, existing privacy-preserving solutions for training random forests remain inefficient.

We propose a new protocol that combines threshold fully homomorphic encryption (tFHE) with secure multi-party computation (MPC) to enable efficient random forest training in a multi-server setting.
We apply the authentication used in the malicious-secure MPC protocol to the partial decryption procedure of tFHE to resolve the intractable integrity issue of FHE, which typically involves impractical zero-knowledge proofs.
To further improve efficiency, we apply attribute mapping to reduce the space of potential splitting criteria for a decision tree, while maintaining comparable accuracy.
Combining these tools, we propose an efficient training protocol for random forests, achieving security against a fully malicious adversary under the honest-majority assumption.

We implement and evaluate our protocol on real-world datasets of various sizes. Our protocol outperforms both FHE-based and MPC-based solutions by one to two orders of magnitude for datasets of moderate sizes.


## Dependencies


- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/microsoft/SEAL) library 4.1 and all its dependencies
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies,\
  as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead.
- (Optional) [HEXL](https://github.com/intel/hexl) library 1.2.3 (this would accelerate the SEAL operations with an Intel AVX-512 processor)

### Scripts to install the dependencies and build the binary
Notice that the following instructions are based on installation steps on a AWS c5.12xlarge.
```
# If permission required, please add sudo before the commands as needed

sudo apt-get update && sudo apt-get install build-essential
sudo apt-get install autoconf
sudo apt-get install cmake
sudo apt-get install libgmp3-dev
sudo apt-get install libntl-dev # specify version to be 11.4.3-1build1 if not found
sudo apt install gitc
sudo apt-get install unzip

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