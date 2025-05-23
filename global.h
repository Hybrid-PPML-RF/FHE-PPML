#pragma once
#include "seal/seal.h"
using namespace seal;

size_t poly_modulus_degree_glb = 32768;

// (root, ring_dim) --> root^(2*ring_dim) % 65527 = 1
// (4, 8), (2, 16), (255, 32), (141, 128), (431, 512), (21, 2048), (15, 8192), (3, 32768)
int primitive_root = 3;

int data_size_glb = 100;
int attr_size_glb = 4;
int value_size_glb = 9;
int label_size_glb = 3;

prng_seed_type seed_glb;

int depth_glb = 4; // decision tree depth

int num_cores = 4;