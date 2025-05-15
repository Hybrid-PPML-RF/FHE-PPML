#include "seal/seal.h"
#include "util.h"
#include "global.h"
#include "seal/util/iterator.h"
#include <numeric>
#include <stdio.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

using namespace seal;
using namespace std;

int main() {
	int numcores = 8;
	NTL::SetNumThreads(numcores);

	for (auto &i : seed_glb) {
		i = random_uint64();
	}

	int ring_dim = 32768;
	int p = 65537;

	EncryptionParameters bfv_params(scheme_type::bfv);
	bfv_params.set_poly_modulus_degree(ring_dim);

	auto coeff_modulus = CoeffModulus::Create(ring_dim, {
														60, 60, 60, 60,
														60, 60, 60, 60,
														60, 60, 60, 60
													});
	bfv_params.set_coeff_modulus(coeff_modulus);
	bfv_params.set_plain_modulus(p);


	prng_seed_type seed;
	for (auto &i : seed) {
		i = random_uint64();
	}
	auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
	bfv_params.set_random_generator(rng);


	SEALContext seal_context(bfv_params, true, sec_level_type::none);
	primitive_root = seal_context.first_context_data()->plain_ntt_tables()->get_root();

	KeyGenerator keygen(seal_context);
	SecretKey bfv_secret_key = keygen.secret_key();

	PublicKey bfv_public_key;
	keygen.create_public_key(bfv_public_key);

	RelinKeys relin_keys, relin_keys_raise;
	keygen.create_relin_keys(relin_keys);

	Encryptor encryptor(seal_context, bfv_public_key);
	Evaluator evaluator(seal_context);
	BatchEncoder batch_encoder(seal_context);
	Decryptor decryptor(seal_context, bfv_secret_key);

	GaloisKeys gal_keys, gal_keys_expand, gal_keys_coeff, gal_keys_coeff_second;

	vector<int> stepsfirst = {0, 1};
	for (int i = 0; i < log2(ring_dim/2); i++) {
		stepsfirst.push_back(-(1<<i));
		stepsfirst.push_back((1<<i));
	}
	keygen.create_galois_keys(stepsfirst, gal_keys);

	Plaintext pl_test;
	vector<uint64_t> msg_test(poly_modulus_degree_glb);


	///////////////////////////////////////////// prepare the one-hot encoding for datasets /////////////////////////////////////////////

	vector<Ciphertext> inputs_X, inputs_Y;
	sample_one_hot_encoding_inputs(inputs_X, inputs_Y, data_size_glb, attr_size_glb, value_size_glb, label_size_glb,
								   batch_encoder, encryptor);

	


	///////////////////////// pre-process the dataset by recording all parition labels based on attr val ////////////////////////////////


	/////////////////////////////////////////// for each node, prepare the gini-index inputs ////////////////////////////////////////////


	///////////////////////////////////////// update the selection vector based on MPC result ///////////////////////////////////////////


	return 0;

}