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

/**

x: number of input_X used to encode the whole dataset
y: number of input_Y used to encode the labels of whole dataset
D: size of dataset
L: total number of labels
V: total number of values
A: total number of attributes

 */

int main() {
	for (auto &i : seed_glb) {
		i = random_uint64();
	}

	int p = 65537;

	EncryptionParameters bfv_params(scheme_type::bfv);
	bfv_params.set_poly_modulus_degree(poly_modulus_degree_glb);

	auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, {
														60, 60, 60, 60, 60
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

	GaloisKeys gal_keys, gal_keys_rot;

	vector<int> stepsfirst = {0, 1};
	for (int i = 0; i < log2(poly_modulus_degree_glb/2); i++) {
		stepsfirst.push_back(-(1<<i));
		stepsfirst.push_back((1<<i));
	}
	keygen.create_galois_keys(stepsfirst, gal_keys);

	// for preparing all threshlold values, rotation and addition
	vector<int> steps_rot = {0, 1};
	for (int i = 0; i < 2*value_size_glb; i++) {
		if (i * data_size_glb < poly_modulus_degree_glb / 2) {
			steps_rot.push_back(i * data_size_glb);
		} else {
			steps_rot.push_back(i * data_size_glb - poly_modulus_degree_glb / 2);
		}
	}
	for (int i = data_size_glb; i > 0; i/=2) {
		if (i % 2) {
			steps_rot.push_back(i-1);
		}
		steps_rot.push_back(i);
	}

	int iter = 1;
    while (iter < attr_size_glb) { // round it to a power of 2
        iter *= 2;
    }
	for (int i = 0; i < iter; i++) {
		if (i * data_size_glb * value_size_glb < poly_modulus_degree_glb / 2) {
			steps_rot.push_back(i * data_size_glb * value_size_glb);
			steps_rot.push_back(-i * data_size_glb * value_size_glb);
		}
	}
	

	keygen.create_galois_keys(steps_rot, gal_keys_rot);

	Plaintext pl_test, all_ones;
	vector<uint64_t> msg_test(poly_modulus_degree_glb);

	vector<uint64_t> allones(poly_modulus_degree_glb, 1);
	batch_encoder.encode(allones, all_ones);


	///////////////////////////////////////////// prepare the one-hot encoding for datasets /////////////////////////////////////////////

	vector<Ciphertext> inputs_X, inputs_Y;
	sample_one_hot_encoding_inputs(inputs_X, inputs_Y, data_size_glb, attr_size_glb, value_size_glb, label_size_glb,
								   batch_encoder, encryptor);

	

	///////////////////////// pre-process the dataset by recording all parition labels based on attr val ////////////////////////////////
	
	// for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
	// 	msg_test[i] = 0;
	// }
	// for (int i = 0; i < (int) 20; i++) {
	// 	msg_test[i] = 1;
	// }
	// batch_encoder.encode(msg_test, pl_test);
	// vector<Ciphertext> test_ct(1);
	// encryptor.encrypt(pl_test, test_ct[0]);

	chrono::high_resolution_clock::time_point time_start, time_end;
    time_start = chrono::high_resolution_clock::now();

	vector<vector<Ciphertext>> preprocessed_partitions((int) inputs_X.size());
	vector<vector<vector<Ciphertext>>> preprocessed_partitioned_labels((int) inputs_Y.size());

	preprocess_all_threshold(inputs_X, inputs_Y, preprocessed_partitions, preprocessed_partitioned_labels, batch_encoder,
							 evaluator, encryptor, gal_keys_rot, relin_keys);

	time_end = chrono::high_resolution_clock::now();
	cout << "Preprocess time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";

	

	// Ciphertext output = rotation_and_fill(test_ct[0], data_size_glb, evaluator, gal_keys_rot);

	// // for (int ccc = 0; ccc < 4; ccc++) {
	// decryptor.decrypt(output, pl_test);
	// batch_encoder.decode(pl_test, msg_test);
	// for (int i = 0; i < (int) 1000; i++) {
	// 	cout << msg_test[i] << " ";
	// }

	// cout << endl;
	// // }
	

	/////////////////////////////////////////// for each node, prepare the gini-index inputs ////////////////////////////////////////////
	vector<Ciphertext> selection_vector(pow(2, depth_glb));

	// just fill in random selection vectors...
	for (int i = 0; i < (int) selection_vector.size(); i++) {
		encryptor.encrypt(pl_test, selection_vector[i]);
	}

	// ideally, different nodes should have different partition thresholds, but just for some simulation...
	int threshold_attr_ind = 1, threshold_val_ind = 1; 
	update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, 0, 0,
							batch_encoder, evaluator, relin_keys, gal_keys_rot);

	time_start = chrono::high_resolution_clock::now();
	for (int d = 1; d < depth_glb; d++) { // for each level in the tree, except the root
		bool multi_thread = pow(2,d) >= 4;

		if (multi_thread) {
			NTL::SetNumThreads(num_cores);
			int thread_chunk_size = pow(2,d) / num_cores;
			NTL_EXEC_RANGE(num_cores, first, last);
			for (int tt = first; tt < last; tt++) {
				for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) { // for each node in this level

					int sel_ind = pow(2, d)-1 + nd;
					
					// based on previous parent partition, threshold attribute value, each #data_size chunk record 
					// this step is used just for multiplying the newly updated selection vector
					// sum up each data_size chunk to a single value, and then square it
					vector<vector<Ciphertext>> partitions_for_node((int) preprocessed_partitions.size(),
																   vector<Ciphertext>((int) preprocessed_partitions[0].size()));
					vector<vector<vector<Ciphertext>>> partition_labels_for_node((int) preprocessed_partitioned_labels.size());
					perform_partition_for_node(preprocessed_partitions, preprocessed_partitioned_labels, partitions_for_node, 
											partition_labels_for_node, selection_vector[sel_ind], evaluator,
											relin_keys, gal_keys_rot, !multi_thread);

					cout << decryptor.invariant_noise_budget(partition_labels_for_node[0][0][0]) << endl;

					// send "partition_labels_for_node" and "partitions_for_node" for MPC protocol and receive a specific threshold value for a specific attribute
					// assume that we have the plaintext value indicating which attribute and which threshold value, update the selection vector corresponding

					
					if (d != depth_glb-1) { // no need to update the leaf level
						update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
												batch_encoder, evaluator, relin_keys, gal_keys_rot);

					}

				}
			}
			NTL_EXEC_RANGE_END;
		} else {
			for (int nd = 0 ; nd < pow(2, d); nd++) { // for each node in this level
				int sel_ind = pow(2, d)-1 + nd;
				
				// based on previous parent partition, threshold attribute value, each #data_size chunk record 
				vector<vector<Ciphertext>> partitions_for_node((int) preprocessed_partitions.size());
				vector<vector<vector<Ciphertext>>> partition_labels_for_node((int) preprocessed_partitioned_labels.size());
				perform_partition_for_node(preprocessed_partitions, preprocessed_partitioned_labels, partitions_for_node, 
										partition_labels_for_node, selection_vector[sel_ind], evaluator,
										relin_keys, gal_keys_rot, !multi_thread);

				cout << decryptor.invariant_noise_budget(partition_labels_for_node[0][0][0]) << endl;

				// send "partition_labels_for_node" and "partitions_for_node" for MPC protocol and receive a specific threshold value for a specific attribute
				// assume that we have the plaintext value indicating which attribute and which threshold value, update the selection vector corresponding

				if (d != depth_glb-1) { // no need to update the leaf level
					update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
											batch_encoder, evaluator, relin_keys, gal_keys_rot);
				}
			}
		}
	}

	time_end = chrono::high_resolution_clock::now();
	cout << "Re-partition the data for all nodes time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";


	return 0;

}