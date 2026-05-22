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

int main(int argc, char* argv[]) {

	int dataset = std::stoi(argv[1]);
	int is_sqrt = std::stoi(argv[4]);

	// default as iris
	if (dataset == 1) {
		data_size_glb = 100;
		attr_size_glb = 4;
		sqrt_attr_size_glb = is_sqrt ? 2 : 4;
		value_size_glb = 8;
		label_size_glb = 3;
	} else if (dataset == 2) { // wine
		data_size_glb = 119;
		attr_size_glb = 13;
		sqrt_attr_size_glb = is_sqrt ? 4 : 13;
		value_size_glb = 9;
		label_size_glb = 3;
	} else if (dataset == 3) { // cancer
		data_size_glb = 380;
		attr_size_glb = 30;
		sqrt_attr_size_glb = is_sqrt ? 6 : 30;
		value_size_glb = 18;
		label_size_glb = 2;
	} else { // digit
		data_size_glb = 1203;
		attr_size_glb = 64;
		sqrt_attr_size_glb = is_sqrt ? 8 : 64;
		value_size_glb = 17;
		label_size_glb = 10;
	}

	depth_glb = std::stoi(argv[2]);

	int is_bin = std::stoi(argv[3]);
	if (is_bin) {
		value_size_glb = 8;
	}


	for (auto &i : seed_glb) {
		i = random_uint64();
	}

	int p = 65537;

	EncryptionParameters bgv_params(scheme_type::bgv);
	bgv_params.set_poly_modulus_degree(poly_modulus_degree_glb);

	auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, {
														60, 60, 60, 60, 60, 60, 60
													});

	if (dataset == 4 && depth_glb == 6) {
		auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, {
															60, 30, 60, 60, 60, 60, 60
														});
	}

	bgv_params.set_coeff_modulus(coeff_modulus);
	bgv_params.set_plain_modulus(p);


	prng_seed_type seed;
	for (auto &i : seed) {
		i = random_uint64();
	}
	auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
	bgv_params.set_random_generator(rng);


	SEALContext seal_context(bgv_params, true, sec_level_type::none);
	primitive_root = seal_context.first_context_data()->plain_ntt_tables()->get_root();

	KeyGenerator keygen(seal_context);
	SecretKey bgv_secret_key = keygen.secret_key();

	PublicKey bgv_public_key;
	keygen.create_public_key(bgv_public_key);

	RelinKeys relin_keys, relin_keys_raise;
	keygen.create_relin_keys(relin_keys);

	Encryptor encryptor(seal_context, bgv_public_key);
	Evaluator evaluator(seal_context);
	BatchEncoder batch_encoder(seal_context);
	Decryptor decryptor(seal_context, bgv_secret_key);

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
			steps_rot.push_back((i * data_size_glb) % (poly_modulus_degree_glb / 2));
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
			steps_rot.push_back((i * data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2));
			steps_rot.push_back((-i * data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2));
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

	cout << "Initial noise budget: " << decryptor.invariant_noise_budget(inputs_X[0]) << " bits\n";

	///////////////////////// pre-process the dataset by recording all parition labels based on attr val ////////////////////////////////

	chrono::high_resolution_clock::time_point time_start, time_end, sss, eee;
    time_start = chrono::high_resolution_clock::now();

	vector<vector<Ciphertext>> preprocessed_partitions((int) inputs_X.size());
	vector<vector<vector<Ciphertext>>> preprocessed_partitioned_labels((int) inputs_X.size());

	preprocess_all_threshold(inputs_X, inputs_Y, preprocessed_partitions, preprocessed_partitioned_labels,
							 seal_context, evaluator, encryptor, gal_keys_rot, relin_keys);

	time_end = chrono::high_resolution_clock::now();
	cout << "Preprocess time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";

	/////////////////////////////////////////// for each node, prepare the gini-index inputs ////////////////////////////////////////////
	vector<Ciphertext> selection_vector(pow(2, depth_glb));

	// just fill in random selection vectors...
	for (int i = 0; i < (int) selection_vector.size(); i++) {
		encryptor.encrypt(pl_test, selection_vector[i]);
	}

	// ideally, different nodes should have different partition thresholds, but just for some simulation...
	int threshold_attr_ind = 1, threshold_val_ind = 1;

	vector<vector<vector<Ciphertext>>> partitions_for_node;
	vector<vector<vector<vector<Ciphertext>>>> partition_labels_for_node;

	time_start = chrono::high_resolution_clock::now();
	for (int d = 0; d < depth_glb; d++) { // for each level in the tree, except the root
		bool multi_thread = pow(2,d) >= 4;

		cout << "	Training for level " << d << " with " << pow(2,d) << " nodes...\n";

		partitions_for_node.resize(pow(2,d));
		partition_labels_for_node.resize(pow(2,d));

		for (int ll = 0; ll < pow(2,d); ll++) {
			partitions_for_node[ll].resize((int) preprocessed_partitions.size());
			partition_labels_for_node[ll].resize((int) preprocessed_partitioned_labels.size());
		}

		if (multi_thread) {
			NTL::SetNumThreads(num_cores);
			int thread_chunk_size = pow(2,d) / num_cores;
			NTL_EXEC_RANGE(num_cores, first, last);
			for (int tt = first; tt < last; tt++) {
				for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) { // for each node in this level

					int sel_ind = pow(2, d)-1 + nd;

					vector<vector<Ciphertext>> random_preprocessed_partitions;
					vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
					simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
														   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
														   seal_context, evaluator, gal_keys_rot, !multi_thread);

					perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
											   partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
											   relin_keys, gal_keys_rot, !multi_thread);

					if (d != depth_glb-1) { // no need to update the leaf level
						update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
												seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
					}

				}
			}
			NTL_EXEC_RANGE_END;
		} else {
			for (int nd = 0 ; nd < pow(2, d); nd++) { // for each node in this level
				int sel_ind = pow(2, d)-1 + nd;

				vector<vector<Ciphertext>> random_preprocessed_partitions;
				vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
				simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
													   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
													   seal_context, evaluator, gal_keys_rot, !multi_thread);

				perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
										partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
										relin_keys, gal_keys_rot, !multi_thread);



				if (d != depth_glb-1) { // no need to update the leaf level
					update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
											seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
				}
			}
		}
	}

	cout << "Final noise budget (partition label): " << decryptor.invariant_noise_budget(partition_labels_for_node[0][0][0][0]) << " bits\n";

	// simulate the labeling for leaf nodes...
	cout << "Calculating the labeling for leaf nodes...\n";
	for (int i = 0; i < pow(2, depth_glb-1) / num_cores; i++) { // simulate the time of single thread
		Ciphertext tmp = preprocessed_partitioned_labels[0][0][0];
		if (selection_vector[selection_vector.size()-3].parms_id() != seal_context.last_parms_id()) {
			evaluator.mod_switch_to_next_inplace(selection_vector[selection_vector.size()-3]);
		}
		evaluator.mod_switch_to_inplace(tmp, selection_vector[selection_vector.size()-3].parms_id());
		evaluator.multiply_inplace(tmp, selection_vector[selection_vector.size()-3]);
		evaluator.relinearize_inplace(tmp, relin_keys);
	}

	Plaintext pll;
	pll.resize(poly_modulus_degree_glb);
	pll.parms_id() = parms_id_zero;
	for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
		pll.data()[i] = 1;
	}

	cout << "Simulate the packing and extraction...\n";
	for (int d = 0; d < depth_glb - 2; d++) { // simulate for all intermediary level
		for (int k = 0; k < pow(2,d); k++) { // for all nodes
			for (int i = 0; i < ceil((double) (sqrt_attr_size_glb * (label_size_glb+1) * (2*value_size_glb-1)) / (double) num_cores); i++) { // simulate the single core runtime
				Ciphertext tmp = partitions_for_node[0][0][0];
				if (tmp.parms_id() != seal_context.last_parms_id()) {
					evaluator.mod_switch_to_next_inplace(tmp);
				}
				evaluator.multiply_plain_inplace(tmp, pll);
				evaluator.rotate_rows_inplace(tmp, 1, gal_keys_rot);
				evaluator.add_inplace(tmp, tmp);
			}
		}
	}

	for (int d = 0; d < depth_glb - 2; d++) { // simulate for all intermediary level
		for (int k = 0; k < pow(2,d); k++) { // for all nodes
			for (int i = 0; i < ceil((double) label_size_glb / (double) num_cores); i++) { // simulate the single core runtime
				Ciphertext tmp = partition_labels_for_node[0][0][0][0];
				if (tmp.parms_id() != seal_context.last_parms_id()) {
					evaluator.mod_switch_to_next_inplace(tmp);
				}
				evaluator.multiply_plain_inplace(tmp, pll);
				evaluator.rotate_rows_inplace(tmp, 1, gal_keys_rot);
				evaluator.add_inplace(tmp, tmp);
			}
		}
	}


	time_end = chrono::high_resolution_clock::now();
	cout << "Training + labeling + packing total runtime: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";


	// ===== Vector-to-Matrix Multiplication Layer =====
	//
	// Uses real inputs_Y[0] (column-major: slot[j*data_size_glb + i] = Y[i][j]).
	//
	// SIMD approach: replicate the input vector v across label_size_glb blocks to match
	// the column-major layout. One CT×CT multiply gives all columns simultaneously.
	// A SINGLE rotation_and_add call then sums within each group of data_size_glb:
	//   z[j] = sum_i v[i]*Y[i][j] accumulates at slot[j*data_size_glb].
	//
	// Why no masking is needed: rotation_and_add(n, chunk_size=1) builds the sum at
	// slot[k] using only slots k..k+(n/2)-1 at each halving step. Contaminated slots
	// (upper half of each group) are never read back into slot[k], so all label_size_glb
	// column sums are computed correctly in one pass.
	//   vs old approach (column loop): label_size_glb CT×CT + label_size_glb rot_and_add
	//   new approach: 1 CT×CT + 1 rot_and_add  → (label_size_glb-1) fewer CT×CT multiplies

	cout << "\n--- Vector-to-Matrix Multiplication Layer ---\n";
	cout << "Vector length: " << data_size_glb << ", Matrix: "
	     << data_size_glb << "x" << label_size_glb
	     << " (using real inputs_Y[0])\n";

	// inputs_Y[0] packing: slot[j*data_size_glb + i] = Y[i][j].
	// After training, check its chain_index and mod-switch to chain_index=1.
	Ciphertext ct_Y = inputs_Y[0];
	cout << "inputs_Y[0] noise budget: " << decryptor.invariant_noise_budget(ct_Y)
	     << " bits (chain_index="
	     << seal_context.get_context_data(ct_Y.parms_id())->chain_index() << ")\n";
	while (seal_context.get_context_data(ct_Y.parms_id())->chain_index() > 1)
		evaluator.mod_switch_to_next_inplace(ct_Y);
	cout << "After mod-switch to chain_index=1: "
	     << decryptor.invariant_noise_budget(ct_Y) << " bits\n";

	// Create ct_v_rep: replicate v[i]=1 across label_size_glb blocks to match inputs_Y layout.
	// slot[j*data_size_glb + i] = v[i] for j=0..label_size_glb-1, i=0..data_size_glb-1.
	// (v[i]=1 is the test vector; in production this would be the client's feature vector.)
	vector<uint64_t> v_rep_msg(poly_modulus_degree_glb, 0);
	for (int j = 0; j < label_size_glb; j++)
		for (int i = 0; i < data_size_glb; i++)
			v_rep_msg[j * data_size_glb + i] = 1;
	Plaintext pl_v_rep;
	batch_encoder.encode(v_rep_msg, pl_v_rep);
	Ciphertext ct_v_rep;
	encryptor.encrypt(pl_v_rep, ct_v_rep);
	while (seal_context.get_context_data(ct_v_rep.parms_id())->chain_index() > 1)
		evaluator.mod_switch_to_next_inplace(ct_v_rep);

	// Single CT×CT: slot[j*data_size_glb + i] = v[i] * Y[i][j] for all j,i.
	auto t_mul_start = chrono::high_resolution_clock::now();
	Ciphertext ct_prod;
	evaluator.multiply(ct_v_rep, ct_Y, ct_prod);
	evaluator.relinearize_inplace(ct_prod, relin_keys);
	auto t_mul_end = chrono::high_resolution_clock::now();
	long long mul_us = chrono::duration_cast<chrono::microseconds>(t_mul_end - t_mul_start).count();
	cout << "Noise budget after multiply+relin: "
	     << decryptor.invariant_noise_budget(ct_prod) << " bits\n";

	// Single rotation_and_add over data_size_glb elements: sums all label_size_glb groups
	// simultaneously. Result: slot[j*data_size_glb] = z[j] for j=0..label_size_glb-1.
	auto t_rot_start = chrono::high_resolution_clock::now();
	Ciphertext ct_result = rotation_and_add(seal_context, ct_prod, data_size_glb, 1,
	                                         evaluator, gal_keys_rot, 0);
	auto t_rot_end = chrono::high_resolution_clock::now();
	long long rot_us = chrono::duration_cast<chrono::microseconds>(t_rot_end - t_rot_start).count();
	cout << "Noise budget after rotation_and_add: "
	     << decryptor.invariant_noise_budget(ct_result) << " bits\n";

	// Correctness: decrypt and read slot[j*data_size_glb] for each j.
	// With v[i]=1, z[j] = sum_i Y[i][j] = count of datapoints labeled j.
	Plaintext pl_check;
	decryptor.decrypt(ct_result, pl_check);
	vector<uint64_t> msg_check(poly_modulus_degree_glb, 0);
	batch_encoder.decode(pl_check, msg_check);
	cout << "Results z[j] at slot[j*" << data_size_glb << "] (= class j count with v=all-ones):\n";
	uint64_t total_check = 0;
	for (int j = 0; j < label_size_glb; j++) {
		cout << "  z[" << j << "] = " << msg_check[(size_t)j * data_size_glb] << "\n";
		total_check += msg_check[(size_t)j * data_size_glb];
	}
	cout << "  sum = " << total_check
	     << (total_check == (uint64_t)data_size_glb ? " (PASS: equals data_size_glb)" : " (FAIL)") << "\n";

	cout << "Multiply + relin (1 CT×CT for all " << label_size_glb << " cols): "
	     << mul_us << " us\n";
	cout << "Rotation-and-add (1 call, ~7 rotations): " << rot_us << " us\n";
	cout << "Vec-to-mat total: " << (mul_us + rot_us) << " us\n";

	return 0;

}
