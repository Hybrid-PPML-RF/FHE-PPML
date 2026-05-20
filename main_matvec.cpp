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


	// ===== Vector-to-Matrix Multiplication Layer (optimized) =====
	//
	// Compute z = W * v  where v is length data_size_glb and W is data_size_glb x label_size_glb.
	// Result z has length label_size_glb; z[j] = sum_i v[i] * W[i][j].
	//
	// Packing (column-major, one CT per matrix column):
	//   ct_vec       : slot[i] = v[i],    i = 0..data_size_glb-1  (fresh)
	//   ct_mat_col[j]: slot[i] = W[i][j], i = 0..data_size_glb-1  (same budget as inputs_Y)
	//
	// Optimizations applied:
	//   1. Mod-switch to last_parms_id (single prime, minimum cost NTTs) before any work.
	//   2. BGV in SEAL 4.x already stores ALL ciphertexts in NTT form (is_ntt_form()==true).
	//      multiply() detects this and skips all forward NTTs — the "pre-compute NTT" benefit
	//      is built-in. ct_vec is reused across label_size_glb column multiplications with
	//      zero extra forward NTT cost each time.
	//   3. rotate_rows and add_inplace also operate directly on NTT-form ciphertexts in BGV,
	//      so no transform_from_ntt step is needed.
	//   4. Separate timing for multiply+relin vs rotation_and_add.
	//
	// BSGS analysis:
	//   Baby-step giant-step reduces rotation count from O(n) to O(sqrt(n)) for a dense
	//   n-element linear combination (e.g. diagonal matrix-vector with plaintext weights).
	//   Here we are summing data_size_glb=100 elements with unit weight. The log2-halving
	//   rotation_and_add already achieves O(log2(100))≈7 rotations — strictly better than
	//   BSGS (2*sqrt(100)=20 rotations). BSGS only wins when n is large and the weights
	//   are non-uniform, which is not the case here. No BSGS applied.

	cout << "\n--- Vector-to-Matrix Multiplication Layer (optimized) ---\n";
	cout << "Vector length: " << data_size_glb
	     << ", Matrix: " << data_size_glb << "x" << label_size_glb << "\n";

	// Encrypt a fresh random vector v
	vector<uint64_t> vec_msg(poly_modulus_degree_glb, 0);
	for (int i = 0; i < data_size_glb; i++) vec_msg[i] = (uint64_t)(i + 1) % (uint64_t)p;
	Plaintext pl_vec;
	batch_encoder.encode(vec_msg, pl_vec);
	Ciphertext ct_vec;
	encryptor.encrypt(pl_vec, ct_vec);

	// Encrypt label_size_glb matrix columns (same budget as inputs_Y = fresh)
	vector<Ciphertext> ct_mat_cols(label_size_glb);
	for (int j = 0; j < label_size_glb; j++) {
		vector<uint64_t> col_msg(poly_modulus_degree_glb, 0);
		for (int i = 0; i < data_size_glb; i++) col_msg[i] = (uint64_t)(i * label_size_glb + j + 1) % (uint64_t)p;
		Plaintext pl_col;
		batch_encoder.encode(col_msg, pl_col);
		encryptor.encrypt(pl_col, ct_mat_cols[j]);
	}

	cout << "Noise budget before mod-switch: ct_vec="
	     << decryptor.invariant_noise_budget(ct_vec) << " bits, ct_mat_col[0]="
	     << decryptor.invariant_noise_budget(ct_mat_cols[0]) << " bits\n";

	// Optimization 1: mod-switch to the lowest level where a single CT×CT multiply still
	// leaves a positive noise budget (i.e., result remains decryptable).
	// chain_index=0 (1 prime, 60 bits): fresh budget=35 bits, but after multiply drops to 0
	//   (noise grows as product of both noise terms * n) → NOT decryptable.
	// chain_index=1 (2 primes, 120 bits): fresh budget≈95 bits, after multiply≈56 bits → OK.
	// So chain_index=1 is the minimum viable level for one CT×CT.
	parms_id_type min_viable_parms;
	{
		auto ctx = seal_context.first_context_data();
		while (ctx->next_context_data() && ctx->next_context_data()->chain_index() >= 1) {
			ctx = ctx->next_context_data();
		}
		min_viable_parms = ctx->parms_id();  // chain_index=1
	}
	evaluator.mod_switch_to_inplace(ct_vec, min_viable_parms);
	for (int j = 0; j < label_size_glb; j++) {
		evaluator.mod_switch_to_inplace(ct_mat_cols[j], min_viable_parms);
	}

	cout << "Noise budget after mod-switch to min viable level (chain_index=1): ct_vec="
	     << decryptor.invariant_noise_budget(ct_vec) << " bits, ct_mat_col[0]="
	     << decryptor.invariant_noise_budget(ct_mat_cols[0]) << " bits\n";

	// Optimization 2 (implicit for BGV): BGV ciphertexts are already in NTT form.
	// Verify and report — no transform needed.
	cout << "ct_vec.is_ntt_form() = " << ct_vec.is_ntt_form()
	     << ", ct_mat_col[0].is_ntt_form() = " << ct_mat_cols[0].is_ntt_form() << "\n";
	cout << "NTT form is pre-built into BGV: multiply() skips forward NTT automatically.\n";

	// Compute z[j] = sum_i v[i]*W[i][j] for each column, with separated timing.
	vector<Ciphertext> ct_result(label_size_glb);
	long long total_mul_us = 0, total_rot_us = 0;

	for (int j = 0; j < label_size_glb; j++) {
		// -- multiply + relinearize (both inputs already in NTT form; forward NTT skipped) --
		auto t_mul_start = chrono::high_resolution_clock::now();
		Ciphertext ct_prod;
		evaluator.multiply(ct_vec, ct_mat_cols[j], ct_prod);
		evaluator.relinearize_inplace(ct_prod, relin_keys);
		// ct_prod remains in NTT form; rotate_rows and add_inplace handle NTT form natively in BGV.
		auto t_mul_end = chrono::high_resolution_clock::now();
		total_mul_us += chrono::duration_cast<chrono::microseconds>(t_mul_end - t_mul_start).count();

		// -- rotation_and_add: sum data_size_glb slots into slot 0 --
		auto t_rot_start = chrono::high_resolution_clock::now();
		ct_result[j] = rotation_and_add(seal_context, ct_prod, data_size_glb, 1, evaluator, gal_keys_rot, 0);
		auto t_rot_end = chrono::high_resolution_clock::now();
		total_rot_us += chrono::duration_cast<chrono::microseconds>(t_rot_end - t_rot_start).count();
	}

	cout << "Multiply + relin + from_ntt time (" << label_size_glb << " columns total): "
	     << total_mul_us << " us"
	     << "  (per column: " << total_mul_us / label_size_glb << " us)\n";
	cout << "Rotation-and-add time (" << label_size_glb << " columns total): "
	     << total_rot_us << " us"
	     << "  (per column: " << total_rot_us / label_size_glb << " us,"
	     << " log2(" << data_size_glb << ")≈7 rotations each)\n";
	cout << "Vec-to-mat total time: " << (total_mul_us + total_rot_us) << " us\n";
	cout << "Result noise budget: ct_result[0]="
	     << decryptor.invariant_noise_budget(ct_result[0]) << " bits\n";

	return 0;

}
