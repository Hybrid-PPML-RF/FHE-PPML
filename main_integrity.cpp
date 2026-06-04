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
														34, 34, 34, 34, 34, 34, 34, 34, 34
													});

	if (depth_glb < 6) {
		coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, {
														34, 34, 34, 34, 34, 34, 34, 34
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

	// for preparing all threshold values, rotation and addition
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

	// Integrity check: binary-doubling fill of fill_n = 4*attr_size copies (each block = data_size slots)
	// and label block shift steps (rotate label i to slot 0 before filling).
	{
		int fill_n = 4 * attr_size_glb;
		for (int s = fill_n / 2; s >= 1; s /= 2) {
			int step = s * data_size_glb % (poly_modulus_degree_glb / 2);
			if (step > 0) steps_rot.push_back(step);
		}
		for (int l = 1; l < label_size_glb; l++) {
			int step = l * data_size_glb % (poly_modulus_degree_glb / 2);
			if (step > 0) steps_rot.push_back(step);
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
				for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) {

					int sel_ind = pow(2, d)-1 + nd;

					vector<vector<Ciphertext>> random_preprocessed_partitions;
					vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
					simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
														   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
														   seal_context, evaluator, gal_keys_rot, !multi_thread);

					perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
											   partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
											   relin_keys, gal_keys_rot, !multi_thread);

					if (d != depth_glb-1) {
						update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
												seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
					}

				}
			}
			NTL_EXEC_RANGE_END;
		} else {
			for (int nd = 0 ; nd < pow(2, d); nd++) {
				int sel_ind = pow(2, d)-1 + nd;

				vector<vector<Ciphertext>> random_preprocessed_partitions;
				vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
				simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
													   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
													   seal_context, evaluator, gal_keys_rot, !multi_thread);

				perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
										partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
										relin_keys, gal_keys_rot, !multi_thread);

				if (d != depth_glb-1) {
					update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
											seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
				}
			}
		}
	}

	// simulate the labeling for leaf nodes...
	cout << "Calculating the labeling for leaf nodes...\n";
	for (int i = 0; i < pow(2, depth_glb-1) / num_cores; i++) {
		Ciphertext tmp = preprocessed_partitioned_labels[0][0][0];
		if (selection_vector[selection_vector.size()-3].parms_id() != seal_context.last_parms_id()) {
			evaluator.mod_switch_to_next_inplace(selection_vector[selection_vector.size()-3]);
		}
		evaluator.mod_switch_to_inplace(tmp, selection_vector[selection_vector.size()-3].parms_id());
		evaluator.multiply_inplace(tmp, selection_vector[selection_vector.size()-3]);
		if (i == 0) cout << "	" << decryptor.invariant_noise_budget(tmp) << endl;
		evaluator.relinearize_inplace(tmp, relin_keys);
	}

	Plaintext pll;
	pll.resize(poly_modulus_degree_glb);
	pll.parms_id() = parms_id_zero;
	for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
		pll.data()[i] = 1;
	}

	cout << "Simulate the packing and extraction...\n";
	for (int d = 0; d < depth_glb - 2; d++) {
		for (int k = 0; k < pow(2,d); k++) {
			for (int i = 0; i < ceil((double) (sqrt_attr_size_glb * (label_size_glb+1) * (2*value_size_glb-1)) / (double) num_cores); i++) {
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

	for (int d = 0; d < depth_glb - 2; d++) {
		for (int k = 0; k < pow(2,d); k++) {
			for (int i = 0; i < ceil((double) label_size_glb / (double) num_cores); i++) {
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


	// =========================================================
	// INTEGRITY CHECK: Y' x C' pipeline (one CT×CT, chain 1→0)
	// =========================================================
	cout << "\n=== Integrity check: Y' x C' pipeline ===\n";

	int fill_n = 4 * attr_size_glb;  // number of copies: e.g. 16 for iris

	// Mod switch inputs_Y[0] to chain 3 (CT×CT needs room: chain 3→2, then mod-switch to 0)
	Ciphertext ct_Y_int = inputs_Y[0];
	while ((int)seal_context.get_context_data(ct_Y_int.parms_id())->chain_index() > 3)
		evaluator.mod_switch_to_next_inplace(ct_Y_int);
	cout << "inputs_Y[0] budget at chain 3: " << decryptor.invariant_noise_budget(ct_Y_int) << " bits\n";

	// Binary-doubling fill: creates n copies of a blk-slot block via log2(n) rotation+add steps.
	auto rot_fill = [&](Ciphertext ct, int blk, int n) -> Ciphertext {
		int itr = 1;
		while (itr < n) itr *= 2;
		while (itr > 1) {
			int step = (itr / 2) * blk % (poly_modulus_degree_glb / 2);
			Ciphertext tmp2;
			evaluator.rotate_rows(ct, step, gal_keys_rot, tmp2);
			evaluator.add_inplace(ct, tmp2);
			itr /= 2;
		}
		return ct;
	};

	// Step 1: Y'
	//   For each label i, extract [data_size*i, data_size*(i+1)) from ct_Y_int via CT×PT mask,
	//   shift block to slot 0, fill to fill_n copies via log2(fill_n) rotation+add,
	//   then sum across all labels → Y'.
	Ciphertext Y_prime;
	bool yp_init = false;
	for (int i = 0; i < label_size_glb; i++) {
		// NTT-free binary mask selecting [data_size*i, data_size*(i+1))
		Plaintext mask_pl;
		mask_pl.resize(poly_modulus_degree_glb);
		mask_pl.parms_id() = parms_id_zero;
		for (int j = 0; j < (int)poly_modulus_degree_glb; j++)
			mask_pl.data()[j] = (j >= data_size_glb * i && j < data_size_glb * (i + 1)) ? 1 : 0;
		Ciphertext extracted;
		evaluator.multiply_plain(ct_Y_int, mask_pl, extracted);

		// Shift block to slot 0: rotate rows left by data_size*i
		if (i > 0)
			evaluator.rotate_rows_inplace(extracted,
				data_size_glb * i % (poly_modulus_degree_glb / 2), gal_keys_rot);

		// Fill to fill_n copies
		Ciphertext filled = rot_fill(extracted, data_size_glb, fill_n);

		if (!yp_init) { Y_prime = filled; yp_init = true; }
		else           evaluator.add_inplace(Y_prime, filled);
	}
	cout << "Y' budget: " << decryptor.invariant_noise_budget(Y_prime) << " bits\n";

	// Step 2: C'
	//   Fresh ciphertext with random data in [0, data_size_glb), mod-switched to chain 1,
	//   then filled to fill_n copies via the same binary-doubling pattern as Y'.
	{
		srand(42);
		vector<uint64_t> cp_data(poly_modulus_degree_glb, 0);
		for (int j = 0; j < data_size_glb; j++)
			cp_data[j] = (uint64_t)((rand() % 100) + 1);
		Plaintext cp_pl;
		batch_encoder.encode(cp_data, cp_pl);
		Ciphertext C_prime;
		encryptor.encrypt(cp_pl, C_prime);
		while ((int)seal_context.get_context_data(C_prime.parms_id())->chain_index() > 3)
			evaluator.mod_switch_to_next_inplace(C_prime);
		C_prime = rot_fill(C_prime, data_size_glb, fill_n);
		cout << "C' budget: " << decryptor.invariant_noise_budget(C_prime) << " bits\n";

		// Step 3: H = Y' × C'  (the one CT×CT in this pipeline)
		Ciphertext H;
		evaluator.multiply(Y_prime, C_prime, H);
		evaluator.relinearize_inplace(H, relin_keys);
		cout << "H budget (CT×CT + relin, chain 2): " << decryptor.invariant_noise_budget(H) << " bits\n";

		// Step 4: H' = rotation_and_add(H, data_size, chunk=1)
		//   Sums each data_size-slot block down to one value per block.
		Ciphertext H_prime = rotation_and_add(seal_context, H,
		                                      data_size_glb, 1, evaluator, gal_keys_rot, 0);
		cout << "H' budget: " << decryptor.invariant_noise_budget(H_prime) << " bits\n";

		// Step 5: H'' = rotation_and_add(H', data_size*attr_size, chunk=data_size)
		//   Sums attr_size consecutive per-attribute blocks into one.
		Ciphertext H_pp = rotation_and_add(seal_context, H_prime,
		                                   data_size_glb * attr_size_glb, data_size_glb,
		                                   evaluator, gal_keys_rot, 0);

		// Mod switch to chain 0 and report final budget
		evaluator.mod_switch_to_inplace(H_pp, seal_context.last_parms_id());
		cout << "H'' final noise budget (chain 0): " << decryptor.invariant_noise_budget(H_pp) << " bits\n";
	}

	return 0;

}
