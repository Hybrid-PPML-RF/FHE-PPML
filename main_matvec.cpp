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
	// Why chain_index=1 (95 bits) is the minimum in the training context:
	//   chain_index=0 has 1 prime → CT×CT multiply fails (needs ~67-bit prime, SEAL max=61).
	//   chain_index=1 gives 56 bits AFTER the full pipeline — much more than needed.
	//
	// Solution: dedicated minimal BGV context with {comp, comp, special...} primes.
	//   - 2 small computation primes for the chain: tighten the noise budget.
	//   - Extra 60-bit "special" primes: improve key-switch decomposition quality.
	//     Without the special prime, rotation_and_add fails even with {60,60} (2-prime context
	//     gives only 2 bits after multiply, and each rotation (key-switch) consumes them all).
	//     With 1 extra 60-bit prime, the key-switch key decomposes over 3 primes → rotation cheap.
	//   Empirically: {34,34,60} → at_chain1=43 bits → after_mul=8 → after_rot=2 (PASS).
	//   This context is independent of the training chain, so training is unaffected.
	//
	// BGV note: ciphertexts are already stored in NTT form (is_ntt_form()==true).
	//   multiply() skips forward NTT automatically; no explicit transform needed.
	//
	// BSGS analysis: log2(100)≈7 rotations < 2*sqrt(100)=20 (BSGS), so log2-halving wins.

	// Calibration: find the minimal prime configuration where the full pipeline
	// (CT×CT multiply + relinearize + rotation_and_add over data_size_glb slots)
	// decrypts correctly with ≥1 bit budget remaining.
	//
	// 2-prime contexts fail: key-switch decomposition over only 2 primes is too noisy.
	// Adding extra "special" primes beyond the computation chain improves key-switch quality.
	// We test {comp, comp, 60} (3 primes) and {comp, comp, 60, 60} (4 primes).
	cout << "\n--- Minimal-context calibration ---\n";
	// Each entry: {computation_prime_bits, num_special_60bit_primes}
	struct CalConfig { int comp_pb; int n_special; };
	vector<CalConfig> configs;
	for (int pb : {34, 38, 42, 46, 50, 54, 58, 60}) configs.push_back({pb, 0});
	for (int pb : {34, 38, 42, 46, 50}) configs.push_back({pb, 1});
	for (int pb : {34, 38, 42}) configs.push_back({pb, 2});

	int best_comp_pb = -1, best_n_special = -1;
	for (auto& cfg : configs) {
		vector<int> primes(2, cfg.comp_pb);
		for (int s = 0; s < cfg.n_special; s++) primes.push_back(60);

		EncryptionParameters cal_params(scheme_type::bgv);
		cal_params.set_poly_modulus_degree(poly_modulus_degree_glb);
		cal_params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree_glb, primes));
		cal_params.set_plain_modulus(p);
		SEALContext cal_ctx(cal_params, true, sec_level_type::none);
		KeyGenerator cal_kg(cal_ctx);
		SecretKey cal_sk = cal_kg.secret_key();
		PublicKey cal_pk; cal_kg.create_public_key(cal_pk);
		RelinKeys cal_rk; cal_kg.create_relin_keys(cal_rk);
		vector<int> cal_steps = {1, 2, 3, 6, 12, 24, 25, 50};
		GaloisKeys cal_gk; cal_kg.create_galois_keys(cal_steps, cal_gk);
		Encryptor cal_enc(cal_ctx, cal_pk);
		Evaluator cal_eval(cal_ctx);
		BatchEncoder cal_benc(cal_ctx);
		Decryptor cal_dec(cal_ctx, cal_sk);
		vector<uint64_t> cal_msg(poly_modulus_degree_glb, 1);
		Plaintext cal_pl; cal_benc.encode(cal_msg, cal_pl);
		Ciphertext cal_a, cal_b; cal_enc.encrypt(cal_pl, cal_a); cal_enc.encrypt(cal_pl, cal_b);
		int fresh = cal_dec.invariant_noise_budget(cal_a);
		// Mod-switch down to chain_index=1 (just the 2 computation primes) before multiply
		// so we do the multiply at the tightest level.
		while (cal_ctx.get_context_data(cal_a.parms_id())->chain_index() > 1)
			cal_eval.mod_switch_to_next_inplace(cal_a);
		while (cal_ctx.get_context_data(cal_b.parms_id())->chain_index() > 1)
			cal_eval.mod_switch_to_next_inplace(cal_b);
		int at_chain1 = cal_dec.invariant_noise_budget(cal_a);
		cal_eval.multiply_inplace(cal_a, cal_b);
		cal_eval.relinearize_inplace(cal_a, cal_rk);
		int after_mul = cal_dec.invariant_noise_budget(cal_a);
		cal_a = rotation_and_add(cal_ctx, cal_a, data_size_glb, 1, cal_eval, cal_gk, 0);
		int after_rot = cal_dec.invariant_noise_budget(cal_a);
		Plaintext cal_res_pl; cal_dec.decrypt(cal_a, cal_res_pl);
		vector<uint64_t> cal_res(poly_modulus_degree_glb, 0);
		cal_benc.decode(cal_res_pl, cal_res);
		bool correct = (cal_res[0] == (uint64_t)data_size_glb);
		cout << "  {" << cfg.comp_pb << "," << cfg.comp_pb;
		for (int s=0; s<cfg.n_special; s++) cout << ",60";
		cout << "} total=" << (2*cfg.comp_pb + 60*cfg.n_special)
		     << " bits: fresh=" << fresh << "  at_chain1=" << at_chain1
		     << "  after_mul=" << after_mul << "  after_rot=" << after_rot
		     << (after_rot <= 0 ? " FAIL" : (correct ? " PASS" : " WRONG")) << "\n";
		if (after_rot >= 1 && correct && best_comp_pb < 0) {
			best_comp_pb = cfg.comp_pb;
			best_n_special = cfg.n_special;
		}
	}
	if (best_comp_pb < 0) {
		cout << "No viable config found — using fallback {60,60,60}\n";
		best_comp_pb = 60; best_n_special = 1;
	}
	cout << "Chosen: comp_prime=" << best_comp_pb << " bits, n_special=" << best_n_special << "\n";

	cout << "\n--- Vector-to-Matrix Multiplication Layer (optimized) ---\n";
	cout << "Vector: " << data_size_glb << " elements, Matrix: "
	     << data_size_glb << "x" << label_size_glb << "\n";

	// Build a dedicated minimal BGV context for vec-to-mat using the calibrated config.
	// Primes: 2 small computation primes + best_n_special large primes for key-switch quality.
	vector<int> vm_prime_list(2, best_comp_pb);
	for (int s = 0; s < best_n_special; s++) vm_prime_list.push_back(60);
	EncryptionParameters vm_params(scheme_type::bgv);
	vm_params.set_poly_modulus_degree(poly_modulus_degree_glb);
	vm_params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree_glb, vm_prime_list));
	vm_params.set_plain_modulus(p);
	SEALContext vm_context(vm_params, true, sec_level_type::none);

	KeyGenerator vm_keygen(vm_context);
	SecretKey vm_sk = vm_keygen.secret_key();
	PublicKey vm_pk;  vm_keygen.create_public_key(vm_pk);
	RelinKeys vm_relin;  vm_keygen.create_relin_keys(vm_relin);

	// Galois keys for rotation_and_add: steps needed for data_size_glb=100, chunk_size=1.
	vector<int> vm_steps = {1, 2, 3, 6, 12, 24, 25, 50};
	GaloisKeys vm_gal_keys;
	vm_keygen.create_galois_keys(vm_steps, vm_gal_keys);

	Encryptor vm_enc(vm_context, vm_pk);
	Evaluator vm_eval(vm_context);
	BatchEncoder vm_benc(vm_context);
	Decryptor vm_dec(vm_context, vm_sk);

	// Encrypt known plaintexts (v[i]=1, W[i][j]=1) for correctness verification.
	// Expected: z[j] = sum_i 1*1 = data_size_glb = 100 for each j.
	vector<uint64_t> vec_msg(poly_modulus_degree_glb, 0);
	for (int i = 0; i < data_size_glb; i++) vec_msg[i] = 1;
	Plaintext pl_vec;
	vm_benc.encode(vec_msg, pl_vec);
	Ciphertext ct_vec;
	vm_enc.encrypt(pl_vec, ct_vec);

	// Mod-switch vec and mat down to chain_index=1 (the 2 computation primes only).
	while (vm_context.get_context_data(ct_vec.parms_id())->chain_index() > 1)
		vm_eval.mod_switch_to_next_inplace(ct_vec);

	vector<Ciphertext> ct_mat_cols(label_size_glb);
	for (int j = 0; j < label_size_glb; j++) {
		Plaintext pl_col;
		vm_benc.encode(vec_msg, pl_col);  // all-ones column
		vm_enc.encrypt(pl_col, ct_mat_cols[j]);
		while (vm_context.get_context_data(ct_mat_cols[j].parms_id())->chain_index() > 1)
			vm_eval.mod_switch_to_next_inplace(ct_mat_cols[j]);
	}

	cout << "Minimal context: comp=" << best_comp_pb << " bits x2"
	     << (best_n_special > 0 ? (" + 60 bits x" + to_string(best_n_special) + " special") : "")
	     << "\n";
	cout << "Fresh noise budget: ct_vec=" << vm_dec.invariant_noise_budget(ct_vec) << " bits\n";

	// Compute z[j] = sum_i v[i]*W[i][j] with separate timing.
	vector<Ciphertext> ct_result(label_size_glb);
	long long total_mul_us = 0, total_rot_us = 0;

	for (int j = 0; j < label_size_glb; j++) {
		auto t_mul_start = chrono::high_resolution_clock::now();
		Ciphertext ct_prod;
		vm_eval.multiply(ct_vec, ct_mat_cols[j], ct_prod);
		vm_eval.relinearize_inplace(ct_prod, vm_relin);
		auto t_mul_end = chrono::high_resolution_clock::now();
		total_mul_us += chrono::duration_cast<chrono::microseconds>(t_mul_end - t_mul_start).count();

		auto t_rot_start = chrono::high_resolution_clock::now();
		ct_result[j] = rotation_and_add(vm_context, ct_prod, data_size_glb, 1, vm_eval, vm_gal_keys, 0);
		auto t_rot_end = chrono::high_resolution_clock::now();
		total_rot_us += chrono::duration_cast<chrono::microseconds>(t_rot_end - t_rot_start).count();
	}

	// Verify correctness and report noise.
	Plaintext pl_check;
	vector<uint64_t> msg_check(poly_modulus_degree_glb, 0);
	vm_dec.decrypt(ct_result[0], pl_check);
	vm_benc.decode(pl_check, msg_check);
	cout << "Correctness: slot[0]=" << msg_check[0]
	     << " (expected " << data_size_glb << ") → "
	     << (msg_check[0] == (uint64_t)data_size_glb ? "PASS" : "FAIL") << "\n";
	cout << "Noise budget after multiply+relin+rot: "
	     << vm_dec.invariant_noise_budget(ct_result[0]) << " bits\n";
	cout << "Multiply + relin (" << label_size_glb << " cols): "
	     << total_mul_us << " us  (per col: " << total_mul_us / label_size_glb << " us)\n";
	cout << "Rotation-and-add (" << label_size_glb << " cols): "
	     << total_rot_us << " us  (per col: " << total_rot_us / label_size_glb
	     << " us, ~7 rotations)\n";
	cout << "Vec-to-mat total: " << (total_mul_us + total_rot_us) << " us\n";

	return 0;

}
