#include "seal/seal.h"
#include "util.h"
#include "global.h"
#include "seal/util/iterator.h"
#include <numeric>
#include <stdio.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>
#include <set>
#include <random>

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
	// optional 6th argument: ring dimension (default 16384). Only meant for smoke tests on a small machine (e.g. 8192 for iris,
	// where A*V*n = 3200 still fits in one batching row); the tuned modulus chain was validated for 16384.
	if (argc > 6) poly_modulus_degree_glb = std::stoi(argv[6]);

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

	cout << "Start training with #attr: " << sqrt_attr_size_glb << " #val: " << value_size_glb << endl;

	for (auto &i : seed_glb) {
		i = random_uint64();
	}

	int p = 65537;

	EncryptionParameters bgv_params(scheme_type::bgv);
	bgv_params.set_poly_modulus_degree(poly_modulus_degree_glb);

	// For the oblivious selection-vector update (iris only, see util.h) the chain is
	//     [ 1 base prime ]  +  [ oblivious_levels primes ]  +  [ special prime ]      (all 46 bits)
	// Every level of the chain is consumed by exactly one ciphertext-ciphertext multiplication (followed by one mod switch):
	//     16  squarings of the equality test x^(p-1)            (ObliviousRotation, p-1 = 2^16)
	//   +  3  selector x P, mask of block 0, selection_vector x threshold_data      (first update)
	//   + (depth-2)  one more selection_vector x threshold_data for each further tree level
	//   +  2  deepest level: partitions x selection_vector, and the leaf labeling below, which first mod-switches the selection
	//         vector one level down and then multiplies (i.e. that multiplication is done on the last-but-one level)
	// 46 bits is the smallest prime size for which the noise of the repeated squarings stays at its floor (44 bits diverges at
	// N = 16384, p = 65537).  The base prime only has to hold the noise left at the very end. Tuned with test_oblivious_update_sel.cpp:
	// the deepest selection vector ends with ~15 bits of noise budget (decryption threshold is 0).
	// NOTE: ~1200 bits is far above the 438 bits that N = 16384 allows for 128-bit security (SEAL is run with sec_level_type::none,
	// as before). The 16 squarings alone cost ~740 bits.
	const bool oblivious_update = (dataset == 1);
	int fermat_squarings = 0;
	while ((1 << fermat_squarings) < p - 1) fermat_squarings++;
	const int levels_first_update = fermat_squarings + 3;
	const int oblivious_levels = oblivious_update ? (levels_first_update + max(depth_glb - 2, 0) + 2) : 0;

	vector<int> modulus_bits;
	if (oblivious_update) {
		modulus_bits.push_back(46);
		for (int i = 0; i < oblivious_levels; i++) modulus_bits.push_back(46);
		modulus_bits.push_back(46);
	} else {
		// original chain (plaintext partition criterion)
		modulus_bits.assign(depth_glb < 6 ? 8 : 9, 34);
	}
	auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, modulus_bits);

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

	// (the separate +-2^i key set that used to be generated here was never used; the oblivious expansion needs the negative
	//  powers of two, which are now part of steps_rot)
	GaloisKeys gal_keys_rot;

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
		// all multiples of data_size: none of the rotations below needs them for iris, and every extra Galois key is huge now that
		// the modulus chain has ~25 primes, so they are only generated for the original (non-oblivious) configurations
		if (!oblivious_update) {
			for (int i = 0; i < poly_modulus_degree_glb / data_size_glb; i++) {
				int step = i * data_size_glb % (poly_modulus_degree_glb / 2);
				if (step > 0) steps_rot.push_back(step);
			}
		}
	}


	if (oblivious_update) {
		// expansion of r, the n-slot selector, fold/tile over the A*V blocks of P (all in util.h)
		for (int s : oblivious_update_rotation_steps(data_size_glb, attr_size_glb, value_size_glb)) {
			steps_rot.push_back(s);
		}
	}

	// remove duplicates: every Galois key is large (it grows quadratically with the length of the modulus chain)
	set<int> steps_unique(steps_rot.begin(), steps_rot.end());
	steps_rot.assign(steps_unique.begin(), steps_unique.end());
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

	const bool verify = argc > 5 && std::stoi(argv[5]);   // optional 5th argument: decrypt and check the selection vectors
	vector<vector<int>> plain_x;
	if (oblivious_update && verify) {
		plain_x = obl_decode_dataset(inputs_X[0], decryptor, batch_encoder);
	}

	// The oblivious update multiplies the selector (which sits `fermat_squarings` levels below the top after the equality test)
	// with P, which is built from the partitions of X. So the clients' ciphertexts only need that many levels: switch them down once
	// (this is what a client could do before uploading), which makes preprocessing and all later operations on them cheaper.
	if (oblivious_update) {
		int data_chain = (int) seal_context.first_context_data()->chain_index() - fermat_squarings;
		for (auto& ct : inputs_X) {
			while ((int) seal_context.get_context_data(ct.parms_id())->chain_index() > data_chain) evaluator.mod_switch_to_next_inplace(ct);
		}
		for (auto& ct : inputs_Y) {
			while ((int) seal_context.get_context_data(ct.parms_id())->chain_index() > data_chain) evaluator.mod_switch_to_next_inplace(ct);
		}
		cout << "Inputs switched to chain index " << data_chain << ", budget " << decryptor.invariant_noise_budget(inputs_X[0]) << " bits\n";
	}

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

	// Oblivious update only: cached constants and P (the "x < theta" partitions of all attributes/thresholds packed in ONE ciphertext)
	ObliviousSelCtx oblivious_ctx;
	// the splits that the MPC would output for each internal node, as *fresh* ciphertexts (a, 0, ..., 0) and (theta, 0, ..., 0);
	// the server never sees them in the clear.  Here they are random (the plaintext values are only kept for verification).
	const int num_internal = (1 << (depth_glb - 1)) - 1;
	vector<Ciphertext> split_attr_ct(num_internal), split_val_ct(num_internal);
	vector<int> split_attr_pt(num_internal), split_val_pt(num_internal);

	if (oblivious_update) {
		time_start = chrono::high_resolution_clock::now();
		build_oblivious_sel_ctx(oblivious_ctx, preprocessed_partitions, seal_context, evaluator, batch_encoder, gal_keys_rot);
		time_end = chrono::high_resolution_clock::now();
		cout << "Packing P time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";

		// root: every datapoint is selected (S_0 = 1_N); only the levels below it are computed obliviously
		vector<uint64_t> root_vec(poly_modulus_degree_glb, 1);
		Plaintext root_pl;
		batch_encoder.encode(root_vec, root_pl);
		encryptor.encrypt(root_pl, selection_vector[0]);
		evaluator.mod_switch_to_inplace(selection_vector[0], inputs_X[0].parms_id());

		mt19937 split_rng(2024);
		for (int i = 0; i < num_internal; i++) {
			// theta in [1, V-1]: split is "x < theta" / "x >= theta" (theta = 0 would be an empty left child)
			split_attr_pt[i] = split_rng() % attr_size_glb;
			split_val_pt[i] = 1 + split_rng() % (value_size_glb - 1);
			vector<uint64_t> va(poly_modulus_degree_glb, 0), vv(poly_modulus_degree_glb, 0);
			va[0] = split_attr_pt[i];
			vv[0] = split_val_pt[i];
			Plaintext pa, pv;
			batch_encoder.encode(va, pa);
			batch_encoder.encode(vv, pv);
			encryptor.encrypt(pa, split_attr_ct[i]);
			encryptor.encrypt(pv, split_val_ct[i]);
		}
	} else {
		// just fill in random selection vectors...
		for (int i = 0; i < (int) selection_vector.size(); i++) {
			encryptor.encrypt(pl_test, selection_vector[i]);
		}
	}

	// legacy (plaintext split) path only: ideally, different nodes should have different partition thresholds, but just for some simulation...
	int threshold_attr_ind = 1, threshold_val_ind = 1;

	vector<vector<vector<Ciphertext>>> partitions_for_node;
	vector<vector<vector<vector<Ciphertext>>>> partition_labels_for_node;

	long www = 0;

	time_start = chrono::high_resolution_clock::now();
	for (int d = 0; d < depth_glb; d++) { // for each level in the tree, except the root
		const long long total = 1LL << d;  // integer bit shift, exact and fast
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
					if (nd == 0) sss = chrono::high_resolution_clock::now();
					simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
															random_preprocessed_partitions, random_reprocessed_partitioned_labels,
															seal_context, evaluator, gal_keys_rot, !multi_thread, dataset == 4);
					if (nd == 0) {
						eee = chrono::high_resolution_clock::now();
						www += chrono::duration_cast<chrono::microseconds>(eee - sss).count();
					}
					perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
												partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
												relin_keys, gal_keys_rot, !multi_thread);

					if (d != depth_glb-1) {
						if (oblivious_update) {
							oblivious_update_selection_vector(selection_vector, oblivious_ctx, split_attr_ct[sel_ind], split_val_ct[sel_ind], d, nd,
																			seal_context, evaluator, relin_keys, gal_keys_rot);
						} else {
							update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
																		seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
						}
					}

				}
			}
			NTL_EXEC_RANGE_END;
		} else {
			for (int nd = 0 ; nd < pow(2, d); nd++) {
				int sel_ind = pow(2, d)-1 + nd;

				vector<vector<Ciphertext>> random_preprocessed_partitions;
				vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
				sss = chrono::high_resolution_clock::now();
				simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
													   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
													   seal_context, evaluator, gal_keys_rot, !multi_thread, dataset == 4);
				eee = chrono::high_resolution_clock::now();
				www += chrono::duration_cast<chrono::microseconds>(eee - sss).count();

				perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
										partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
										relin_keys, gal_keys_rot, !multi_thread);

				if (d != depth_glb-1) {
					if (oblivious_update) {
						oblivious_update_selection_vector(selection_vector, oblivious_ctx, split_attr_ct[sel_ind], split_val_ct[sel_ind], d, nd,
																		seal_context, evaluator, relin_keys, gal_keys_rot);
					} else {
						update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
																	seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
					}
				}
			}
		}

	}

	if (oblivious_update && verify) {
		int wrong = verify_oblivious_selection_vectors(selection_vector, split_attr_pt, split_val_pt, plain_x, depth_glb,
													   decryptor, batch_encoder, seal_context);
		cout << "Verification of all selection vectors against plaintext training: " << (wrong ? "FAILED, wrong slots: " + to_string(wrong) : string("OK")) << endl;
	}

	// simulate the labeling for leaf nodes for multi-threading...
	cout << "Calculating the labeling for leaf nodes...\n";
	const long long power_term = 1LL << (depth_glb - 1);  // integer bit shift, no pow()
	const long long divisor = min(power_term, static_cast<long long>(num_cores));
	const int bound = static_cast<int>(power_term / divisor); 
	for (int i = 0; i < bound; i++) {
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
	for (int i = 0; i < (int) poly_modulus_degree_glb/2; i++) {
		pll.data()[i] = 1;
	}

	cout << "Simulate the packing and extraction...\n";
	for (int d = 0; d < depth_glb - 2; d++) {
		for (int k = 0; k < pow(2,d); k++) {
			int extraction_count = (sqrt_attr_size_glb * (label_size_glb+1) * (2*value_size_glb-1));
			int thread_chunk = ceil((double) extraction_count / (double) num_cores);
			for (int i = 0; i < max(1, thread_chunk); i++) {
				Ciphertext tmp = partitions_for_node[0][0][0];
				if (tmp.parms_id() != seal_context.last_parms_id()) {
					evaluator.mod_switch_to_next_inplace(tmp);
				}
				if (d == 0 && k == 0 && i == 0) cout << "	budget of the node partitions entering the packing: " << decryptor.invariant_noise_budget(tmp) << endl;
				evaluator.multiply_plain_inplace(tmp, pll);
				evaluator.rotate_rows_inplace(tmp, 1, gal_keys_rot);
				evaluator.add_inplace(tmp, tmp);
				if (d == 0 && k == 0 && i == 0) cout << "	budget after packing: " << decryptor.invariant_noise_budget(tmp) << endl;
			}
		}
	}

	for (int d = 0; d < depth_glb - 2; d++) {
		for (int k = 0; k < pow(2,d); k++) {
			const int bound = max(1, static_cast<int>(ceil(static_cast<double>(label_size_glb) / static_cast<double>(num_cores))));
			for (int i = 0; i < bound; i++) {
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


























	chrono::high_resolution_clock::time_point time_int_start, time_int_end;
    long int_time = 0;
	num_cores = num_cores * 12;

	// =========================================================
	// INTEGRITY CHECK: Y' x C' pipeline (one CT×CT, chain 1→0)
	// =========================================================
	cout << "\n=== Integrity check: Y' x C' pipeline ===\n";

	int fill_n = 4 * attr_size_glb;  // number of copies: e.g. 16 for iris
	int total_block = fill_n * label_size_glb; // total number of data_size_glb blocks we should pack in ciphertexts
	int pack_size = (floor(poly_modulus_degree_glb/2 / data_size_glb) * 2);
	int ct_count = ceil((double) total_block / (double) pack_size);
	cout << "Pack commitment in " << ct_count << " ciphertexts, eaching packing " << pack_size << " chunks.\n";


	time_int_start = chrono::high_resolution_clock::now();
	Ciphertext ct_Y_int = inputs_Y[0];
	while ((int)seal_context.get_context_data(ct_Y_int.parms_id())->chain_index() > 4)
		evaluator.mod_switch_to_next_inplace(ct_Y_int);
	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();
	
	cout << "inputs_Y[0] budget at chain 3: " << decryptor.invariant_noise_budget(ct_Y_int) << " bits\n";

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

	time_int_start = chrono::high_resolution_clock::now();
	Ciphertext Y_prime;
	bool yp_init = false;
	NTL::SetNumThreads(min(label_size_glb, num_cores));
	int thread_chunk_size = static_cast<int>(std::max(1.0, ceil((double)label_size_glb / (double)num_cores)));
	NTL_EXEC_RANGE(min(label_size_glb, num_cores), first, last);
	for (int tt = first; tt < last; tt++) {
		for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) {
		// NTT-free binary mask selecting [data_size*i, data_size*(i+1))
			Plaintext mask_pl;
			mask_pl.resize(poly_modulus_degree_glb);
			mask_pl.parms_id() = parms_id_zero;
			for (int j = 0; j < (int)poly_modulus_degree_glb; j++)
				mask_pl.data()[j] = (j >= data_size_glb * nd && j < data_size_glb * (nd + 1)) ? 1 : 0;
			Ciphertext extracted;
			evaluator.multiply_plain(ct_Y_int, mask_pl, extracted);

			// Shift block to slot 0: rotate rows left by data_size*i
			if (nd > 0)
				evaluator.rotate_rows_inplace(extracted,
					data_size_glb * nd % (poly_modulus_degree_glb / 2), gal_keys_rot);

			// Fill to fill_n copies
			int cnt = 0;
			Ciphertext filled;
			while (cnt * pack_size < 4 * attr_size_glb) {
				if (nd == 0) cout << "	packing labels... " << cnt << endl;
				int fill_count = min(pack_size, 4 * attr_size_glb - cnt);
				filled = rot_fill(extracted, data_size_glb, fill_count);
				cnt += fill_count;
			}

			if (!yp_init) { Y_prime = filled; yp_init = true; }
			else           evaluator.add_inplace(Y_prime, filled);
		}
	}
	NTL_EXEC_RANGE_END;
	evaluator.mod_switch_to_next_inplace(Y_prime);
	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();

	cout << "Y' budget: " << decryptor.invariant_noise_budget(Y_prime) << " bits\n";
	

	srand(42);
	vector<uint64_t> cp_data(poly_modulus_degree_glb, 0);
	for (int j = 0; j < data_size_glb; j++)
		cp_data[j] = (uint64_t)((rand() % 100) + 1);
	Plaintext cp_pl;
	batch_encoder.encode(cp_data, cp_pl);
	Ciphertext C_prime, tmp;
	encryptor.encrypt(cp_pl, C_prime);

	time_int_start = chrono::high_resolution_clock::now();
	while ((int)seal_context.get_context_data(C_prime.parms_id())->chain_index() > 4)
		evaluator.mod_switch_to_next_inplace(C_prime);

	if (dataset == 1) {
		C_prime = rot_fill(C_prime, data_size_glb, label_size_glb);
	} else if (dataset == 2) {
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < data_size_glb; j++)
				cp_data[j] = (uint64_t)((rand() % 100) + 1);
			batch_encoder.encode(cp_data, cp_pl);
			
			evaluator.multiply_plain(C_prime, cp_pl, tmp);
			evaluator.rotate_rows_inplace(tmp, data_size_glb, gal_keys_rot);
			evaluator.add_inplace(C_prime, tmp);
		}
	} else if (dataset == 3) {
		evaluator.rotate_columns_inplace(C_prime, gal_keys_rot);
	} else {
		// do nothing for digits, no need to pack... no SIMD potential, reuse the ct for multiplication
	}
	evaluator.mod_switch_to_next_inplace(C_prime);
	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();
	
	
	cout << "C' budget: " << decryptor.invariant_noise_budget(C_prime) << " bits\n";

	Ciphertext H_pp;
	// Step 3: H = Y' × C'  (the one CT×CT in this pipeline)
	time_int_start = chrono::high_resolution_clock::now();
	int endd = min(ct_count, num_cores);
	NTL::SetNumThreads(endd);
	thread_chunk_size = static_cast<int>(std::max(1.0, ceil((double)ct_count / (double)num_cores)));
	NTL_EXEC_RANGE(min(ct_count, num_cores), first, last);
	for (int tt = first; tt < last; tt++) {
		for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) {
			Ciphertext H;
			evaluator.multiply(Y_prime, C_prime, H);
			evaluator.relinearize_inplace(H, relin_keys);
			evaluator.mod_switch_to_next_inplace(H);

			// cout << "H budget (CT×CT + relin, chain 2): " << decryptor.invariant_noise_budget(H) << " bits\n";
			Ciphertext H_prime = rotation_and_add(seal_context, H,
											data_size_glb, 1, evaluator, gal_keys_rot, 0);
			// cout << "H' budget: " << decryptor.invariant_noise_budget(H_prime) << " bits\n";
			int blk = min(data_size_glb * attr_size_glb, (int) poly_modulus_degree_glb);
			Ciphertext tmp = rotation_and_add(seal_context, H_prime,
												blk,
												data_size_glb, evaluator, gal_keys_rot, 0);
			evaluator.mod_switch_to_next_inplace(tmp);

			if (nd == 0) {
				H_pp = tmp;
				cout << "H'' final noise budget (chain 2): " << decryptor.invariant_noise_budget(H_pp) << " bits\n";
			}
		}
	}
	NTL_EXEC_RANGE_END;
	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();



	// for |D_x| checks... 
	int ct_count_D_x = ceil((double) fill_n / (double) pack_size);

	while ((int)seal_context.get_context_data(C_prime.parms_id())->chain_index() > 2)
		evaluator.mod_switch_to_next_inplace(C_prime);

	time_int_start = chrono::high_resolution_clock::now();
	NTL::SetNumThreads(min(ct_count_D_x, num_cores));
	thread_chunk_size = max(1, ct_count_D_x / num_cores);
	NTL_EXEC_RANGE(min(ct_count_D_x, num_cores), first, last);
	for (int tt = first; tt < last; tt++) {
		for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) {
			tmp = rotation_and_add(seal_context, C_prime,
										data_size_glb, 1,
										evaluator, gal_keys_rot, 0);
		}
	}
	NTL_EXEC_RANGE_END;
	evaluator.mod_switch_to_next_inplace(C_prime);
	cout << "C'x before packing final noise budget (chain 1): " << decryptor.invariant_noise_budget(C_prime) << " bits\n";

	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();


	// final packing...

	time_int_start = chrono::high_resolution_clock::now();
	NTL::SetNumThreads(min(ct_count + ct_count_D_x, num_cores));
	thread_chunk_size = max(1, (ct_count+ct_count_D_x) / num_cores);
	NTL_EXEC_RANGE(min(ct_count+ct_count_D_x, num_cores), first, last);
	for (int tt = first; tt < last; tt++) {
		for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) {
			vector<uint64_t> tt_v(poly_modulus_degree_glb, 0);
			Plaintext tt_p;  
			for (int j = 0; j < poly_modulus_degree_glb; j++)
				tt_v[j] = (uint64_t)((rand() % 100) + 1);
			batch_encoder.encode(tt_v, tt_p);

			Ciphertext tt;
			evaluator.multiply_plain(H_pp, tt_p, tt);
			evaluator.rotate_rows_inplace(tt, data_size_glb, gal_keys_rot);
			evaluator.add_inplace(tt, tt);

			if (nd == 0) {
				C_prime = tt;
				evaluator.mod_switch_to_next_inplace(C_prime);
				cout << "C'' final packing noise budget (chain 0): " << decryptor.invariant_noise_budget(C_prime) << " bits\n";
			}
		}
	}
	NTL_EXEC_RANGE_END;
	
	time_int_end = chrono::high_resolution_clock::now();
	int_time += chrono::duration_cast<chrono::microseconds>(time_int_end - time_int_start).count();



	cout << "Integrity Runtime for all : " << int_time * (depth_glb+1) << " ms." << endl;

	return 0;

}
