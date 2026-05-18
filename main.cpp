#include "seal/seal.h"
#include "util.h"
#include "global.h"
#include "seal/util/iterator.h"
#include <numeric>
#include <stdio.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>
#include <iomanip>
#include <mach/mach.h>

static void print_rss(const char* label) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        printf("[MEM] %s: RSS=%.1f GB\n", label, (double)info.resident_size / (1024.0*1024.0*1024.0));
    }
}

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

struct RunResult {
	string name;
	long long preprocess_us;
	long long train_us;
};

RunResult run_dataset(int dataset, int depth, int is_bin, int is_sqrt) {

	setvbuf(stdout, nullptr, _IONBF, 0); // unbuffer C stdio so output is visible even if killed

	string ds_name;
	if (dataset == 1) {
		ds_name = "iris";
		data_size_glb = 100;
		attr_size_glb = 4;
		sqrt_attr_size_glb = is_sqrt ? 2 : 4;
		value_size_glb = 8;
		label_size_glb = 3;
	} else if (dataset == 2) { // wine
		ds_name = "wine";
		data_size_glb = 119;
		attr_size_glb = 13;
		sqrt_attr_size_glb = is_sqrt ? 4 : 13;
		value_size_glb = 9;
		label_size_glb = 3;
	} else if (dataset == 3) { // cancer
		ds_name = "cancer";
		data_size_glb = 380;
		attr_size_glb = 30;
		sqrt_attr_size_glb = is_sqrt ? 6 : 30;
		value_size_glb = 18;
		label_size_glb = 2;
	} else { // digit
		ds_name = "digit";
		data_size_glb = 1203;
		attr_size_glb = 64;
		sqrt_attr_size_glb = is_sqrt ? 8 : 64;
		value_size_glb = 17;
		label_size_glb = 10;
	}

	depth_glb = depth;
	if (is_bin) value_size_glb = 8;

	cout << "\n=== Dataset: " << ds_name << "  depth=" << depth
	     << "  data_size=" << data_size_glb << "  label_size=" << label_size_glb << " ===\n";

	for (auto &i : seed_glb) {
		i = random_uint64();
	}

	int p = 65537;

	EncryptionParameters bgv_params(scheme_type::bgv);
	bgv_params.set_poly_modulus_degree(poly_modulus_degree_glb);

	// BGV modulus chain: first prime is the base (level 0, always retained).
	// Middle 40-bit primes are consumed one-per-multiply via mod_switch_to_next_inplace.
	// Level budget breakdown:
	//   depth_glb        : update_selection_vector calls (one per depth)
	//   leaf_iter        : leaf-labeling loop mod-switches selection_vector in-place each iteration
	//                      leaf_iter = pow(2, depth_glb-1) / num_cores
	//   6                : 1 (preprocess) + 2 (perform_partition) + 1 (mat-vec) + 2 (margin)
	int leaf_iter = (int)(pow(2, depth_glb - 1) / num_cores);
	int num_middle = depth_glb + leaf_iter + 6;
	vector<int> mod_bits = {60};
	for (int i = 0; i < num_middle; i++) mod_bits.push_back(40);
	mod_bits.push_back(60);
	auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, mod_bits);

	bgv_params.set_coeff_modulus(coeff_modulus);
	bgv_params.set_plain_modulus(p);

	// Print coeff modulus configuration
	{
		int total_bits = 0;
		for (auto& m : coeff_modulus) total_bits += m.bit_count();
		cout << "Coeff modulus: " << coeff_modulus.size() << " primes, "
		     << total_bits << " bits total  [";
		for (size_t i = 0; i < coeff_modulus.size(); i++) {
			cout << coeff_modulus[i].bit_count();
			if (i + 1 < coeff_modulus.size()) cout << ", ";
		}
		cout << "]\n";
		cout << "Modulus levels: " << (coeff_modulus.size() - 1) << "\n";
	}

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

	RelinKeys relin_keys;
	keygen.create_relin_keys(relin_keys);

	Encryptor encryptor(seal_context, bgv_public_key);
	Evaluator evaluator(seal_context);
	BatchEncoder batch_encoder(seal_context);
	Decryptor decryptor(seal_context, bgv_secret_key);

	GaloisKeys gal_keys, gal_keys_rot;

	vector<int> stepsfirst = {0, 1};
	for (int i = 0; i < (int)log2(poly_modulus_degree_glb/2); i++) {
		stepsfirst.push_back(-(1<<i));
		stepsfirst.push_back((1<<i));
	}
	keygen.create_galois_keys(stepsfirst, gal_keys);

	// for preparing all threshold values, rotation and addition
	vector<int> steps_rot = {0, 1};
	for (int i = 0; i < 2*value_size_glb; i++) {
		if (i * data_size_glb < (int)poly_modulus_degree_glb / 2) {
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
		if (i * data_size_glb * value_size_glb < (int)poly_modulus_degree_glb / 2) {
			steps_rot.push_back((i * data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2));
			steps_rot.push_back((-i * data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2));
		}
	}

	keygen.create_galois_keys(steps_rot, gal_keys_rot);
	print_rss("after galois keys");

	Plaintext pl_test, all_ones;
	vector<uint64_t> msg_test(poly_modulus_degree_glb);

	vector<uint64_t> allones(poly_modulus_degree_glb, 1);
	batch_encoder.encode(allones, all_ones);

	///////////////////////////////////////////// prepare the one-hot encoding for datasets /////////////////////////////////////////////

	vector<Ciphertext> inputs_X, inputs_Y;
	sample_one_hot_encoding_inputs(inputs_X, inputs_Y, data_size_glb, attr_size_glb, value_size_glb, label_size_glb,
								   batch_encoder, encryptor);

	///////////////////////// pre-process the dataset by recording all partition labels based on attr val ////////////////////////////////

	chrono::high_resolution_clock::time_point time_start, time_end;
	time_start = chrono::high_resolution_clock::now();

	vector<vector<Ciphertext>> preprocessed_partitions((int) inputs_X.size());
	vector<vector<vector<Ciphertext>>> preprocessed_partitioned_labels((int) inputs_X.size());

	preprocess_all_threshold(inputs_X, inputs_Y, preprocessed_partitions, preprocessed_partitioned_labels,
							 seal_context, evaluator, encryptor, gal_keys_rot, relin_keys);

	time_end = chrono::high_resolution_clock::now();
	long long preprocess_us = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
	cout << "Preprocess time: " << preprocess_us << " us.\n";
	print_rss("after preprocessing");

	/////////////////////////////////////////// for each node, prepare the gini-index inputs ////////////////////////////////////////////
	vector<Ciphertext> selection_vector((int)pow(2, depth_glb));

	// just fill in random selection vectors...
	for (int i = 0; i < (int) selection_vector.size(); i++) {
		encryptor.encrypt(pl_test, selection_vector[i]);
	}

	// ideally, different nodes should have different partition thresholds, but just for some simulation...
	int threshold_attr_ind = 1, threshold_val_ind = 1;

	vector<vector<vector<Ciphertext>>> partitions_for_node;
	vector<vector<vector<vector<Ciphertext>>>> partition_labels_for_node;

	bool sim_cts_saved = false;
	Ciphertext sim_partition_ct, sim_partition_label_ct;

	time_start = chrono::high_resolution_clock::now();
	try {
	for (int d = 0; d < depth_glb; d++) { // for each level in the tree, except the root
		bool multi_thread = false; // disabled: outer-parallel 4 threads OOM on 48GB; inner parallelism handles concurrency instead

		cout << "	Training for level " << d << " with " << (int)pow(2,d) << " nodes...\n";

		partitions_for_node.resize((int)pow(2,d));
		partition_labels_for_node.resize((int)pow(2,d));

		for (int ll = 0; ll < (int)pow(2,d); ll++) {
			partitions_for_node[ll].resize((int) preprocessed_partitions.size());
			partition_labels_for_node[ll].resize((int) preprocessed_partitioned_labels.size());
		}

		if (multi_thread) {
			NTL::SetNumThreads(num_cores);
			int thread_chunk_size = (int)pow(2,d) / num_cores;
			NTL_EXEC_RANGE(num_cores, first, last);
			for (int tt = first; tt < last; tt++) {
				for (int nd = tt*thread_chunk_size ; nd < (tt+1)*thread_chunk_size; nd++) { // for each node in this level

					int sel_ind = (int)pow(2, d)-1 + nd;

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
			for (int nd = 0 ; nd < (int)pow(2, d); nd++) { // for each node in this level
				int sel_ind = (int)pow(2, d)-1 + nd;
				// When sqrt_attr == attr (no actual random selection needed), skip the simulate copy
				// to avoid allocating ~8.7 GB of identical ciphertext duplicates per node.
				// perform_partition_for_node only reads its inputs (via Ciphertext tmp = ...) so
				// passing the global preprocessed_partitions directly is safe.
				bool skip_simulate = (sqrt_attr_size_glb == attr_size_glb);

				if (!skip_simulate) cout << "    node " << nd << "/" << (int)pow(2,d) << " simulate...\n";

				vector<vector<Ciphertext>> random_preprocessed_partitions;
				vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;

				auto& parts_in  = skip_simulate ? preprocessed_partitions           : random_preprocessed_partitions;
				auto& labels_in = skip_simulate ? preprocessed_partitioned_labels   : random_reprocessed_partitioned_labels;

				if (!skip_simulate) {
					simulate_random_select_sqrt_attributes(preprocessed_partitions, preprocessed_partitioned_labels,
														   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
														   seal_context, evaluator, gal_keys_rot, !multi_thread);
				}
				if (d >= depth_glb - 2) print_rss(("after simulate d=" + to_string(d) + " nd=" + to_string(nd)).c_str());

				cout << "    node " << nd << "/" << (int)pow(2,d) << " partition (sim_parts=" << parts_in.size() << "x" << (parts_in.empty() ? 0 : parts_in[0].size()) << ")...\n";
				perform_partition_for_node(parts_in, labels_in, partitions_for_node[nd],
										   partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
										   relin_keys, gal_keys_rot, !multi_thread);

				if (d >= depth_glb - 2) print_rss(("after partition d=" + to_string(d) + " nd=" + to_string(nd)).c_str());
				cout << "    node " << nd << "/" << (int)pow(2,d) << " done.\n";

				// Save one representative ciphertext on first completion, then free immediately to avoid OOM accumulation
				if (!sim_cts_saved && !partitions_for_node[nd].empty() && !partitions_for_node[nd][0].empty()) {
					sim_partition_ct = partitions_for_node[nd][0][0];
					sim_partition_label_ct = partition_labels_for_node[nd][0][0][0];
					sim_cts_saved = true;
				}
				partitions_for_node[nd].clear();
				partition_labels_for_node[nd].clear();
				if (d >= depth_glb - 2) print_rss(("after clear d=" + to_string(d) + " nd=" + to_string(nd)).c_str());

				if (d != depth_glb-1) { // no need to update the leaf level
					update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
											seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
				}
			}
		}
	}

	} catch (const std::bad_alloc&) {
		time_end = chrono::high_resolution_clock::now();
		long long oom_us = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
		cerr << "Out of memory during training loop (" << oom_us/1e6 << " s elapsed)\n";
		return {ds_name, preprocess_us, -1LL};
	}

	// sim_partition_ct and sim_partition_label_ct were saved and partitions freed node-by-node during the loop.

	// ── homomorphic vector-to-matrix multiplication after the depth loop ────────
	// inputs_Y[0] packs matrix M: column l occupies slots [l*data_size_glb, (l+1)*data_size_glb).
	// vec_ct packs vector v: v[l] is replicated in all slots of column l's range.
	// result[j] = sum_{l=0}^{label_size_glb-1}  M[j][l] * v[l],  at output slots [0, data_size_glb).
	{
		vector<uint64_t> v_msg(poly_modulus_degree_glb, 0);
		for (int l = 0; l < label_size_glb; l++) {
			uint64_t val = (uint64_t)(l + 1); // placeholder values; supplied via MPC in practice
			for (int j = 0; j < data_size_glb; j++)
				v_msg[l * data_size_glb + j] = val;
		}
		Plaintext v_plain;
		batch_encoder.encode(v_msg, v_plain);
		Ciphertext vec_ct;
		encryptor.encrypt(v_plain, vec_ct);

		Ciphertext matvec_result = ct_matvec_bgv(vec_ct, inputs_Y[0],
		                                          seal_context, evaluator,
		                                          relin_keys, gal_keys_rot,
		                                          data_size_glb, label_size_glb);
		cout << "Mat-vec multiply done. Remaining modulus levels: "
		     << seal_context.get_context_data(matvec_result.parms_id())->chain_index() << "\n";
	}

	// simulate the labeling for leaf nodes...
	cout << "Calculating the labeling for leaf nodes...\n";
	for (int i = 0; i < (int)(pow(2, depth_glb-1)) / num_cores; i++) { // simulate the time of single thread
		Ciphertext tmp = preprocessed_partitioned_labels[0][0][0];
		if (selection_vector[selection_vector.size()-3].parms_id() != seal_context.last_parms_id()) {
			evaluator.mod_switch_to_next_inplace(selection_vector[selection_vector.size()-3]);
		}
		evaluator.mod_switch_to_inplace(tmp, selection_vector[selection_vector.size()-3].parms_id());
		evaluator.multiply_inplace(tmp, selection_vector[selection_vector.size()-3]);
		evaluator.relinearize_inplace(tmp, relin_keys);
		if (i == 0) cout << "\tNoise budget (leaf-label after relin): " << decryptor.invariant_noise_budget(tmp) << " bits\n";
		if (tmp.parms_id() != seal_context.last_parms_id())
			evaluator.mod_switch_to_next_inplace(tmp);  // BGV: mod down after CT×CT multiply
		rotation_and_add(seal_context, tmp, data_size_glb, 1, evaluator, gal_keys_rot);
	}

	Plaintext pll;
	pll.resize(poly_modulus_degree_glb);
	pll.parms_id() = parms_id_zero;
	for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
		pll.data()[i] = 1;
	}

	cout << "Simulate the packing and extraction...\n";
	try {
		for (int d = 0; d < depth_glb - 2; d++) { // simulate for all intermediary level
			for (int k = 0; k < (int)pow(2,d); k++) { // for all nodes
				for (int i = 0; i < (int)ceil((double) (sqrt_attr_size_glb * (label_size_glb+1) * (2*value_size_glb-1)) / (double) num_cores); i++) { // simulate the single core runtime
					Ciphertext tmp = sim_partition_ct;
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
			for (int k = 0; k < (int)pow(2,d); k++) { // for all nodes
				for (int i = 0; i < (int)ceil((double) label_size_glb / (double) num_cores); i++) { // simulate the single core runtime
					Ciphertext tmp = sim_partition_label_ct;
					if (tmp.parms_id() != seal_context.last_parms_id()) {
						evaluator.mod_switch_to_next_inplace(tmp);
					}
					evaluator.multiply_plain_inplace(tmp, pll);
					evaluator.rotate_rows_inplace(tmp, 1, gal_keys_rot);
					evaluator.add_inplace(tmp, tmp);

					if (d == 0 && k == 0 && i == 0) cout << "\tLeft noise budget: " << decryptor.invariant_noise_budget(sim_partition_label_ct) << ", "
					     << decryptor.invariant_noise_budget(tmp) << ", " << tmp.coeff_modulus_size() << endl;
				}
			}
		}
	} catch (const std::bad_alloc&) {
		cout << "\tPacking simulation skipped (out of memory)\n";
	}

	time_end = chrono::high_resolution_clock::now();
	long long train_us = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
	cout << "Training + labeling + packing total runtime: " << train_us << " us.\n";

	return {ds_name, preprocess_us, train_us};
}

int main(int argc, char* argv[]) {

	int dataset = std::stoi(argv[1]);
	int depth   = std::stoi(argv[2]);
	int is_bin  = std::stoi(argv[3]);
	int is_sqrt = std::stoi(argv[4]);

	if (dataset == 0) {
		// run all four datasets and print a summary table
		const string ds_names[] = {"", "iris", "wine", "cancer", "digit"};
		vector<RunResult> results;
		for (int ds = 1; ds <= 4; ds++) {
			try {
				results.push_back(run_dataset(ds, depth, is_bin, is_sqrt));
			} catch (const std::bad_alloc&) {
				cerr << "Out of memory for dataset " << ds_names[ds] << "\n";
				results.push_back({ds_names[ds], 0LL, -1LL});
			}
		}

		const int W = 72;
		cout << "\n" << string(W, '=') << "\n";
		cout << "Runtime Summary  (depth=" << depth
		     << "  is_bin=" << is_bin << "  is_sqrt=" << is_sqrt << ")\n";
		cout << string(W, '-') << "\n";
		cout << left  << setw(10) << "Dataset"
		     << right << setw(18) << "Preprocess (s)"
		     << setw(18) << "Training (s)"
		     << setw(16) << "Total (s)" << "\n";
		cout << string(W, '-') << "\n";
		for (auto& r : results) {
			cout << left << setw(10) << r.name;
			if (r.train_us < 0) {
				cout << right << setw(18) << fixed << setprecision(2) << r.preprocess_us / 1e6
				     << setw(18) << "OOM" << setw(16) << "OOM" << "\n";
			} else {
				double pre_s   = r.preprocess_us / 1e6;
				double train_s = r.train_us      / 1e6;
				cout << right << fixed << setprecision(2)
				     << setw(18) << pre_s
				     << setw(18) << train_s
				     << setw(16) << (pre_s + train_s) << "\n";
			}
		}
		cout << string(W, '=') << "\n";
	} else {
		run_dataset(dataset, depth, is_bin, is_sqrt);
	}

	return 0;
}
