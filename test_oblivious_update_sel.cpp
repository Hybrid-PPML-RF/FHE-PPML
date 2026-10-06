// Standalone correctness + noise + runtime test for the oblivious selection-vector update (util.h).
//
// It builds a random one-hot dataset, preprocesses the partitions exactly like main_integrity.cpp, then walks a small
// decision tree. Every node gets a random split (attr, theta) which is only handed to the server as two *fresh* ciphertexts
// (one pair per group of G nodes, see util.h). After each update the children are decrypted and compared with plaintext
// training on the same data; the noise budget of every stage and the time of every stage are printed, so that the modulus
// chain can be tuned.
//
// usage: ./test_obl [N n A V depth  base_n base_bits  topup_n topup_bits  special_bits  fermat_switch_every  light  stress  expand  eq]
//   N         poly modulus degree (iris: 16384, small functional test: 4096)
//   n A V     data_size, attr_size, value_size  (iris: 100 4 8)
//   depth     number of tree levels (levels 0..depth-2 get an update, as in main_integrity)
//   chain     coeff modulus = base_n x base_bits  +  topup_n x topup_bits  +  special_bits   (last prime is SEAL's special prime)
//   light     1 = skip preprocess_all_threshold (saves its Galois keys / RAM): the "x < theta" partitions are encrypted directly
//   stress    k > 0: instead of a tree, run k random groups on the root (checks that the noise of the equality test is safe for
//             every split, not just for a lucky one) and print the minimum final budget
//             k < 0: only the equality test (ObliviousRotation), |k| random block indices; counts how often the output is wrong
//   eq        1 (default): low-depth polynomial equality test (5 levels); 0: Qelect's Fermat test x^(p-1) (16 levels)
//   expand    1 (default): the parties encrypt their shares replicated over the region (no expansion);
//             0: the input ciphertexts only hold the value in the first slot of the region and are expanded homomorphically

#include "seal/seal.h"
#include "util.h"
#include "global.h"
#include <numeric>
#include <random>
#include <iostream>
#include <set>

using namespace seal;
using namespace std;

int main(int argc, char* argv[]) {
	auto arg = [&](int i, int def) { return argc > i ? stoi(argv[i]) : def; };

	poly_modulus_degree_glb = arg(1, 4096);
	data_size_glb = arg(2, 24);
	attr_size_glb = arg(3, 3);
	value_size_glb = arg(4, 4);
	label_size_glb = 2;
	sqrt_attr_size_glb = attr_size_glb;
	int depth = arg(5, 3);
	depth_glb = depth;
	int base_n = arg(6, 8), base_bits = arg(7, 34);
	int topup_n = arg(8, 18), topup_bits = arg(9, 44);
	int special_bits = arg(10, 50);
	int switch_every = arg(11, 1);
	int light = arg(12, 0);
	int stress = arg(13, 0);
	bool replicated_input = arg(14, 1) != 0;
	bool equality_poly = arg(15, 1) != 0;

	const int n = data_size_glb, A = attr_size_glb, V = value_size_glb;
	const size_t N = poly_modulus_degree_glb, row = N / 2;
	cout << "N=" << N << " n=" << n << " A=" << A << " V=" << V << " depth=" << depth
	     << (replicated_input ? " (replicated inputs)" : " (first-slot inputs, expanded homomorphically)")
	     << (equality_poly ? ", polynomial equality test" : ", Fermat equality test") << endl;
	cout << "levels used by the equality test: " << oblivious_equality_levels(equality_poly, A, V, 65537) << endl;

	for (auto &i : seed_glb) i = random_uint64();

	vector<int> bits;
	for (int i = 0; i < base_n; i++) bits.push_back(base_bits);
	for (int i = 0; i < topup_n; i++) bits.push_back(topup_bits);
	bits.push_back(special_bits);
	int total_bits = 0;
	for (int b : bits) total_bits += b;
	cout << "coeff modulus: " << base_n << "x" << base_bits << " + " << topup_n << "x" << topup_bits << " + special " << special_bits
	     << "  = " << total_bits << " bits (128-bit security bound at this N: " << CoeffModulus::MaxBitCount(N) << ")\n";

	EncryptionParameters params(scheme_type::bgv);
	params.set_poly_modulus_degree(N);
	params.set_coeff_modulus(CoeffModulus::Create(N, bits));
	params.set_plain_modulus(65537);
	SEALContext context(params, true, sec_level_type::none);

	KeyGenerator keygen(context);
	SecretKey sk = keygen.secret_key();
	PublicKey pk;
	keygen.create_public_key(pk);
	RelinKeys relin_keys;
	keygen.create_relin_keys(relin_keys);
	Encryptor encryptor(context, pk);
	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	Decryptor decryptor(context, sk);

	// ---- Galois keys: the ones preprocess_all_threshold needs (same list as main_integrity) + the oblivious update ones
	set<int> steps;
	if (!light) {
		steps = {0, 1};
		for (int i = 0; i < 2 * V; i++) steps.insert((i * n) % row);
		for (int i = n; i > 0; i /= 2) { if (i % 2) steps.insert(i - 1); steps.insert(i); }
		int iter = 1;
		while (iter < A) iter *= 2;
		for (int i = 0; i < iter; i++) {
			if ((size_t) i * n * V < row) { steps.insert((i * n * V) % row); steps.insert((-i * n * V) % (int) row); }
		}
	}
	for (int s : oblivious_update_rotation_steps(n, A, V, replicated_input)) steps.insert(s);
	GaloisKeys gal_keys;
	keygen.create_galois_keys(vector<int>(steps.begin(), steps.end()), gal_keys);
	cout << "generated " << steps.size() << " Galois keys\n";

	// ---- noise trace: prints the noise budget and the time spent since the previous trace point (budget computation excluded)
	chrono::steady_clock::time_point last_trace = chrono::steady_clock::now();
	auto print_trace = [&](const string& name, const Ciphertext& ct) {
		double ms = chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - last_trace).count() / 1000.0;
		cout << "      [" << name << "] chain " << context.get_context_data(ct.parms_id())->chain_index()
		     << ", budget " << decryptor.invariant_noise_budget(ct) << " bits, +" << ms << " ms\n";
		last_trace = chrono::steady_clock::now();
	};
	oblivious_trace_glb = print_trace;

	// ---- dataset + preprocessing
	Plaintext pl;
	vector<uint64_t> dec;
	vector<vector<int>> x(n, vector<int>(A, -1));   // x[j][a] = value of attribute a of datapoint j
	vector<vector<Ciphertext>> preprocessed_partitions(1);
	vector<Ciphertext> inputs_X, inputs_Y;
	if (!light) {
		sample_one_hot_encoding_inputs(inputs_X, inputs_Y, n, A, V, label_size_glb, batch_encoder, encryptor);
		vector<vector<vector<Ciphertext>>> preprocessed_partitioned_labels((int) inputs_X.size());
		preprocessed_partitions.assign((int) inputs_X.size(), vector<Ciphertext>());
		preprocess_all_threshold(inputs_X, inputs_Y, preprocessed_partitions, preprocessed_partitioned_labels, context, evaluator,
		                         encryptor, gal_keys, relin_keys);
		x = obl_decode_dataset(inputs_X[0], decryptor, batch_encoder);
	} else {
		// random data; encrypt the "x < theta" partitions (odd index 2*theta-1) directly, with random garbage in the slots of each
		// attribute chunk that preprocess_all_threshold leaves meaningless (to exercise the masking in build_oblivious_sel_ctx)
		mt19937 drng(99);
		for (int j = 0; j < n; j++) for (int a = 0; a < A; a++) x[j][a] = drng() % V;
		preprocessed_partitions[0].resize(2 * V - 1);
		for (int th = 1; th < V; th++) {
			vector<uint64_t> vec(N, 0);
			for (int a = 0; a < A; a++)
				for (int o = 0; o < V * n; o++)
					vec[(size_t) a * V * n + o] = (o < n) ? (x[o][a] < th) : (drng() % 3);
			Plaintext p;
			batch_encoder.encode(vec, p);
			encryptor.encrypt(p, preprocessed_partitions[0][2 * th - 1]);
		}
	}

	ObliviousSelCtx oc;
	oc.fermat_switch_every = switch_every;
	oc.equality_poly = equality_poly;
	{
		auto t0 = chrono::steady_clock::now();
		build_oblivious_sel_ctx(oc, preprocessed_partitions, context, evaluator, batch_encoder, gal_keys);
		cout << "build_oblivious_sel_ctx: " << chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - t0).count()
		     << " ms; group size G = " << oc.group_size << " nodes per ciphertext (" << oc.regions_per_row << " regions per row)\n";
	}
	const int G = oc.group_size;

	// check P:  in every region, slot a*V*n + theta*n + j == [x_{j,a} < theta]
	decryptor.decrypt(oc.packed_partitions, pl);
	batch_encoder.decode(pl, dec);
	int bad = 0;
	for (size_t s = 0; s < N; s++) {
		int expect = 0;
		for (int g = 0; g < G; g++) {
			int base = obl_region_base(oc, g);
			if ((int) s >= base && (int) s < base + oc.region_size) {
				size_t o = s - base;
				int a = o / (V * n), th = (o / n) % V, j = o % n;
				expect = (x[j][a] < th) ? 1 : 0;
			}
		}
		if ((int) dec[s] != expect) bad++;
	}
	cout << "packed partitions P: " << (bad ? "WRONG (" + to_string(bad) + " slots)" : "ok") << ", budget "
	     << decryptor.invariant_noise_budget(oc.packed_partitions) << " bits\n";

	// encrypts one group's split vectors as fresh ciphertexts
	auto encrypt_group = [&](const vector<int>& values, Ciphertext& ct) {
		Plaintext p;
		batch_encoder.encode(oblivious_group_vector(oc, values, replicated_input), p);
		encryptor.encrypt(p, ct);
	};

	// ---- equality test only
	if (stress < 0) {
		mt19937 srng(4242);
		int bad_trials = 0, min_budget = 100000;
		vector<uint64_t> d2;
		for (int it = 0; it < -stress; it++) {
			vector<int> as(G), vs(G);
			for (int g = 0; g < G; g++) { as[g] = srng() % A; vs[g] = srng() % V; }   // theta = 0 too: that is what unused regions carry
			Ciphertext ct_a, ct_v;
			encrypt_group(as, ct_a);
			encrypt_group(vs, ct_v);
			oblivious_trace_glb = nullptr;
			Ciphertext out = oblivious_selector(context, evaluator, oc, relin_keys, ct_a, ct_v);
			decryptor.decrypt(out, pl);
			batch_encoder.decode(pl, d2);
			int e = 0;
			for (size_t j = 0; j < N; j++) {
				uint64_t expect = 0;
				for (int g = 0; g < G; g++) {
					int base = obl_region_base(oc, g);
					if ((int) j >= base && (int) j < base + oc.region_size) {
						int blk = (int) ((j - base) / n);
						if (blk / V == as[g] && blk % V == vs[g]) expect = oc.selector_scale;
					}
				}
				if (d2[j] != expect) e++;
			}
			int fb = decryptor.invariant_noise_budget(out);
			min_budget = min(min_budget, fb);
			bad_trials += (e != 0);
			if (e || (it % 20 == 0)) cout << "  trial " << it << ": selector budget " << fb << ", chain " << context.get_context_data(out.parms_id())->chain_index() << (e ? "  WRONG" : "  ok") << endl;
		}
		cout << "equality-test stress: " << bad_trials << "/" << -stress << " wrong, min selector budget " << min_budget << endl;
		return bad_trials ? 1 : 0;
	}

	// ---- random groups on the root
	if (stress > 0) {
		vector<uint64_t> ones_v(N, 1);
		Plaintext pr;
		batch_encoder.encode(ones_v, pr);
		mt19937 srng(777);
		int bad_groups = 0, min_budget = 100000;
		vector<uint64_t> d2;
		for (int it = 0; it < stress; it++) {
			vector<Ciphertext> sv(3);
			encryptor.encrypt(pr, sv[0]);
			vector<int> as(G), ts(G);
			for (int g = 0; g < G; g++) { as[g] = srng() % A; ts[g] = 1 + srng() % (V - 1); }
			if (it == 0) { as[0] = 0; ts[0] = 2; }
			Ciphertext ct_a, ct_t;
			encrypt_group(as, ct_a);
			encrypt_group(ts, ct_t);
			oblivious_trace_glb = nullptr;
			Ciphertext T = oblivious_group_threshold_data(context, evaluator, oc, relin_keys, gal_keys, ct_a, ct_t, replicated_input);
			int e = 0, fb_min = 100000;
			for (int g = 0; g < G; g++) {
				oblivious_apply_threshold_data(sv, T, g, 0, 0, oc, context, evaluator, relin_keys, gal_keys);
				for (int c = 1; c <= 2; c++) {
					decryptor.decrypt(sv[c], pl);
					batch_encoder.decode(pl, d2);
					for (int blk = 0; blk < A * V; blk++)
						for (int j = 0; j < n; j++) {
							int in_left = x[j][as[g]] < ts[g];
							int expect = (c == 1) ? in_left : !in_left;
							if ((int) d2[(size_t) blk * n + j] != expect) e++;
						}
				}
				fb_min = min(fb_min, (int) decryptor.invariant_noise_budget(sv[1]));
			}
			min_budget = min(min_budget, fb_min);
			bad_groups += (e != 0);
			cout << "  group " << it << ": left-child budget " << fb_min << (e ? "  WRONG" : "  ok") << endl;
		}
		cout << "stress: " << bad_groups << "/" << stress << " groups wrong, min left-child budget " << min_budget << endl;
		return bad_groups ? 1 : 0;
	}

	// ---- tree walk
	vector<Ciphertext> selection_vector((size_t) 1 << depth);
	vector<uint64_t> ones(N, 1);
	batch_encoder.encode(ones, pl);
	encryptor.encrypt(pl, selection_vector[0]);   // root: everything is selected
	int num_internal = (1 << (depth - 1)) - 1;
	vector<int> split_attr(num_internal), split_val(num_internal);

	mt19937 rng(1234);
	int errors = 0;
	long long total_group_us = 0, total_apply_us = 0;
	int groups_done = 0, nodes_done = 0;
	oblivious_trace_glb = nullptr;
	for (int d = 0; d < depth - 1; d++) {
		for (int first = 0; first < (1 << d); first += G) {
			int cnt = min(G, (1 << d) - first);
			vector<int> as(cnt), ts(cnt);
			for (int g = 0; g < cnt; g++) {
				as[g] = rng() % A; ts[g] = 1 + rng() % (V - 1);
				split_attr[(1 << d) - 1 + first + g] = as[g];
				split_val[(1 << d) - 1 + first + g] = ts[g];
			}
			Ciphertext ct_a, ct_t;
			encrypt_group(as, ct_a);
			encrypt_group(ts, ct_t);

			cout << "  level " << d << ", nodes " << first << ".." << first + cnt - 1 << " (one group)\n";
			last_trace = chrono::steady_clock::now();
			if (groups_done == 0) oblivious_trace_glb = print_trace;   // detailed trace for the first group only
			auto t0 = chrono::steady_clock::now();
			Ciphertext T = oblivious_group_threshold_data(context, evaluator, oc, relin_keys, gal_keys, ct_a, ct_t, replicated_input);
			auto t1 = chrono::steady_clock::now();
			for (int g = 0; g < cnt; g++) {
				oblivious_apply_threshold_data(selection_vector, T, g, d, first + g, oc, context, evaluator, relin_keys, gal_keys);
			}
			auto t2 = chrono::steady_clock::now();
			oblivious_trace_glb = nullptr;
			total_group_us += chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
			total_apply_us += chrono::duration_cast<chrono::microseconds>(t2 - t1).count();
			groups_done++; nodes_done += cnt;
		}
	}
	cout << "groups: " << groups_done << " (" << nodes_done << " nodes), group computation " << total_group_us / 1000 << " ms total ("
	     << total_group_us / max(1, groups_done) / 1000 << " ms per group), per-node application " << total_apply_us / 1000 << " ms total ("
	     << total_apply_us / max(1, nodes_done) / 1000 << " ms per node)\n";
	cout << "total single-threaded time for all updates: " << (total_group_us + total_apply_us) / 1000 << " ms\n";

	int wrong = verify_oblivious_selection_vectors(selection_vector, split_attr, split_val, x, depth, decryptor, batch_encoder, context);
	cout << "selection vectors vs plaintext training: " << (wrong ? "WRONG slots: " + to_string(wrong) : string("ok")) << endl;
	// budget of the children, per level (min over the level)
	for (int d = 1; d < depth; d++) {
		int mn = 100000, chain = -1;
		for (int i = (1 << d) - 1; i < (1 << (d + 1)) - 1; i++) {
			mn = min(mn, (int) decryptor.invariant_noise_budget(selection_vector[i]));
			chain = (int) context.get_context_data(selection_vector[i].parms_id())->chain_index();
		}
		cout << "  level " << d << " selection vectors: chain " << chain << ", min budget " << mn << " bits\n";
	}
	errors += wrong;

	// ---- what happens to the deepest selection vector afterwards (perform_partition_for_node / leaf labeling): one CT x CT with
	// a preprocessed ciphertext, then a mod switch; the result must still decrypt correctly
	{
		int node = (1 << (depth - 1)) - 1;                    // first node of the deepest level that has a selection vector
		vector<int> expected_node(n, 1);
		vector<int> path;                                     // nodes from `node` up to (excluding) the root
		for (int v = node; v > 0; v = (v - 1) / 2) path.push_back(v);
		for (int k = (int) path.size() - 1; k >= 0; k--) {
			int child = path[k], parent = (child - 1) / 2;
			bool left = (child % 2 == 1);
			for (int j = 0; j < n; j++) {
				bool in_left = x[j][split_attr[parent]] < split_val[parent];
				expected_node[j] = expected_node[j] && (left ? in_left : !in_left);
			}
		}
		Ciphertext sel = selection_vector[node], part = preprocessed_partitions[0][1], prod;
		obl_match_levels(context, evaluator, sel, part);
		evaluator.multiply(part, sel, prod);
		evaluator.relinearize_inplace(prod, relin_keys);
		evaluator.mod_switch_to_next_inplace(prod);
		int e = 0;
		decryptor.decrypt(prod, pl);
		batch_encoder.decode(pl, dec);
		for (int a = 0; a < A; a++)
			for (int j = 0; j < n; j++) {
				int expect = expected_node[j] && (x[j][a] < 1);
				if ((int) dec[(size_t) a * V * n + j] != expect) e++;
			}
		cout << "final partition product (deepest sel x partition): " << (e ? "WRONG" : "ok") << ", chain "
		     << context.get_context_data(prod.parms_id())->chain_index() << ", budget " << decryptor.invariant_noise_budget(prod) << " bits\n";
		errors += e;
	}
	cout << (errors ? "FAILED" : "ALL CHILDREN CORRECT") << endl;
	return errors ? 1 : 0;
}
