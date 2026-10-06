// Standalone correctness + noise test for the oblivious selection-vector update (util.h: oblivious_update_selection_vector).
//
// It builds a random one-hot dataset, preprocesses the partitions exactly like main_integrity.cpp, then walks a small
// decision tree. Every node gets a random split (attr, theta) which is only handed to the server as two *fresh* ciphertexts.
// After each update the children are decrypted and compared with plaintext training on the same data, and the noise budget of
// every stage is printed so that the modulus chain can be tuned.
//
// usage: ./test_obl [N n A V depth  base_n base_bits  topup_n topup_bits  special_bits  fermat_switch_every  light  stress]
//   N         poly modulus degree (iris: 16384, small functional test: 4096)
//   n A V     data_size, attr_size, value_size  (iris: 100 4 8)
//   depth     number of tree levels that get an update (levels 0..depth-2 are updated, as in main_integrity)
//   stress    k > 0: instead of a tree, run k independent random splits on the root (checks that the noise of the equality test is
//             safe for every split, not just for a lucky one) and print the minimum final budget
//             k < 0: only the equality test (ObliviousRotation), |k| random r; counts how often the output is not exactly the unit vector
//   light     1 = skip preprocess_all_threshold (saves its Galois keys / RAM): the "x < theta" partitions are encrypted directly
//   chain     coeff modulus = base_n x base_bits  +  topup_n x topup_bits  +  special_bits   (last prime is SEAL's special prime)

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
	int light = arg(12, 0);
	int stress = arg(13, 0);
	int base_n = arg(6, 8), base_bits = arg(7, 34);
	int topup_n = arg(8, 18), topup_bits = arg(9, 44);
	int special_bits = arg(10, 50);
	int switch_every = arg(11, 1);

	const int n = data_size_glb, A = attr_size_glb, V = value_size_glb;
	const size_t N = poly_modulus_degree_glb, row = N / 2;
	cout << "N=" << N << " n=" << n << " A=" << A << " V=" << V << " depth=" << depth << endl;

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
	for (int s : oblivious_update_rotation_steps(n, A, V)) steps.insert(s);
	GaloisKeys gal_keys;
	keygen.create_galois_keys(vector<int>(steps.begin(), steps.end()), gal_keys);
	cout << "generated " << steps.size() << " Galois keys\n";

	// ---- noise trace
	oblivious_trace_glb = [&](const string& name, const Ciphertext& ct) {
		cout << "      [" << name << "] chain " << context.get_context_data(ct.parms_id())->chain_index()
		     << ", budget " << decryptor.invariant_noise_budget(ct) << " bits\n";
	};

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
		decryptor.decrypt(inputs_X[0], pl);
		batch_encoder.decode(pl, dec);
		for (int a = 0; a < A; a++)
			for (int v = 0; v < V; v++)
				for (int j = 0; j < n; j++)
					if (dec[(size_t) a * V * n + v * n + j] == 1) x[j][a] = v;
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
	build_oblivious_sel_ctx(oc, preprocessed_partitions, context, evaluator, batch_encoder, gal_keys);

	// check P:  slot a*V*n + theta*n + j == [x_{j,a} < theta]
	decryptor.decrypt(oc.packed_partitions, pl);
	batch_encoder.decode(pl, dec);
	int bad = 0;
	for (size_t s = 0; s < N; s++) {
		int expect = 0;
		if (s < (size_t) A * V * n) {
			int a = s / (V * n), th = (s / n) % V, j = s % n;
			expect = (x[j][a] < th) ? 1 : 0;
		}
		if ((int) dec[s] != expect) bad++;
	}
	cout << "packed partitions P: " << (bad ? "WRONG (" + to_string(bad) + " slots)" : "ok") << ", budget "
	     << decryptor.invariant_noise_budget(oc.packed_partitions) << " bits\n";

	if (stress < 0) {
		mt19937 srng(4242);
		int bad = 0, min_budget = 100000, min_sq8 = 100000;
		vector<uint64_t> d2;
		for (int it = 0; it < -stress; it++) {
			uint64_t r = srng() % (A * V * n);
			vector<uint64_t> v1(N, 0);
			v1[0] = r;
			Plaintext p1;
			Ciphertext ct_r;
			batch_encoder.encode(v1, p1);
			encryptor.encrypt(p1, ct_r);
			int sq8 = -1;
			oblivious_trace_glb = [&](const string& name, const Ciphertext& ct) {
				if (name == "square 8") sq8 = decryptor.invariant_noise_budget(ct);
			};
			Ciphertext out = oblivious_rotation(context, evaluator, oc, relin_keys, gal_keys, ct_r);
			decryptor.decrypt(out, pl);
			batch_encoder.decode(pl, d2);
			int e = 0;
			for (size_t j = 0; j < N; j++) if (d2[j] != (j == r ? 1 : 0)) e++;
			int fb = decryptor.invariant_noise_budget(out);
			min_budget = min(min_budget, fb);
			min_sq8 = min(min_sq8, sq8);
			bad += (e != 0);
			if (e || (it % 20 == 0)) cout << "  trial " << it << " r=" << r << ": budget after square 8 = " << sq8 << ", final " << fb << (e ? "  WRONG" : "  ok") << endl;
		}
		cout << "equality-test stress: " << bad << "/" << -stress << " wrong, min budget after square 8 = " << min_sq8 << ", min final budget " << min_budget << endl;
		return bad ? 1 : 0;
	}

	if (stress > 0) {
		vector<Ciphertext> sv(3);
		vector<uint64_t> ones_v(N, 1);
		Plaintext pr;
		batch_encoder.encode(ones_v, pr);
		encryptor.encrypt(pr, sv[0]);
		mt19937 srng(777);
		int bad_splits = 0, min_budget = 100000;
		vector<uint64_t> d2;
		for (int it = 0; it < stress; it++) {
			int a = srng() % A, th = 1 + srng() % (V - 1);
			if (it == 0) { a = 0; th = 2; }   // the split that failed on a marginal chain
			vector<uint64_t> v1(N, 0), v2(N, 0);
			v1[0] = a; v2[0] = th;
			Plaintext p1, p2;
			Ciphertext ct_a, ct_th;
			batch_encoder.encode(v1, p1); batch_encoder.encode(v2, p2);
			encryptor.encrypt(p1, ct_a); encryptor.encrypt(p2, ct_th);
			oblivious_trace_glb = nullptr;
			int fermat_budget = -1;
			oblivious_trace_glb = [&](const string& name, const Ciphertext& ct) {
				if (name == "unit vector") fermat_budget = decryptor.invariant_noise_budget(ct);
			};
			oblivious_update_selection_vector(sv, oc, ct_a, ct_th, 0, 0, context, evaluator, relin_keys, gal_keys);
			int e = 0;
			for (int c = 1; c <= 2; c++) {
				decryptor.decrypt(sv[c], pl);
				batch_encoder.decode(pl, d2);
				for (int blk = 0; blk < A * V; blk++)
					for (int j = 0; j < n; j++) {
						int in_left = x[j][a] < th;
						int expect = (c == 1) ? in_left : !in_left;
						if ((int) d2[(size_t) blk * n + j] != expect) e++;
					}
			}
			int fb = decryptor.invariant_noise_budget(sv[1]);
			min_budget = min(min_budget, fb);
			bad_splits += (e != 0);
			cout << "  split (attr " << a << ", theta " << th << "): equality-test output budget " << fermat_budget << ", left child budget " << fb
			     << (e ? "  WRONG" : "  ok") << endl;
		}
		cout << "stress: " << bad_splits << "/" << stress << " splits wrong, min left-child budget " << min_budget << endl;
		return bad_splits ? 1 : 0;
	}

	// ---- tree walk
	vector<Ciphertext> selection_vector((size_t) 1 << depth);
	vector<vector<int>> expected(selection_vector.size(), vector<int>(n, 0));
	vector<uint64_t> ones(N, 1);
	batch_encoder.encode(ones, pl);
	encryptor.encrypt(pl, selection_vector[0]);   // root: everything is selected
	fill(expected[0].begin(), expected[0].end(), 1);

	mt19937 rng(1234);
	int errors = 0;
	long long total_us = 0;
	for (int d = 0; d < depth - 1; d++) {
		for (int nd = 0; nd < (1 << d); nd++) {
			int a = rng() % A, th = 1 + rng() % (V - 1);
			// the two *fresh* split ciphertexts: (a,0,...,0) and (theta,0,...,0)
			vector<uint64_t> v1(N, 0), v2(N, 0);
			v1[0] = a; v2[0] = th;
			Plaintext p1, p2;
			Ciphertext ct_a, ct_th;
			batch_encoder.encode(v1, p1); batch_encoder.encode(v2, p2);
			encryptor.encrypt(p1, ct_a); encryptor.encrypt(p2, ct_th);

			cout << "  level " << d << " node " << nd << ": split (attr " << a << ", theta " << th << ")\n";
			auto t0 = chrono::high_resolution_clock::now();
			oblivious_update_selection_vector(selection_vector, oc, ct_a, ct_th, d, nd, context, evaluator, relin_keys, gal_keys);
			total_us += chrono::duration_cast<chrono::microseconds>(chrono::high_resolution_clock::now() - t0).count();

			int parent = (1 << d) - 1 + nd, left = 2 * parent + 1, right = left + 1;
			for (int j = 0; j < n; j++) {
				int in_left = x[j][a] < th;
				expected[left][j] = expected[parent][j] && in_left;
				expected[right][j] = expected[parent][j] && !in_left;
			}
			for (int c = left; c <= right; c++) {
				decryptor.decrypt(selection_vector[c], pl);
				batch_encoder.decode(pl, dec);
				int e = 0;
				for (int blk = 0; blk < A * V; blk++)          // tiled over every block of the packed region
					for (int j = 0; j < n; j++)
						if ((int) dec[(size_t) blk * n + j] != expected[c][j]) e++;
				cout << "    child " << c << ": " << (e ? "WRONG" : "ok") << ", chain "
				     << context.get_context_data(selection_vector[c].parms_id())->chain_index() << ", budget "
				     << decryptor.invariant_noise_budget(selection_vector[c]) << " bits\n";
				errors += e;
			}
		}
	}

	// ---- what happens to the deepest selection vector afterwards (perform_partition_for_node / leaf labeling): one CT x CT with
	// a preprocessed ciphertext, then a mod switch; the result must still decrypt correctly
	{
		int node = (1 << (depth - 1)) - 1;                    // first node of the deepest level that has a selection vector
		if (depth == 1) node = 0;
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
				int expect = expected[node][j] && (x[j][a] < 1);
				if ((int) dec[(size_t) a * V * n + j] != expect) e++;
			}
		cout << "final partition product (deepest sel x partition): " << (e ? "WRONG" : "ok") << ", chain "
		     << context.get_context_data(prod.parms_id())->chain_index() << ", budget " << decryptor.invariant_noise_budget(prod) << " bits\n";
		errors += e;
	}
	cout << "avg time per node update: " << total_us / max(1, (1 << (depth - 1)) - 1) / 1000 << " ms\n";
	cout << (errors ? "FAILED" : "ALL CHILDREN CORRECT") << endl;
	return errors ? 1 : 0;
}
