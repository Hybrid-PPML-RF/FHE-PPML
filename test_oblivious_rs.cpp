// Correctness + noise + runtime test of the oblivious selection-vector update with the equality test in a second ring
// (N_big = 2 * N_small, ring switching, see util.h and ring_switch.h).
//
// Two SEAL contexts:
//   small (N = N_small): the data ciphertexts, P, the selection vectors.  Chain = shared_n primes + special prime.
//   big   (N = 2 N_small): the split ciphertexts and the equality test.  Chain = the same shared_n primes + extra primes for the
//                          equality test + special prime.  Independent secret key; key-switched to embed(sk_small) after the test.
// A tree is walked level by level; every group of G nodes shares one pair of fresh big-ring ciphertexts (attribute, threshold),
// the children are decrypted and compared with plaintext training.  The partitions are encrypted directly ("light" setup of
// test_oblivious_update_sel.cpp).
//
// usage: ./test_orsw [N_small n A V depth  shared_n shared_bits special_small_bits  extra_bits special_big_bits  log_base  stress]
//   shared_n  primes of the small data chain (0 = depth + 3, the number the update needs: P, mask, depth-2 updates, 2 for the node processing, + 1 base)
//   stress    k > 0: k random groups on the root instead of a tree (min budgets over many random splits)

#include <chrono>
#include <iostream>
#include <random>
#include <set>
#include "seal/seal.h"
#include "util.h"
#include "global.h"

using namespace seal;
using namespace std;
using namespace std::chrono;

int main(int argc, char* argv[]) {
	auto arg = [&](int i, int def) { return argc > i ? stoi(argv[i]) : def; };
	poly_modulus_degree_glb = arg(1, 4096);
	data_size_glb = arg(2, 24);
	attr_size_glb = arg(3, 4);
	value_size_glb = arg(4, 8);
	label_size_glb = 2;
	sqrt_attr_size_glb = attr_size_glb;
	const int depth = arg(5, 3);
	depth_glb = depth;
	int shared_n = arg(6, 0);
	if (shared_n == 0) shared_n = depth + 3;
	const int shared_bits = arg(7, 40), special_small_bits = arg(8, 40);
	const int extra_bits = arg(9, 40), special_big_bits = arg(10, 50);
	const int log_base = arg(11, 8);
	const int stress = arg(12, 0);

	const int n = data_size_glb, A = attr_size_glb, V = value_size_glb;
	const size_t N_small = poly_modulus_degree_glb, N_big = 2 * N_small, row = N_small / 2;
	const uint64_t t = 65537;
	const int extra_n = oblivious_equality_levels(true, A, V, t);
	cout << "N_small=" << N_small << " N_big=" << N_big << " n=" << n << " A=" << A << " V=" << V << " depth=" << depth
	     << ", equality test: " << extra_n << " levels in the big ring\n";

	// ---- primes: shared (small data chain), extra (equality test), special_big, special_small.  All = 1 mod 2*N_big.
	vector<int> bits;
	for (int i = 0; i < shared_n; i++) bits.push_back(shared_bits);
	for (int i = 0; i < extra_n; i++) bits.push_back(extra_bits);
	bits.push_back(special_big_bits);
	bits.push_back(special_small_bits);
	auto primes = CoeffModulus::Create(N_big, bits);
	vector<Modulus> small_chain(primes.begin(), primes.begin() + shared_n), big_chain(primes.begin(), primes.begin() + shared_n + extra_n);
	big_chain.push_back(primes[shared_n + extra_n]);
	small_chain.push_back(primes[shared_n + extra_n + 1]);
	int big_bits = 0, small_bits = 0;
	for (auto& m : big_chain) big_bits += m.bit_count();
	for (auto& m : small_chain) small_bits += m.bit_count();
	cout << "small context: " << shared_n << " x " << shared_bits << " + special " << special_small_bits << " = " << small_bits
	     << " bits (128-bit bound " << CoeffModulus::MaxBitCount(N_small) << ")\n";
	cout << "big   context: " << shared_n << " shared + " << extra_n << " x " << extra_bits << " + special " << special_big_bits << " = "
	     << big_bits << " bits (128-bit bound " << CoeffModulus::MaxBitCount(N_big) << ")\n";

	EncryptionParameters parms_small(scheme_type::bgv), parms_big(scheme_type::bgv);
	parms_small.set_poly_modulus_degree(N_small);
	parms_small.set_coeff_modulus(small_chain);
	parms_small.set_plain_modulus(t);
	parms_big.set_poly_modulus_degree(N_big);
	parms_big.set_coeff_modulus(big_chain);
	parms_big.set_plain_modulus(t);
	SEALContext ctx_small(parms_small, true, sec_level_type::none), ctx_big(parms_big, true, sec_level_type::none);

	// ---- keys
	auto sk_small_c = rsw::sample_ternary(N_small, 111), sk_big_c = rsw::sample_ternary(N_big, 222);
	auto sk_target_c = rsw::embed_sk(sk_small_c);
	SecretKey sk_small = rsw::make_secret_key(sk_small_c, ctx_small), sk_big = rsw::make_secret_key(sk_big_c, ctx_big);
	KeyGenerator kg_small(ctx_small, sk_small), kg_big(ctx_big, sk_big);
	PublicKey pk_small, pk_big;
	kg_small.create_public_key(pk_small);
	kg_big.create_public_key(pk_big);
	RelinKeys relin_small, relin_big;
	kg_small.create_relin_keys(relin_small);
	kg_big.create_relin_keys(relin_big);
	GaloisKeys gal_small;
	{
		set<int> steps;
		for (int s : oblivious_update_rotation_steps(n, A, V, true)) steps.insert(s);
		kg_small.create_galois_keys(vector<int>(steps.begin(), steps.end()), gal_small);
		cout << "Galois keys (small ring): " << steps.size() << "\n";
	}
	Encryptor enc_small(ctx_small, pk_small), enc_big(ctx_big, pk_big);
	Evaluator eval_small(ctx_small), eval_big(ctx_big);
	Decryptor dec_small(ctx_small, sk_small);
	BatchEncoder batch_small(ctx_small);

	parms_id_type level_id = ctx_big.first_context_data()->parms_id();       // the level of the shared primes
	for (int i = 0; i < extra_n; i++) level_id = ctx_big.get_context_data(level_id)->next_context_data()->parms_id();
	auto t0 = steady_clock::now();
	rsw::KSwitchKey ksk = rsw::gen_key_switch_key(sk_big_c, sk_target_c, ctx_big, level_id, t, log_base, 333);
	cout << "key-switching key: " << ksk.pieces.size() << " primes x " << ksk.num_digits << " digits (base 2^" << log_base << ")\n";

	// ---- data: partitions encrypted directly (small ring) + P
	Plaintext pl;
	vector<uint64_t> dec;
	vector<vector<int>> x(n, vector<int>(A));
	vector<vector<Ciphertext>> preprocessed_partitions(1);
	{
		mt19937 drng(99);
		for (int j = 0; j < n; j++) for (int a = 0; a < A; a++) x[j][a] = drng() % V;
		preprocessed_partitions[0].resize(2 * V - 1);
		for (int th = 1; th < V; th++) {
			vector<uint64_t> vec(N_small, 0);
			for (int a = 0; a < A; a++)
				for (int o = 0; o < V * n; o++)
					vec[(size_t) a * V * n + o] = (o < n) ? (x[o][a] < th) : (drng() % 3);
			Plaintext p;
			batch_small.encode(vec, p);
			enc_small.encrypt(p, preprocessed_partitions[0][2 * th - 1]);
		}
	}
	ObliviousSelCtx oc;
	oc.equality_poly = true;
	build_oblivious_sel_ctx(oc, preprocessed_partitions, ctx_small, eval_small, batch_small, gal_small);
	const int G = oc.group_size;
	ObliviousRingSwitch rs;
	oblivious_ring_switch_init(rs, ctx_big, eval_big, relin_big, ksk, oc);
	cout << "group size G = " << G << " nodes per ciphertext; P budget " << dec_small.invariant_noise_budget(oc.packed_partitions)
	     << " bits at chain " << ctx_small.get_context_data(oc.packed_partitions.parms_id())->chain_index() << "\n";

	auto encrypt_group = [&](const vector<int>& values) { return oblivious_encrypt_group_big(oc, values, batch_small, enc_big, N_big, true); };

	// ---- random groups on the root
	if (stress > 0) {
		vector<uint64_t> ones_v(N_small, 1);
		Plaintext pr;
		batch_small.encode(ones_v, pr);
		mt19937 srng(777);
		int bad_groups = 0, min_budget = 100000;
		vector<uint64_t> d2;
		for (int it = 0; it < stress; it++) {
			vector<Ciphertext> sv(3);
			enc_small.encrypt(pr, sv[0]);
			vector<int> as(G), ts(G);
			for (int g = 0; g < G; g++) { as[g] = srng() % A; ts[g] = 1 + srng() % (V - 1); }
			Ciphertext ct_a = encrypt_group(as), ct_t = encrypt_group(ts);
			Ciphertext T = oblivious_group_threshold_data_rs(ctx_small, eval_small, oc, relin_small, gal_small, rs, ct_a, ct_t);
			int e = 0, fb_min = 100000;
			for (int g = 0; g < G; g++) {
				oblivious_apply_threshold_data(sv, T, g, 0, 0, oc, ctx_small, eval_small, relin_small, gal_small);
				for (int c = 1; c <= 2; c++) {
					dec_small.decrypt(sv[c], pl);
					batch_small.decode(pl, d2);
					for (int blk = 0; blk < A * V; blk++)
						for (int j = 0; j < n; j++) {
							int in_left = x[j][as[g]] < ts[g];
							if ((int) d2[(size_t) blk * n + j] != ((c == 1) ? in_left : !in_left)) e++;
						}
				}
				fb_min = min(fb_min, (int) dec_small.invariant_noise_budget(sv[1]));
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
	{
		vector<uint64_t> ones(N_small, 1);
		batch_small.encode(ones, pl);
		enc_small.encrypt(pl, selection_vector[0]);
	}
	const int num_internal = (1 << (depth - 1)) - 1;
	vector<int> split_attr(num_internal), split_val(num_internal);
	mt19937 rng(1234);
	long long eq_us = 0, ext_us = 0, apply_us = 0;
	int groups_done = 0, nodes_done = 0, sel_bad_groups = 0;
	for (int d = 0; d < depth - 1; d++) {
		for (int first = 0; first < (1 << d); first += G) {
			int cnt = min(G, (1 << d) - first);
			vector<int> as(cnt), ts(cnt);
			for (int g = 0; g < cnt; g++) {
				as[g] = rng() % A; ts[g] = 1 + rng() % (V - 1);
				split_attr[(1 << d) - 1 + first + g] = as[g];
				split_val[(1 << d) - 1 + first + g] = ts[g];
			}
			Ciphertext ct_a = encrypt_group(as), ct_t = encrypt_group(ts);

			auto a0 = steady_clock::now();
			Ciphertext selector_big = oblivious_selector_poly(ctx_big, eval_big, rs.oc_big, relin_big, ct_a, ct_t);
			auto a1 = steady_clock::now();
			Ciphertext selector = rsw::ring_switch(selector_big, ksk, ctx_big, ctx_small);
			auto a2 = steady_clock::now();
			if (groups_done == 0) {
				cout << "  first group: selector in the big ring: chain " << ctx_big.get_context_data(selector_big.parms_id())->chain_index()
				     << "; after ring switching (small ring): chain " << ctx_small.get_context_data(selector.parms_id())->chain_index()
				     << ", budget " << dec_small.invariant_noise_budget(selector) << " bits\n";
			}
			Ciphertext T = oblivious_threshold_from_selector(ctx_small, eval_small, oc, relin_small, gal_small, selector);
			auto a3 = steady_clock::now();
			for (int g = 0; g < cnt; g++)
				oblivious_apply_threshold_data(selection_vector, T, g, d, first + g, oc, ctx_small, eval_small, relin_small, gal_small);
			auto a4 = steady_clock::now();
			eq_us += duration_cast<microseconds>(a1 - a0).count();
			ext_us += duration_cast<microseconds>(a2 - a1).count() + duration_cast<microseconds>(a3 - a2).count();
			apply_us += duration_cast<microseconds>(a4 - a3).count();
			groups_done++; nodes_done += cnt;

			// slot-level check of the ring-switched selector (not timed): in region g it must hold selector_scale exactly on the n slots
			// [r n, (r+1) n) of chunk r = attr * V + theta, and 0 everywhere else (unused regions carry attr = theta = 0, i.e. chunk 0)
			{
				vector<uint64_t> sd;
				dec_small.decrypt(selector, pl);
				batch_small.decode(pl, sd);
				vector<uint64_t> expect(N_small, 0);
				for (int g = 0; g < oc.group_size; g++) {
					int r = g < cnt ? as[g] * V + ts[g] : 0, base = obl_region_base(oc, g);
					for (int o = r * n; o < (r + 1) * n; o++) expect[base + o] = oc.selector_scale;
				}
				int e = 0;
				for (size_t j = 0; j < N_small; j++) e += (sd[j] != expect[j]);
				sel_bad_groups += (e != 0);
				if (groups_done == 1) {
					for (int g = 0; g < min(cnt, 2); g++) {
						int r = as[g] * V + ts[g], base = obl_region_base(oc, g), lo = -1, hi = -1;
						for (int o = 0; o < oc.region_size; o++) if (sd[base + o]) { if (lo < 0) lo = o; hi = o + 1; }
						cout << "  selector of node " << g << ": split (attr " << as[g] << ", theta " << ts[g] << ") = chunk r = " << r
						     << ", non-zero slots of its region: [" << lo << ", " << hi << ") = [r*n, (r+1)*n) = [" << r * n << ", " << (r + 1) * n << ")\n";
					}
				}
			}
		}
	}
	cout << "selector check (every group, every slot): " << (sel_bad_groups ? to_string(sel_bad_groups) + " groups WRONG" : string("ok")) << endl;
	cout << "groups: " << groups_done << " (" << nodes_done << " nodes); single-threaded totals: equality test in the big ring " << eq_us / 1000
	     << " ms, ring switch + extraction (P, fold, mask, tile) " << ext_us / 1000 << " ms, per-node application " << apply_us / 1000
	     << " ms; all: " << (eq_us + ext_us + apply_us) / 1000 << " ms\n";

	int errors = verify_oblivious_selection_vectors(selection_vector, split_attr, split_val, x, depth, dec_small, batch_small, ctx_small);
	cout << "selection vectors vs plaintext training: " << (errors ? "WRONG slots: " + to_string(errors) : string("ok")) << endl;
	for (int d = 1; d < depth; d++) {
		int mn = 100000, chain = -1;
		for (int i = (1 << d) - 1; i < (1 << (d + 1)) - 1; i++) {
			mn = min(mn, (int) dec_small.invariant_noise_budget(selection_vector[i]));
			chain = (int) ctx_small.get_context_data(selection_vector[i].parms_id())->chain_index();
		}
		cout << "  level " << d << " selection vectors: chain " << chain << ", min budget " << mn << " bits\n";
	}

	// deepest selection vector x a partition (what the node processing / leaf labeling does with it)
	{
		int node = (1 << (depth - 1)) - 1;
		vector<int> expected_node(n, 1), path;
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
		obl_match_levels(ctx_small, eval_small, sel, part);
		eval_small.multiply(part, sel, prod);
		eval_small.relinearize_inplace(prod, relin_small);
		eval_small.mod_switch_to_next_inplace(prod);
		int e = 0;
		dec_small.decrypt(prod, pl);
		batch_small.decode(pl, dec);
		for (int a = 0; a < A; a++)
			for (int j = 0; j < n; j++)
				if ((int) dec[(size_t) a * V * n + j] != (expected_node[j] && (x[j][a] < 1))) e++;
		cout << "final partition product (deepest sel x partition): " << (e ? "WRONG" : "ok") << ", chain "
		     << ctx_small.get_context_data(prod.parms_id())->chain_index() << ", budget " << dec_small.invariant_noise_budget(prod) << " bits\n";
		errors += e;
	}
	cout << (errors ? "FAILED" : "ALL CHILDREN CORRECT") << endl;
	return errors ? 1 : 0;
}
