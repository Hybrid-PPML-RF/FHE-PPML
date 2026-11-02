// Correctness + noise + runtime test of the oblivious selection-vector update for datasets whose partitions need SEVERAL
// ciphertexts (oblivious_multi.h), with the equality test in the big ring (ring switching, ring_switch.h).
//
// usage: ./test_omulti [N_small n A V depth  nprime  shared_n shared_bits special_small_bits  extra_bits special_big_bits  log_base  stress]
//   nprime    datapoint chunk size n' (0 = cost model of omc_choose_chunk)
//   shared_n  primes of the data chain (0 = depth + 4: stretch, partitions, mask, depth-2 updates S*T, 2 for the node processing, + 1 base)
//   stress    k > 0: k random groups on the root instead of a tree
//   profile   1: only the first group and its first node, with the time and budget after every stage
//             2: slot-level check of the selectors S_c of every node of `stress` random groups
//
// iris-like sizes:  ./test_omulti 16384 100 4 8 6          digits:  ./test_omulti 16384 1203 64 17 6

#include <chrono>
#include <iostream>
#include <random>
#include <set>
#include "seal/seal.h"
#include "oblivious_multi.h"
#include "global.h"

using namespace seal;
using namespace std;
using namespace std::chrono;

int main(int argc, char* argv[]) {
	auto arg = [&](int i, int def) { return argc > i ? stoi(argv[i]) : def; };
	poly_modulus_degree_glb = arg(1, 4096);
	data_size_glb = arg(2, 200);
	attr_size_glb = arg(3, 40);
	value_size_glb = arg(4, 9);
	label_size_glb = 2;
	sqrt_attr_size_glb = attr_size_glb;
	const int depth = arg(5, 3);
	depth_glb = depth;
	const int nprime_arg = arg(6, 0);
	int shared_n = arg(7, 0);
	if (shared_n == 0) shared_n = depth + 4;
	const int shared_bits = arg(8, 40), special_small_bits = arg(9, 40);
	const int extra_bits = arg(10, 40), special_big_bits = arg(11, 50);
	const int log_base = arg(12, 8);
	const int stress = arg(13, 0);
	const int profile = arg(14, 0);

	const int n = data_size_glb, A = attr_size_glb, V = value_size_glb;
	const size_t N_small = poly_modulus_degree_glb, N_big = 2 * N_small;
	const uint64_t t = 65537;
	const int extra_n = oblivious_equality_levels(true, A, V, t);

	// ---- primes: shared (data chain), extra (equality test), special_big, special_small.  All = 1 mod 2*N_big.
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
	cout << "N_small=" << N_small << " n=" << n << " A=" << A << " V=" << V << " depth=" << depth << "; equality test: " << extra_n << " levels in the big ring\n";
	cout << "small context: " << shared_n << " x " << shared_bits << " + special " << special_small_bits << " = " << small_bits << " bits (128-bit bound "
	     << CoeffModulus::MaxBitCount(N_small) << ")\n";
	cout << "big   context: " << shared_n << " shared + " << extra_n << " x " << extra_bits << " + special " << special_big_bits << " = " << big_bits
	     << " bits (128-bit bound " << CoeffModulus::MaxBitCount(N_big) << ")\n";

	EncryptionParameters parms_small(scheme_type::bgv), parms_big(scheme_type::bgv);
	parms_small.set_poly_modulus_degree(N_small);
	parms_small.set_coeff_modulus(small_chain);
	parms_small.set_plain_modulus(t);
	parms_big.set_poly_modulus_degree(N_big);
	parms_big.set_coeff_modulus(big_chain);
	parms_big.set_plain_modulus(t);
	SEALContext ctx_small(parms_small, true, sec_level_type::none), ctx_big(parms_big, true, sec_level_type::none);

	// ---- keys (OS entropy; the test only needs them in one process)
	auto sk_small_c = rsw::sample_ternary(N_small, 0), sk_big_c = rsw::sample_ternary(N_big, 0);
	auto sk_target_c = rsw::embed_sk(sk_small_c);
	SecretKey sk_small = rsw::make_secret_key(sk_small_c, ctx_small), sk_big = rsw::make_secret_key(sk_big_c, ctx_big);
	KeyGenerator kg_small(ctx_small, sk_small), kg_big(ctx_big, sk_big);
	PublicKey pk_small, pk_big;
	kg_small.create_public_key(pk_small);
	kg_big.create_public_key(pk_big);
	RelinKeys relin_small, relin_big;
	kg_small.create_relin_keys(relin_small);
	kg_big.create_relin_keys(relin_big);
	Encryptor enc_small(ctx_small, pk_small), enc_big(ctx_big, pk_big);
	Evaluator eval_small(ctx_small), eval_big(ctx_big);
	Decryptor dec_small(ctx_small, sk_small);
	BatchEncoder batch_small(ctx_small);

	// ---- geometry, plaintexts, Galois keys
	ObliviousMultiCtx mc;
	auto t0 = steady_clock::now();
	omc_init(mc, n, A, V, ctx_small, eval_small, batch_small, nprime_arg);
	cout << "layout: n'=" << mc.nprime << " (" << mc.J << " datapoint chunks), " << mc.B << " blocks of n' slots, " << mc.kk << " per ciphertext -> "
	     << mc.m_b << " ciphertexts per chunk, " << mc.J * mc.m_b << " ciphertexts of P; compact regions of " << mc.B << " slots: "
	     << mc.G << " nodes per ciphertext; stretch bs=" << mc.bs << " gs=" << mc.gs << "\n";
	GaloisKeys gal_small;
	{
		set<int> steps;
		for (int s : omc_rotation_steps(mc)) steps.insert(s);
		kg_small.create_galois_keys(vector<int>(steps.begin(), steps.end()), gal_small);
		cout << "Galois keys (small ring): " << steps.size() << "\n";
	}
	parms_id_type level_id = ctx_big.first_context_data()->parms_id();       // the level of the shared primes
	for (int i = 0; i < extra_n; i++) level_id = ctx_big.get_context_data(level_id)->next_context_data()->parms_id();
	rsw::KSwitchKey ksk = rsw::gen_key_switch_key(sk_big_c, sk_target_c, ctx_big, level_id, t, log_base, 0);

	// ---- data
	vector<vector<int>> x(n, vector<int>(A));
	{
		mt19937 drng(99);
		for (int j = 0; j < n; j++) for (int a = 0; a < A; a++) x[j][a] = drng() % V;
	}
	omc_encrypt_partitions(mc, x, ctx_small, eval_small, batch_small, enc_small);
	const int top = (int) ctx_small.first_context_data()->chain_index();
	cout << "setup " << duration_cast<milliseconds>(steady_clock::now() - t0).count() << " ms; P: " << mc.J * mc.m_b << " ciphertexts at chain " << top - 1
	     << ", budget " << dec_small.invariant_noise_budget(mc.P[0][0]) << " bits\n";

	ObliviousRingSwitch rs;
	oblivious_ring_switch_init(rs, ctx_big, eval_big, relin_big, ksk, mc.eq_small);

	// ---- root selection vector: everything selected, tile format (ones everywhere)
	vector<Ciphertext> selection_vector((size_t) 1 << depth);
	Plaintext pl;
	vector<uint64_t> dec;
	{
		vector<uint64_t> ones(N_small, 1);
		batch_small.encode(ones, pl);
		enc_small.encrypt(pl, selection_vector[0]);
		for (int i = 0; i < 3; i++) eval_small.mod_switch_to_next_inplace(selection_vector[0]);     // = chain of T (only the level matters, the root is public)
	}

	// ---- slot-level check of the selectors (profile = 2, `stress` random groups, every node of a group): S_c must hold the selector
	//      scale exactly on the n' slots of the selected block b* = attr (V-1) + theta - 1, i.e. block position p = b* - c kk of
	//      P-ciphertext c (row p / rho', slots [(p mod rho') n', +n')), and 0 on all other blocks of P
	if (profile == 2) {
		mt19937 crng(31);
		const int groups = max(1, stress);
		const size_t R = N_small / 2;
		int bad_nodes = 0, checked = 0;
		for (int it = 0; it < groups; it++) {
			vector<int> as(mc.G), ts(mc.G);
			for (int g = 0; g < mc.G; g++) { as[g] = crng() % A; ts[g] = 1 + crng() % (V - 1); }
			Ciphertext ct_a = omc_encrypt_group_big(mc, as, batch_small, enc_big, N_big), ct_t = omc_encrypt_group_big(mc, ts, batch_small, enc_big, N_big);
			Ciphertext U = rsw::ring_switch(oblivious_selector_poly(ctx_big, eval_big, rs.oc_big, relin_big, ct_a, ct_t), ksk, ctx_big, ctx_small);
			for (int g = 0; g < mc.G; g++) {
				vector<Ciphertext> S;
				omc_node_threshold_data(ctx_small, eval_small, mc, relin_small, gal_small, U, g, &S);
				const int bstar = as[g] * (V - 1) + ts[g] - 1;
				int e = 0, hits = 0;
				for (int cc = 0; cc < mc.m_b; cc++) {
					dec_small.decrypt(S[cc], pl);
					batch_small.decode(pl, dec);
					for (int row = 0; row < 2; row++)
						for (size_t s = 0; s < R; s++) {
							uint64_t v = dec[row * R + s];
							if (s >= (size_t) mc.rho_p * mc.nprime) { e += (v != 0); continue; }      // no block there
							int b = cc * mc.kk + row * mc.rho_p + (int) (s / mc.nprime);
							if (b >= mc.B) continue;                                            // beyond the last block: meets zeros of P
							uint64_t expect = (b == bstar) ? mc.selector_scale : 0;
							e += (v != expect);
							hits += (v != 0 && v == expect);
						}
				}
				checked++;
				bad_nodes += (e != 0 || hits != mc.nprime);
				if (it == 0 && g < 3) {
					int p = bstar % mc.kk;
					cout << "  node " << g << ": split (attr " << as[g] << ", theta " << ts[g] << ") = block b* = " << bstar << " -> P-ciphertext c = "
					     << bstar / mc.kk << ", row " << p / mc.rho_p << ", slots [" << (p % mc.rho_p) * mc.nprime << ", " << (p % mc.rho_p + 1) * mc.nprime
					     << "): " << hits << " slots carry the selector scale, " << e << " wrong slots over all " << mc.m_b << " selectors\n";
				}
			}
		}
		cout << "selector check: " << bad_nodes << "/" << checked << " nodes wrong" << endl;
		return bad_nodes ? 1 : 0;
	}

	// ---- profile of one group / one node
	if (profile == 1) {
		chrono::steady_clock::time_point last = chrono::steady_clock::now();
		oblivious_trace_glb = [&](const string& name, const Ciphertext& ct) {
			double ms = chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - last).count() / 1000.0;
			cout << "      [" << name << "] chain " << ctx_small.get_context_data(ct.parms_id())->chain_index() << ", budget "
			     << dec_small.invariant_noise_budget(ct) << " bits, +" << ms << " ms\n";
			last = chrono::steady_clock::now();
		};
		mt19937 prng(5);
		vector<int> as(mc.G), ts(mc.G);
		for (int g = 0; g < mc.G; g++) { as[g] = prng() % A; ts[g] = 1 + prng() % (V - 1); }
		Ciphertext ct_a = omc_encrypt_group_big(mc, as, batch_small, enc_big, N_big), ct_t = omc_encrypt_group_big(mc, ts, batch_small, enc_big, N_big);
		auto a0 = steady_clock::now();
		oblivious_trace_glb = nullptr;
		Ciphertext selector_big = oblivious_selector_poly(ctx_big, eval_big, rs.oc_big, relin_big, ct_a, ct_t);
		auto a1 = steady_clock::now();
		Ciphertext U = rsw::ring_switch(selector_big, ksk, ctx_big, ctx_small);
		auto a2 = steady_clock::now();
		cout << "equality test (big ring): " << duration_cast<milliseconds>(a1 - a0).count() << " ms, ring switch: " << duration_cast<milliseconds>(a2 - a1).count() << " ms\n";
		last = chrono::steady_clock::now();
		oblivious_trace_glb = [&](const string& name, const Ciphertext& ct) {
			double ms = chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now() - last).count() / 1000.0;
			cout << "      [" << name << "] chain " << ctx_small.get_context_data(ct.parms_id())->chain_index() << ", budget "
			     << dec_small.invariant_noise_budget(ct) << " bits, +" << ms << " ms\n";
			last = chrono::steady_clock::now();
		};
		auto b0 = steady_clock::now();
		Ciphertext T = omc_node_threshold_data(ctx_small, eval_small, mc, relin_small, gal_small, U, 0);
		cout << "node: " << duration_cast<milliseconds>(steady_clock::now() - b0).count() << " ms\n";
		return 0;
	}

	// ---- random groups on the root: min budgets over many random splits
	if (stress > 0) {
		mt19937 srng(777);
		int bad = 0, min_budget = 100000;
		for (int it = 0; it < stress; it++) {
			vector<Ciphertext> sv(3);
			sv[0] = selection_vector[0];
			int cnt = mc.G;
			vector<int> as(cnt), ts(cnt);
			for (int g = 0; g < cnt; g++) { as[g] = srng() % A; ts[g] = 1 + srng() % (V - 1); }
			Ciphertext ct_a = omc_encrypt_group_big(mc, as, batch_small, enc_big, N_big), ct_t = omc_encrypt_group_big(mc, ts, batch_small, enc_big, N_big);
			// every node of the group checked: use a few of them (all nodes would take G times longer)
			vector<Ciphertext> T = omc_group_threshold_data(ctx_small, eval_small, mc, relin_small, gal_small, rs, ct_a, ct_t, min(cnt, 4));
			for (int g = 0; g < (int) T.size(); g++) {
				omc_apply_children(sv, T[g], 0, 0, mc, ctx_small, eval_small, relin_small);
				int e = 0;
				for (int ch = 1; ch <= 2; ch++) {
					dec_small.decrypt(sv[ch], pl);
					batch_small.decode(pl, dec);
					for (int row = 0; row < 2; row++)
						for (int tc = 0; tc < mc.rho_n; tc++)
							for (int j = 0; j < n; j++) {
								int in_left = x[j][as[g]] < ts[g];
								if ((int) dec[row * (N_small / 2) + (size_t) tc * n + j] != ((ch == 1) ? in_left : !in_left)) e++;
							}
				}
				int fb = dec_small.invariant_noise_budget(sv[1]);
				min_budget = min(min_budget, fb);
				bad += (e != 0);
				cout << "  group " << it << " node " << g << " (attr " << as[g] << ", theta " << ts[g] << "): left-child budget " << fb << (e ? "  WRONG" : "  ok") << endl;
			}
		}
		cout << "stress: " << bad << " wrong nodes, min left-child budget " << min_budget << endl;
		return bad ? 1 : 0;
	}

	// ---- tree walk
	const int num_internal = (1 << (depth - 1)) - 1;
	vector<int> split_attr(num_internal), split_val(num_internal);
	mt19937 rng(1234);
	long long eq_us = 0, rs_us = 0, node_us = 0, apply_us = 0;
	int groups_done = 0, nodes_done = 0;
	for (int d = 0; d < depth - 1; d++) {
		for (int first = 0; first < (1 << d); first += mc.G) {
			int cnt = min(mc.G, (1 << d) - first);
			vector<int> as(cnt), ts(cnt);
			for (int g = 0; g < cnt; g++) {
				as[g] = rng() % A; ts[g] = 1 + rng() % (V - 1);
				split_attr[(1 << d) - 1 + first + g] = as[g];
				split_val[(1 << d) - 1 + first + g] = ts[g];
			}
			Ciphertext ct_a = omc_encrypt_group_big(mc, as, batch_small, enc_big, N_big), ct_t = omc_encrypt_group_big(mc, ts, batch_small, enc_big, N_big);
			auto a0 = steady_clock::now();
			Ciphertext selector_big = oblivious_selector_poly(ctx_big, eval_big, rs.oc_big, relin_big, ct_a, ct_t);
			auto a1 = steady_clock::now();
			Ciphertext U = rsw::ring_switch(selector_big, ksk, ctx_big, ctx_small);
			auto a2 = steady_clock::now();
			if (groups_done == 0) {
				cout << "  first group: compact selector in the big ring chain " << ctx_big.get_context_data(selector_big.parms_id())->chain_index()
				     << "; after ring switching: chain " << ctx_small.get_context_data(U.parms_id())->chain_index() << ", budget "
				     << dec_small.invariant_noise_budget(U) << " bits\n";
			}
			vector<Ciphertext> T(cnt);
			for (int g = 0; g < cnt; g++) {
				T[g] = omc_node_threshold_data(ctx_small, eval_small, mc, relin_small, gal_small, U, g);
			}
			auto a3 = steady_clock::now();
			for (int g = 0; g < cnt; g++) omc_apply_children(selection_vector, T[g], d, first + g, mc, ctx_small, eval_small, relin_small);
			auto a4 = steady_clock::now();
			if (groups_done == 0) {
				cout << "  first node: T at chain " << ctx_small.get_context_data(T[0].parms_id())->chain_index() << ", budget "
				     << dec_small.invariant_noise_budget(T[0]) << " bits\n";
			}
			eq_us += duration_cast<microseconds>(a1 - a0).count();
			rs_us += duration_cast<microseconds>(a2 - a1).count();
			node_us += duration_cast<microseconds>(a3 - a2).count();
			apply_us += duration_cast<microseconds>(a4 - a3).count();
			groups_done++; nodes_done += cnt;
		}
	}
	cout << "groups: " << groups_done << " (" << nodes_done << " nodes); single-threaded totals: equality test (big ring) " << eq_us / 1000
	     << " ms, ring switch " << rs_us / 1000 << " ms, per-node selectors + P + fold (" << node_us / 1000 / max(1, nodes_done) << " ms per node) "
	     << node_us / 1000 << " ms, children " << apply_us / 1000 << " ms;  all: " << (eq_us + rs_us + node_us + apply_us) / 1000 << " ms\n";

	int errors = omc_verify_selection_vectors(selection_vector, split_attr, split_val, x, depth, dec_small, batch_small, mc);
	cout << "selection vectors vs plaintext training: " << (errors ? "WRONG slots: " + to_string(errors) : string("ok")) << endl;
	for (int d = 1; d < depth; d++) {
		int mn = 100000, chain = -1;
		for (int i = (1 << d) - 1; i < (1 << (d + 1)) - 1; i++) {
			mn = min(mn, (int) dec_small.invariant_noise_budget(selection_vector[i]));
			chain = (int) ctx_small.get_context_data(selection_vector[i].parms_id())->chain_index();
		}
		cout << "  level " << d << " selection vectors: chain " << chain << ", min budget " << mn << " bits\n";
	}
	cout << (errors ? "FAILED" : "ALL CHILDREN CORRECT") << endl;
	return errors ? 1 : 0;
}
