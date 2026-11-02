#include "seal/seal.h"
#include "util.h"
#include "oblivious_multi.h"
#include "share_select.h"
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

	// For the oblivious selection-vector update (util.h: P in one ciphertext, oblivious_multi.h: P in several) the chain is
	//     [ 1 base prime ]  +  [ oblivious_levels primes ]  +  [ special prime ]
	// Every level of the chain is consumed by exactly one ciphertext-ciphertext (or ciphertext-plaintext) multiplication followed by a mod switch:
	//     eq_levels  equality test of ObliviousRotation: 5 for iris with the polynomial test (default), 16 squarings with Qelect's x^(p-1)
	//   +  2  selector x P, mask of block 0      (+ 1 more for the stretch of the compact one-hot in the multi-ciphertext layout)
	//         -- the root's selection vector is public, so the first update is S_left = T without a multiplication --
	//   + (depth-2)  one selection_vector x threshold_data for each further tree level
	//   +  2  deepest level: partitions x selection_vector, and the leaf labeling below, which first mod-switches the selection
	//         vector one level down and then multiplies (i.e. that multiplication is done on the last-but-one level)
	// With ring switching (default) the equality test does not count for the ring of the data ciphertexts, see below.
	// Prime size (N = 16384, p = 65537, test_oblivious_update_sel.cpp, depth-6 tree walk, single ring):
	//   polynomial test: any size from 40 to 50 bits works (the chain is short, noise cannot run away)
	//   Fermat test:     44 bits diverges, 46 bits is marginal (5 of 31 nodes lost all their budget), 48 and 50 bits work -> 50 bits
	// optional 7th argument: the selection-vector update.
	//   0 = original plaintext split (the split is opened; original modulus chain), for runtime comparison
	//   1 = private model, oblivious update in FHE: equality test on the encrypted split, ring switching (util.h, oblivious_multi.h)
	//   2 = private model, selection in MPC (default, share_select.h): BestSplit outputs the one-hot of the split in shares, the
	//       servers compute the shares of the left-child indicator from their shares of the data and encrypt them; the FHE side is
	//       the plaintext-split path with a fresh ciphertext as threshold data (original modulus chain)
	const int update_mode = argc > 7 ? std::stoi(argv[7]) : 2;
	const bool oblivious_update = update_mode == 1;
	const bool share_update = update_mode == 2;
	// optional 13th argument (mode 2): 1 = every server encrypts its share already tiled, one ciphertext per node (no extraction);
	//                                   0 (default) = packed, floor((N/2)/n) nodes per batching row
	// optional 14th argument (mode 2): number of servers M (default 10, as in the benchmarks); every server encrypts its share
	const bool share_tiled = share_update && argc > 13 && std::stoi(argv[13]) != 0;
	const int num_servers = argc > 14 ? std::stoi(argv[14]) : 10;
	// optional 15th argument (modes 0 and 2): prime size of the original modulus chain (default 34 bits, as in the original code).
	// With real (non-zero) selection vectors 34 bits leave no budget for the leaf labeling at depth 6; 40 bits do (still < 438 bits).
	const int orig_prime_bits = argc > 15 ? std::stoi(argv[15]) : 34;
	// optional 11th argument: 1 = force the multi-ciphertext layout (oblivious_multi.h) even if P fits one ciphertext (testing)
	// Single-ciphertext layout (util.h) when the partitions of all attributes and thresholds fit one batching row (iris), otherwise
	// P is a vector of ciphertexts and the selection first picks the ciphertext and then the block (oblivious_multi.h: wine, cancer, digits).
	const bool use_multi = oblivious_update && ((argc > 11 && std::stoi(argv[11]) != 0) ||
		(size_t) attr_size_glb * value_size_glb * data_size_glb > poly_modulus_degree_glb / 2);
	// optional 8th argument: switch the preprocessed partitions down, once per tree level, to the level of that level's selection
	// vectors before they are used (default: on, for the original and the oblivious path)
	const bool level_switch = argc > 8 ? (std::stoi(argv[8]) != 0) : true;   // default on, for the original path as well
	// optional 9th argument: 0 = Qelect's x^(p-1) equality test, 1 (default) = low-depth polynomial equality test (single-ciphertext layout only)
	const bool equality_poly = use_multi || !(argc > 9 && std::stoi(argv[9]) == 0);
	// optional 12th argument: 0 = keep all ciphertexts of the simulated data (memory: gigabytes for digits).  Default (1): "simulated reuse".
	// The node processing of this benchmark works on vectors of ciphertexts of which only the first one is ever looked at again: the
	// per-node copies of the partitions are identical, and the later stages only read the first output of every node.  So only 2
	// distinct input ciphertexts are preprocessed, the work for the logical number of ciphertexts is still done (the stored one is used over
	// and over), and all outputs but the first one of each node are dropped as soon as they are computed.  The amount of computation of the
	// training phase is unchanged; only preprocessing (not part of the reported training runtime) is done for 2 of the input ciphertexts.
	const bool sim_reuse = !(argc > 12 && std::stoi(argv[12]) == 0);
	// optional 10th argument: 1 (default) = ring switching: the split ciphertexts and the equality test live in a second context with
	// ring dimension 2N (secure for the extra levels of the test), the selector is then switched to the ring of the data (N), whose
	// modulus stays within the 128-bit security bound.  0 = everything in one ring (the chain is then longer than the bound).
	const bool use_rs = oblivious_update && equality_poly && (use_multi || !(argc > 10 && std::stoi(argv[10]) == 0));
	// levels of the equality test: the polynomial test is a product tree over the (V-1) + A factors; for the multi-ciphertext layout it
	// runs on the compact one-hot over A*(V-1) blocks, whose digits are the same attribute / threshold digits
	const int eq_levels = oblivious_equality_levels(equality_poly, attr_size_glb, value_size_glb, p);
	const int eq_levels_small = use_rs ? 0 : eq_levels;     // levels of the equality test that are taken from the chain of the data ring
	// = [selector x P, mask] (single-ciphertext layout) or [stretch, selector x P, mask] (multi-ciphertext layout: one more level) for the first
	// update (the root is public: S_left = T, no multiplication), one S x T per further tree level, 2 for the node processing at the deepest level
	const int oblivious_levels = oblivious_update ? (eq_levels_small + (use_multi ? 3 : 2) + max(depth_glb - 2, 0) + 2) : 0;

	vector<Modulus> coeff_modulus, coeff_modulus_big;
	// prime sizes of the data ring: 40 bits plus a 38-bit special prime = 438 bits (the 128-bit bound of N = 16384) for up to 10 primes (iris: 9,
	// wine / cancer / digits: 10 at depth 6); deeper trees shrink the primes to stay within the bound (not below 34 bits)
	const int small_prime_bits = max(34, min(40, ((int) CoeffModulus::MaxBitCount(poly_modulus_degree_glb) - 38) / (oblivious_levels + 1)));
	const int small_special_bits = 38, big_extra_bits = 40, big_special_bits = 50;
	if (use_rs) {
		// primes: [oblivious_levels + 1 shared] [eq_levels extra, only in the big ring] [special big] [special small]; all are
		// = 1 mod 2 * N_big and therefore valid in both rings.  The data chain is the shared primes + its own special prime,
		// the big chain is the shared primes + the extra ones + its own special prime.
		vector<int> bits(oblivious_levels + 1, small_prime_bits);
		for (int i = 0; i < eq_levels; i++) bits.push_back(big_extra_bits);
		bits.push_back(big_special_bits);
		bits.push_back(small_special_bits);
		auto primes = CoeffModulus::Create(2 * poly_modulus_degree_glb, bits);
		coeff_modulus.assign(primes.begin(), primes.begin() + oblivious_levels + 1);
		coeff_modulus_big.assign(primes.begin(), primes.begin() + oblivious_levels + 1 + eq_levels);
		coeff_modulus_big.push_back(primes[oblivious_levels + 1 + eq_levels]);
		coeff_modulus.push_back(primes[oblivious_levels + 2 + eq_levels]);
	} else {
		vector<int> modulus_bits;
		if (oblivious_update) {
			const int prime_bits = equality_poly ? 40 : 50, special_bits = equality_poly ? 50 : 60;
			for (int i = 0; i <= oblivious_levels; i++) modulus_bits.push_back(prime_bits);   // base prime + one prime per level
			modulus_bits.push_back(special_bits);
		} else {
			// original chain (plaintext partition criterion; also the chain of the selection from shares, which adds no level)
			modulus_bits.assign(depth_glb < 6 ? 8 : 9, orig_prime_bits);
		}
		coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, modulus_bits);
	}
	{
		int total = 0;
		for (auto& m : coeff_modulus) total += m.bit_count();
		cout << "Modulus chain of the data ring (N=" << poly_modulus_degree_glb << "): " << coeff_modulus.size() - 1 << " primes + special = " << total
			 << " bits (128-bit security bound: " << CoeffModulus::MaxBitCount(poly_modulus_degree_glb) << ")\n";
		if (use_rs) {
			int totalb = 0;
			for (auto& m : coeff_modulus_big) totalb += m.bit_count();
			cout << "Modulus chain of the ring of the equality test (N=" << 2 * poly_modulus_degree_glb << "): " << coeff_modulus_big.size() - 1
				 << " primes + special = " << totalb << " bits (bound: " << CoeffModulus::MaxBitCount(2 * poly_modulus_degree_glb) << ")\n";
		}
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

	// with ring switching the secret key of the data ring is needed in coefficient form (the key-switching key targets embed(sk_small))
	vector<int> sk_small_coeffs;
	SecretKey sk_small_custom;
	if (use_rs) {
		sk_small_coeffs = rsw::sample_ternary(poly_modulus_degree_glb, 0);   // 0 = OS entropy
		sk_small_custom = rsw::make_secret_key(sk_small_coeffs, seal_context);
	}
	KeyGenerator keygen = use_rs ? KeyGenerator(seal_context, sk_small_custom) : KeyGenerator(seal_context);
	SecretKey bgv_secret_key = keygen.secret_key();

	PublicKey bgv_public_key;
	keygen.create_public_key(bgv_public_key);

	RelinKeys relin_keys, relin_keys_raise;
	keygen.create_relin_keys(relin_keys);

	Encryptor encryptor(seal_context, bgv_public_key);
	Evaluator evaluator(seal_context);
	BatchEncoder batch_encoder(seal_context);
	Decryptor decryptor(seal_context, bgv_secret_key);

	// second ring (ring switching): context, independent secret key, relinearization key, key-switching key sk_big -> embed(sk_small)
	unique_ptr<SEALContext> seal_context_big;
	unique_ptr<Evaluator> evaluator_big;
	unique_ptr<Encryptor> encryptor_big;
	RelinKeys relin_keys_big;
	rsw::KSwitchKey ksk_big_to_small;
	if (use_rs) {
		EncryptionParameters params_big(scheme_type::bgv);
		params_big.set_poly_modulus_degree(2 * poly_modulus_degree_glb);
		params_big.set_coeff_modulus(coeff_modulus_big);
		params_big.set_plain_modulus(p);
		seal_context_big.reset(new SEALContext(params_big, true, sec_level_type::none));
		auto sk_big_coeffs = rsw::sample_ternary(2 * poly_modulus_degree_glb, 0);
		SecretKey sk_big = rsw::make_secret_key(sk_big_coeffs, *seal_context_big);
		KeyGenerator keygen_big(*seal_context_big, sk_big);
		PublicKey pk_big;
		keygen_big.create_public_key(pk_big);
		keygen_big.create_relin_keys(relin_keys_big);
		encryptor_big.reset(new Encryptor(*seal_context_big, pk_big));
		evaluator_big.reset(new Evaluator(*seal_context_big));
		// the key-switching key is generated for the level of the shared primes (= the top level of the data ring)
		parms_id_type shared_level = seal_context_big->first_context_data()->parms_id();
		for (int i = 0; i < eq_levels; i++) shared_level = seal_context_big->get_context_data(shared_level)->next_context_data()->parms_id();
		ksk_big_to_small = rsw::gen_key_switch_key(sk_big_coeffs, rsw::embed_sk(sk_small_coeffs), *seal_context_big, shared_level, p, 8, 0);
	}

	ObliviousMultiCtx oblivious_multi;
	if (use_multi) omc_init(oblivious_multi, data_size_glb, attr_size_glb, value_size_glb, seal_context, evaluator, batch_encoder);
	ShareSelCtx share_ctx;
	if (share_update) ssc_init(share_ctx, data_size_glb, num_servers, share_tiled, p, batch_encoder);

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


	if (use_multi) {
		// aligning compact regions, stretch (baby / giant steps), fill, fold, chunk placement, tiling (all in oblivious_multi.h)
		for (int s : omc_rotation_steps(oblivious_multi)) steps_rot.push_back(s);
	} else if (oblivious_update) {
		// fold/tile over the A*V blocks of P, copying P into the regions of the ciphertext, aligning regions (all in util.h)
		for (int s : oblivious_update_rotation_steps(data_size_glb, attr_size_glb, value_size_glb, true)) {
			steps_rot.push_back(s);
		}
	} else if (share_update) {
		// moving a node's region to the front, both rows, tiling (share_select.h)
		for (int s : ssc_rotation_steps(share_ctx)) steps_rot.push_back(s);
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
	if (sim_reuse && inputs_X.size() > 2) {
		cout << "Simulated reuse: " << inputs_X.size() << " input ciphertexts, only 2 are preprocessed and stored.\n";
		inputs_X.resize(2);   // (the legacy plaintext update reads ciphertext 1 of the partitions, so keep two)
	}

	const bool verify = argc > 5 && std::stoi(argv[5]);   // optional 5th argument: decrypt and check the selection vectors
	vector<vector<int>> plain_x;
	if (oblivious_update && verify && !use_multi) {
		plain_x = obl_decode_dataset(inputs_X[0], decryptor, batch_encoder);
	}
	if (share_update) {
		// the data whose shares the servers hold: decoded from the clients' one-hot ciphertext when it holds the whole dataset (iris),
		// otherwise random data as in the multi-ciphertext layout (the preprocessing of the repo is a runtime simulation for these sizes)
		if ((size_t) attr_size_glb * value_size_glb * data_size_glb <= poly_modulus_degree_glb / 2) {
			plain_x = obl_decode_dataset(inputs_X[0], decryptor, batch_encoder);
		} else {
			plain_x.assign(data_size_glb, vector<int>(attr_size_glb));
			mt19937 data_rng(7);
			for (auto& row : plain_x) for (auto& v : row) v = data_rng() % value_size_glb;
		}
	}

	// The oblivious update multiplies the selector (which sits `eq_levels_small` levels below the top after the equality test)
	// with P, which is built from the partitions of X. So the clients' ciphertexts only need that many levels: switch them down once
	// (this is what a client could do before uploading), which makes preprocessing and all later operations on them cheaper.
	if (oblivious_update) {
		int data_chain = (int) seal_context.first_context_data()->chain_index() - eq_levels_small;
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
	ObliviousRingSwitch oblivious_rs;    // ring switching only
	// The splits that the MPC would output for each internal node, as *fresh* ciphertexts; the server never sees them in the clear.
	// The nodes of a level are handled in groups of G = oblivious_ctx.group_size nodes per ciphertext (util.h): one ciphertext holds
	// the attribute index of the G nodes of a group (replicated over the region of each node, as the parties can do with their
	// shares), another one the thresholds. Here the splits are random (the plaintext values are only kept for verification).
	const int num_internal = (1 << (depth_glb - 1)) - 1;
	vector<vector<Ciphertext>> level_attr_ct(depth_glb), level_val_ct(depth_glb);   // [level][group]
	vector<int> split_attr_pt(num_internal), split_val_pt(num_internal);

	if (use_multi) {
		// The preprocessing of this repo is only a runtime simulation for these sizes (its one-hot encoding does not fit the layout), so
		// the partitions P of the multi-ciphertext layout are encrypted directly from random plaintext data (stand-in for the output of a
		// correct preprocessing); the splits below are verified against plaintext training on this data.
		time_start = chrono::high_resolution_clock::now();
		plain_x.assign(data_size_glb, vector<int>(attr_size_glb));
		mt19937 data_rng(7);
		for (auto& row : plain_x) for (auto& v : row) v = data_rng() % value_size_glb;
		omc_encrypt_partitions(oblivious_multi, plain_x, seal_context, evaluator, batch_encoder, encryptor);
		oblivious_ring_switch_init(oblivious_rs, *seal_context_big, *evaluator_big, relin_keys_big, ksk_big_to_small, oblivious_multi.eq_small);
		time_end = chrono::high_resolution_clock::now();
		cout << "Packing P time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us. "
			 << "chunk n'=" << oblivious_multi.nprime << " (" << oblivious_multi.J << " chunks), " << oblivious_multi.J * oblivious_multi.m_b
			 << " ciphertexts of P, " << oblivious_multi.G << " nodes per compact ciphertext.\n";

		vector<uint64_t> root_vec(poly_modulus_degree_glb, 1);
		Plaintext root_pl;
		batch_encoder.encode(root_vec, root_pl);
		encryptor.encrypt(root_pl, selection_vector[0]);
		// the first update (S_left = T, public root) is at chain index top - 3 (stretch, P, mask); the root is used up to there
		int root_chain = (int) seal_context.first_context_data()->chain_index() - 3;
		while ((int) seal_context.get_context_data(selection_vector[0].parms_id())->chain_index() > root_chain)
			evaluator.mod_switch_to_next_inplace(selection_vector[0]);

		mt19937 split_rng(2024);
		for (int d = 0; d < depth_glb - 1; d++) {
			int groups = ((1 << d) + oblivious_multi.G - 1) / oblivious_multi.G;
			level_attr_ct[d].resize(groups);
			level_val_ct[d].resize(groups);
			for (int gi = 0; gi < groups; gi++) {
				vector<int> attrs, vals;
				for (int g = 0; g < oblivious_multi.G && gi * oblivious_multi.G + g < (1 << d); g++) {
					int node = (1 << d) - 1 + gi * oblivious_multi.G + g;
					split_attr_pt[node] = split_rng() % attr_size_glb;
					split_val_pt[node] = 1 + split_rng() % (value_size_glb - 1);
					attrs.push_back(split_attr_pt[node]);
					vals.push_back(split_val_pt[node]);
				}
				level_attr_ct[d][gi] = omc_encrypt_group_big(oblivious_multi, attrs, batch_encoder, *encryptor_big, 2 * poly_modulus_degree_glb);
				level_val_ct[d][gi] = omc_encrypt_group_big(oblivious_multi, vals, batch_encoder, *encryptor_big, 2 * poly_modulus_degree_glb);
			}
		}
	} else if (oblivious_update) {
		time_start = chrono::high_resolution_clock::now();
		oblivious_ctx.equality_poly = equality_poly;
		build_oblivious_sel_ctx(oblivious_ctx, preprocessed_partitions, seal_context, evaluator, batch_encoder, gal_keys_rot);
		if (use_rs) oblivious_ring_switch_init(oblivious_rs, *seal_context_big, *evaluator_big, relin_keys_big, ksk_big_to_small, oblivious_ctx);
		time_end = chrono::high_resolution_clock::now();
		cout << "Packing P time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us. "
			 << oblivious_ctx.group_size << " nodes per ciphertext.\n";

		// root: every datapoint is selected (S_0 = 1_N); only the levels below it are computed obliviously
		vector<uint64_t> root_vec(poly_modulus_degree_glb, 1);
		Plaintext root_pl;
		batch_encoder.encode(root_vec, root_pl);
		encryptor.encrypt(root_pl, selection_vector[0]);
		// The first update matches the root to the threshold data, which sits at chain index top - eq_levels_small - 2 (equality test, selector x P,
		// fold + mask). The root is only ever used at that level or below, so switch it there right away: level 0 then runs on as many
		// limbs as the original chain has, instead of on the (longer) level of the clients' inputs.
		int root_chain = (int) seal_context.first_context_data()->chain_index() - eq_levels_small - 2;
		while ((int) seal_context.get_context_data(selection_vector[0].parms_id())->chain_index() > root_chain)
			evaluator.mod_switch_to_next_inplace(selection_vector[0]);

		mt19937 split_rng(2024);
		for (int d = 0; d < depth_glb - 1; d++) {
			int groups = ((1 << d) + oblivious_ctx.group_size - 1) / oblivious_ctx.group_size;
			level_attr_ct[d].resize(groups);
			level_val_ct[d].resize(groups);
			for (int gi = 0; gi < groups; gi++) {
				vector<int> attrs, vals;
				for (int g = 0; g < oblivious_ctx.group_size && gi * oblivious_ctx.group_size + g < (1 << d); g++) {
					// theta in [1, V-1]: split is "x < theta" / "x >= theta" (theta = 0 would be an empty left child)
					int node = (1 << d) - 1 + gi * oblivious_ctx.group_size + g;
					split_attr_pt[node] = split_rng() % attr_size_glb;
					split_val_pt[node] = 1 + split_rng() % (value_size_glb - 1);
					attrs.push_back(split_attr_pt[node]);
					vals.push_back(split_val_pt[node]);
				}
				if (use_rs) {
					// the parties encrypt their (replicated, embedded) shares under the key of the big ring
					level_attr_ct[d][gi] = oblivious_encrypt_group_big(oblivious_ctx, attrs, batch_encoder, *encryptor_big, 2 * poly_modulus_degree_glb, true);
					level_val_ct[d][gi] = oblivious_encrypt_group_big(oblivious_ctx, vals, batch_encoder, *encryptor_big, 2 * poly_modulus_degree_glb, true);
				} else {
					Plaintext pa, pv;
					batch_encoder.encode(oblivious_group_vector(oblivious_ctx, attrs, true), pa);
					batch_encoder.encode(oblivious_group_vector(oblivious_ctx, vals, true), pv);
					encryptor.encrypt(pa, level_attr_ct[d][gi]);
					encryptor.encrypt(pv, level_val_ct[d][gi]);
				}
			}
		}
	} else if (share_update) {
		// root: every datapoint is selected (public); the splits stand in for the outputs of BestSplit, the servers encrypt their shares
		// of the selection level by level in the training loop (after BestSplit of that level)
		encryptor.encrypt(share_ctx.ones_pl, selection_vector[0]);
		mt19937 split_rng(2024);
		for (int node = 0; node < num_internal; node++) {
			split_attr_pt[node] = split_rng() % attr_size_glb;
			split_val_pt[node] = 1 + split_rng() % (value_size_glb - 1);
		}
		cout << "Selection from shares: " << share_ctx.M << " servers, " << (share_ctx.tiled ? "tiled, 1 node" : "packed, " + to_string(share_ctx.G) + " nodes")
			 << " per share ciphertext\n";
	} else {
		// just fill in random selection vectors...
		for (int i = 0; i < (int) selection_vector.size(); i++) {
			encryptor.encrypt(pl_test, selection_vector[i]);
		}
	}
	long long parallel_servers_us = 0;   // share encryptions of the other M - 1 servers (they run in parallel with the first one)
	mt19937_64 share_rng(99);

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
		chrono::high_resolution_clock::time_point lvl_start = chrono::high_resolution_clock::now(), lvl_mid;

		// oblivious update: the equality test + extraction of the threshold data for all nodes of this level, one ciphertext per
		// group of nodes (independent groups run in parallel)
		vector<Ciphertext> level_threshold_data;
		if (oblivious_update && d != depth_glb - 1) {
			int groups = (int) level_attr_ct[d].size();
			level_threshold_data.resize(groups);
			auto compute_group = [&](int gi) {
				if (use_multi) {
					// compact one-hot over the blocks for the whole group, in the big ring, switched to the data ring
					Ciphertext sel_big = oblivious_selector_poly(*seal_context_big, *evaluator_big, oblivious_rs.oc_big, relin_keys_big,
																 level_attr_ct[d][gi], level_val_ct[d][gi]);
					level_threshold_data[gi] = rsw::ring_switch(sel_big, ksk_big_to_small, *seal_context_big, seal_context);
				} else if (use_rs) {
					level_threshold_data[gi] = oblivious_group_threshold_data_rs(seal_context, evaluator, oblivious_ctx, relin_keys, gal_keys_rot,
																				 oblivious_rs, level_attr_ct[d][gi], level_val_ct[d][gi]);
				} else {
					level_threshold_data[gi] = oblivious_group_threshold_data(seal_context, evaluator, oblivious_ctx, relin_keys, gal_keys_rot,
																			  level_attr_ct[d][gi], level_val_ct[d][gi], true);
				}
			};
			if (groups > 1) {
				NTL::SetNumThreads(min(groups, num_cores));
				NTL_EXEC_RANGE(groups, first, last);
				for (int gi = first; gi < last; gi++) compute_group(gi);
				NTL_EXEC_RANGE_END;
			} else {
				compute_group(0);
			}
		}

		if (share_update && d != depth_glb - 1) {
			// the selection of a node is used at the level of its parent's selection vector (the root's children: one level below the
			// top); a packed share ciphertext is encrypted one level higher, for the mask of the extraction
			parms_id_type use_level = d == 0 ? seal_context.first_context_data()->next_context_data()->parms_id()
											 : selection_vector[(1 << d) - 1].parms_id();
			parms_id_type enc_level = share_ctx.tiled ? use_level : seal_context.get_context_data(use_level)->prev_context_data()->parms_id();
			int groups = ((1 << d) + share_ctx.G - 1) / share_ctx.G;
			level_threshold_data.resize(groups);
			double enc_before = share_ctx.enc_us, sum_before = share_ctx.sum_us;
			long long cts_before = share_ctx.cts_per_server, bytes_before = share_ctx.bytes_per_server;
			for (int gi = 0; gi < groups; gi++) {
				vector<vector<int>> sels;
				for (int g = 0; g < share_ctx.G && gi * share_ctx.G + g < (1 << d); g++) {
					int node = (1 << d) - 1 + gi * share_ctx.G + g;
					sels.push_back(ssc_plain_selection(plain_x, split_attr_pt[node], split_val_pt[node]));
				}
				level_threshold_data[gi] = ssc_encrypt_group(share_ctx, sels, enc_level, share_rng, batch_encoder, encryptor, evaluator);
			}
			double enc_level_us = share_ctx.enc_us - enc_before;
			parallel_servers_us += (long long) (enc_level_us * (share_ctx.M - 1) / share_ctx.M);
			cout << "		level " << d << ": " << share_ctx.cts_per_server - cts_before << " share ciphertext(s) per server, "
				 << (share_ctx.bytes_per_server - bytes_before) / 1024 << " KiB, chain index " << seal_context.get_context_data(enc_level)->chain_index()
				 << "; encryption " << (long long) (enc_level_us / share_ctx.M) / 1000.0 << " ms per server, aggregation of the "
				 << share_ctx.M << " shares " << (long long) (share_ctx.sum_us - sum_before) / 1000.0 << " ms\n";
		}

		lvl_mid = chrono::high_resolution_clock::now();

		// Every operation on the partitions below happens at the level of the selection vector anyway (the higher of the two
		// ciphertexts is switched down), but the rotations of simulate_random_select_sqrt_attributes would run at the much higher
		// level of the stored partitions, and each node would switch its own copies. Switch the stored partitions once per level instead,
		// IN PLACE: the level of the selection vectors never increases from one level of the tree to the next, so nothing needs the higher
		// level again (the leaf labeling switches down to the selection vector's level as well).  A copy per level would double the memory
		// of the partitions, which is gigabytes for digits.
		if (level_switch) {
			parms_id_type target = selection_vector[(1 << d) - 1].parms_id();
			int target_chain = (int) seal_context.get_context_data(target)->chain_index();
			vector<Ciphertext*> stored;
			for (auto& v : preprocessed_partitions) for (auto& ct : v) stored.push_back(&ct);
			for (auto& v : preprocessed_partitioned_labels) for (auto& w : v) for (auto& ct : w) stored.push_back(&ct);
			NTL::SetNumThreads(num_cores);
			NTL_EXEC_RANGE((long) stored.size(), first, last);
			for (long i = first; i < last; i++)
				if ((int) seal_context.get_context_data(stored[i]->parms_id())->chain_index() > target_chain)
					evaluator.mod_switch_to_inplace(*stored[i], target);
			NTL_EXEC_RANGE_END;
		}
		vector<vector<Ciphertext>>& part_for_level = preprocessed_partitions;
		vector<vector<vector<Ciphertext>>>& part_labels_for_level = preprocessed_partitioned_labels;

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
					int logical_cts = 0;
					vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
					if (nd == 0) sss = chrono::high_resolution_clock::now();
					simulate_random_select_sqrt_attributes(part_for_level, part_labels_for_level,
															random_preprocessed_partitions, random_reprocessed_partitioned_labels,
															seal_context, evaluator, gal_keys_rot, !multi_thread, dataset == 4, &logical_cts, sim_reuse);
					if (nd == 0) {
						eee = chrono::high_resolution_clock::now();
						www += chrono::duration_cast<chrono::microseconds>(eee - sss).count();
					}
					perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
												partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
												relin_keys, gal_keys_rot, !multi_thread, sim_reuse ? logical_cts : 0, sim_reuse);

					if (d != depth_glb-1) {
						if (use_multi) {
							Ciphertext threshold_data = omc_node_threshold_data(seal_context, evaluator, oblivious_multi, relin_keys, gal_keys_rot,
																			level_threshold_data[nd / oblivious_multi.G], nd % oblivious_multi.G);
							omc_apply_children(selection_vector, threshold_data, d, nd, oblivious_multi, seal_context, evaluator, relin_keys);
						} else if (share_update) {
							Ciphertext threshold_data = ssc_node_threshold_data(seal_context, evaluator, share_ctx, gal_keys_rot,
																			   level_threshold_data[nd / share_ctx.G], nd % share_ctx.G);
							ssc_apply_children(selection_vector, threshold_data, d, nd, share_ctx, evaluator, relin_keys);
						} else if (oblivious_update) {
							oblivious_apply_threshold_data(selection_vector, level_threshold_data[nd / oblivious_ctx.group_size], nd % oblivious_ctx.group_size,
																	  d, nd, oblivious_ctx, seal_context, evaluator, relin_keys, gal_keys_rot);
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
				int logical_cts = 0;
				vector<vector<vector<Ciphertext>>> random_reprocessed_partitioned_labels;
				sss = chrono::high_resolution_clock::now();
				simulate_random_select_sqrt_attributes(part_for_level, part_labels_for_level,
													   random_preprocessed_partitions, random_reprocessed_partitioned_labels,
													   seal_context, evaluator, gal_keys_rot, !multi_thread, dataset == 4, &logical_cts, sim_reuse);
				eee = chrono::high_resolution_clock::now();
				www += chrono::duration_cast<chrono::microseconds>(eee - sss).count();

				perform_partition_for_node(random_preprocessed_partitions, random_reprocessed_partitioned_labels, partitions_for_node[nd],
										partition_labels_for_node[nd], seal_context, selection_vector[sel_ind], evaluator,
										relin_keys, gal_keys_rot, !multi_thread, sim_reuse ? logical_cts : 0, sim_reuse);

				if (d != depth_glb-1) {
					if (use_multi) {
						Ciphertext threshold_data = omc_node_threshold_data(seal_context, evaluator, oblivious_multi, relin_keys, gal_keys_rot,
																		level_threshold_data[nd / oblivious_multi.G], nd % oblivious_multi.G);
						omc_apply_children(selection_vector, threshold_data, d, nd, oblivious_multi, seal_context, evaluator, relin_keys);
					} else if (share_update) {
						Ciphertext threshold_data = ssc_node_threshold_data(seal_context, evaluator, share_ctx, gal_keys_rot,
																		   level_threshold_data[nd / share_ctx.G], nd % share_ctx.G);
						ssc_apply_children(selection_vector, threshold_data, d, nd, share_ctx, evaluator, relin_keys);
					} else if (oblivious_update) {
						oblivious_apply_threshold_data(selection_vector, level_threshold_data[nd / oblivious_ctx.group_size], nd % oblivious_ctx.group_size,
																  d, nd, oblivious_ctx, seal_context, evaluator, relin_keys, gal_keys_rot);
					} else {
						update_selection_vector(selection_vector, preprocessed_partitions, threshold_attr_ind, threshold_val_ind, d, nd,
																	seal_context, batch_encoder, evaluator, relin_keys, gal_keys_rot);
					}
				}
			}
		}

		chrono::high_resolution_clock::time_point lvl_end = chrono::high_resolution_clock::now();
		cout << "		level " << d << ": oblivious group computation " << chrono::duration_cast<chrono::milliseconds>(lvl_mid - lvl_start).count()
			 << " ms, nodes (partitions + selection update + attribute re-selection) " << chrono::duration_cast<chrono::milliseconds>(lvl_end - lvl_mid).count() << " ms\n";
	}

	if (oblivious_update && verify) {
		int wrong = use_multi ? omc_verify_selection_vectors(selection_vector, split_attr_pt, split_val_pt, plain_x, depth_glb,
															 decryptor, batch_encoder, oblivious_multi)
							  : verify_oblivious_selection_vectors(selection_vector, split_attr_pt, split_val_pt, plain_x, depth_glb,
																   decryptor, batch_encoder, seal_context);
		cout << "Verification of all selection vectors against plaintext training: " << (wrong ? "FAILED, wrong slots: " + to_string(wrong) : string("OK")) << endl;
	}
	if (share_update) {
		cout << "Share ciphertexts per server: " << share_ctx.cts_per_server << ", " << share_ctx.bytes_per_server / 1024 << " KiB (uncompressed); encryption "
			 << share_ctx.enc_us / share_ctx.M / 1000.0 << " ms per server, aggregation " << share_ctx.sum_us / 1000.0 << " ms\n";
		if (verify) {
			int min_budget = 0;
			int wrong = ssc_verify_selection_vectors(selection_vector, split_attr_pt, split_val_pt, plain_x, depth_glb,
													 decryptor, batch_encoder, share_ctx, &min_budget);
			cout << "Verification of all selection vectors against plaintext training: " << (wrong ? "FAILED, wrong slots: " + to_string(wrong) : string("OK"))
				 << " (lowest noise budget " << min_budget << " bits)" << endl;
		}
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
	long long total_us = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
	if (share_update) {
		// the M servers encrypt their shares in parallel: count the encryption of one server
		cout << "	(one machine, the share encryptions of all " << share_ctx.M << " servers in sequence: " << total_us << " us)\n";
		total_us -= parallel_servers_us;
	}
	cout << "Training + labeling + packing total runtime: " << total_us << " us.\n";


























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
