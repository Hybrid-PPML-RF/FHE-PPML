// Test of the ring switch  R_{32768} -> R_{16384}  (ring_switch.h) in the setting of the oblivious selection-vector update:
//   * the big context has the data primes of the small context at the bottom of its chain and a few extra primes on top;
//   * a few multiplications are computed in the big ring on an embedded plaintext (the extra primes are consumed),
//   * the ciphertext is switched to the small ring and decrypted there with the secret key of the small context,
//   * the noise budget is reported before and after.
//
// usage: ./test_rs [shared_n shared_bits special_small_bits extra_n extra_bits special_big_bits log_base N_small]

#include <chrono>
#include <iostream>
#include <random>
#include "seal/seal.h"
#include "ring_switch.h"

using namespace seal;
using namespace std;
using namespace std::chrono;

int main(int argc, char* argv[]) {
	auto arg = [&](int i, int def) { return argc > i ? stoi(argv[i]) : def; };
	const int shared_n = arg(1, 10), shared_bits = arg(2, 38), special_small_bits = arg(3, 38);
	const int extra_n = arg(4, 5), extra_bits = arg(5, 40), special_big_bits = arg(6, 50);
	const int log_base = arg(7, 8);
	const size_t N_small = arg(8, 16384), N_big = 2 * N_small;
	const uint64_t t = 65537;

	// primes: all of them are = 1 mod 2*N_big, so they are valid for both rings
	vector<int> bits;
	for (int i = 0; i < shared_n; i++) bits.push_back(shared_bits);
	for (int i = 0; i < extra_n; i++) bits.push_back(extra_bits);
	bits.push_back(special_big_bits);
	bits.push_back(special_small_bits);
	auto primes = CoeffModulus::Create(N_big, bits);
	vector<Modulus> shared(primes.begin(), primes.begin() + shared_n);
	vector<Modulus> big_chain(primes.begin(), primes.begin() + shared_n + extra_n);
	big_chain.push_back(primes[shared_n + extra_n]);                       // special prime of the big context
	vector<Modulus> small_chain = shared;
	small_chain.push_back(primes[shared_n + extra_n + 1]);                 // special prime of the small context

	int big_bits = 0, small_bits = 0;
	for (auto& m : big_chain) big_bits += m.bit_count();
	for (auto& m : small_chain) small_bits += m.bit_count();
	cout << "small context N=" << N_small << ": " << shared_n << " x " << shared_bits << " + special " << special_small_bits << " = " << small_bits
	     << " bits (128-bit bound " << CoeffModulus::MaxBitCount(N_small) << ")\n";
	cout << "big   context N=" << N_big << ": " << shared_n << " shared + " << extra_n << " x " << extra_bits << " + special " << special_big_bits << " = "
	     << big_bits << " bits (128-bit bound " << CoeffModulus::MaxBitCount(N_big) << ")\n";

	EncryptionParameters parms_small(scheme_type::bgv), parms_big(scheme_type::bgv);
	parms_small.set_poly_modulus_degree(N_small);
	parms_small.set_coeff_modulus(small_chain);
	parms_small.set_plain_modulus(t);
	parms_big.set_poly_modulus_degree(N_big);
	parms_big.set_coeff_modulus(big_chain);
	parms_big.set_plain_modulus(t);
	SEALContext ctx_small(parms_small, true, sec_level_type::none), ctx_big(parms_big, true, sec_level_type::none);

	// keys
	auto sk_small_c = rsw::sample_ternary(N_small, getenv("DET") ? 111 : 0);
	auto sk_big_c = rsw::sample_ternary(N_big, getenv("DET") ? 222 : 0);
	auto sk_target_c = rsw::embed_sk(sk_small_c);
	SecretKey sk_small = rsw::make_secret_key(sk_small_c, ctx_small);
	SecretKey sk_big = rsw::make_secret_key(sk_big_c, ctx_big);
	SecretKey sk_target = rsw::make_secret_key(sk_target_c, ctx_big);
	KeyGenerator kg_big(ctx_big, sk_big);
	PublicKey pk_big;
	kg_big.create_public_key(pk_big);
	RelinKeys relin_big;
	kg_big.create_relin_keys(relin_big);
	Encryptor enc_big(ctx_big, pk_big);
	Evaluator eval_big(ctx_big), eval_small(ctx_small);
	Decryptor dec_big(ctx_big, sk_big), dec_target(ctx_big, sk_target), dec_small(ctx_small, sk_small);
	BatchEncoder batch_small(ctx_small);

	// key switching key at the level of the shared primes
	parms_id_type level_id = ctx_big.first_context_data()->parms_id();
	for (int i = 0; i < extra_n; i++) level_id = ctx_big.get_context_data(level_id)->next_context_data()->parms_id();
	auto t0 = steady_clock::now();
	rsw::KSwitchKey ksk = rsw::gen_key_switch_key(sk_big_c, sk_target_c, ctx_big, level_id, t, log_base, getenv("DET") ? 333 : 0);
	cout << "KSK: " << ksk.pieces.size() << " primes x " << ksk.num_digits << " digits (base 2^" << log_base << "), generated in "
	     << duration_cast<milliseconds>(steady_clock::now() - t0).count() << " ms\n";

	// small slot vectors -> embedded plaintexts in the big ring
	mt19937_64 rng(5);
	vector<uint64_t> v(N_small), w(N_small);
	for (size_t i = 0; i < N_small; i++) { v[i] = rng() % t; w[i] = rng() % t; }
	Plaintext pv, pw;
	batch_small.encode(v, pv);
	batch_small.encode(w, pw);
	Ciphertext cv, cw;
	enc_big.encrypt(rsw::embed_plaintext(pv, N_big), cv);
	enc_big.encrypt(rsw::embed_plaintext(pw, N_big), cw);
	cout << "fresh budget (big ring): " << dec_big.invariant_noise_budget(cv) << " bits\n";

	// extra_n multiplications in the big ring: x <- x * w (all slots, mod t) after v;  expected v * w^extra_n
	Ciphertext x = cv;
	vector<uint64_t> expect = v;
	t0 = steady_clock::now();
	for (int i = 0; i < extra_n; i++) {
		Ciphertext wi = cw;
		eval_big.mod_switch_to_inplace(wi, x.parms_id());
		eval_big.multiply_inplace(x, wi);
		eval_big.relinearize_inplace(x, relin_big);
		eval_big.mod_switch_to_next_inplace(x);
		for (size_t j = 0; j < N_small; j++) expect[j] = expect[j] * w[j] % t;
	}
	cout << "big ring: " << extra_n << " multiplications: " << duration_cast<milliseconds>(steady_clock::now() - t0).count()
	     << " ms, budget " << dec_big.invariant_noise_budget(x) << " bits, chain index " << ctx_big.get_context_data(x.parms_id())->chain_index() << "\n";

	t0 = steady_clock::now();
	Ciphertext switched = rsw::apply_key_switch(x, ksk, ctx_big);
	auto t1 = steady_clock::now();
	Ciphertext small = rsw::extract_to_small(switched, ctx_big, ctx_small);
	auto t2 = steady_clock::now();
	cout << "key switching: " << duration_cast<milliseconds>(t1 - t0).count() << " ms, budget under sk_target "
	     << dec_target.invariant_noise_budget(switched) << " bits;  extraction: " << duration_cast<milliseconds>(t2 - t1).count() << " ms\n";
	cout << "small ring: chain index " << ctx_small.get_context_data(small.parms_id())->chain_index() << ", budget "
	     << dec_small.invariant_noise_budget(small) << " bits\n";

	Plaintext pr;
	dec_small.decrypt(small, pr);
	vector<uint64_t> got;
	batch_small.decode(pr, got);
	size_t bad = 0;
	for (size_t i = 0; i < N_small; i++) bad += (got[i] != expect[i]);
	cout << "decrypted in the small ring: " << (bad ? "WRONG, " + to_string(bad) + " slots" : string("all slots correct")) << "\n";

	// the switched ciphertext is a regular ciphertext of the small context: use it with the small evaluator (square, then decrypt
	// the size-3 result, no relinearization key needed for that)
	Ciphertext sq;
	eval_small.square(small, sq);
	Plaintext ps;
	dec_small.decrypt(sq, ps);
	batch_small.decode(ps, got);
	size_t bad2 = 0;
	for (size_t i = 0; i < N_small; i++) bad2 += (got[i] != expect[i] * expect[i] % t);
	cout << "square with the small evaluator: " << (bad2 ? "WRONG, " + to_string(bad2) + " slots" : string("all slots correct")) << "\n";
	return (bad || bad2) ? 1 : 0;
}
