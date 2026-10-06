// Ring switching for BGV ciphertexts:  R_{2N} (N_big = 32768)  ->  R_{N} (N_small = 16384).
//
// Ported from https://github.com/wyunhao/mk-fhe-zkp (util/ring_switch.{h,cpp}, prototype_ring_switch.cpp) and adapted:
//   * header-only,
//   * the result is a regular SEAL Ciphertext of the small context (NTT form), so it can be used directly with the Evaluator
//     of the small context,
//   * no trace / Galois key: see below.
//
// Setting.  The big ring has an independent secret key sk_big (secure at N = 32768 with a modulus of up to 881 bits).
// The small ring has the secret key sk_small of the data ciphertexts (N = 16384, modulus <= 438 bits).  Let
//     sk_target := embed(sk_small) in R_big,   embed: Y -> X^2   (sk_target[2i] = sk_small[i], sk_target[2i+1] = 0).
// A ciphertext in R_big is switched in two steps:
//   1. key switching  sk_big -> sk_target.  SEAL has no API for switching to an arbitrary key, so a BV-style key-switching key
//      with an RNS + gadget decomposition (base 2^log_base) is used.  It is built for ONE modulus level (the level at which the
//      ring switch happens), so its modulus is only the product of those primes, and as an RLWE sample under sk_target (a
//      polynomial in X^2) it is exactly as hard as an RLWE sample in dimension N_small with that modulus.
//   2. extraction of the even coefficients.  Since sk_target is a polynomial in X^2, in  c0 + c1 * sk_target  the odd
//      coefficients of c1 only reach odd coefficients of the result.  So (c0_even, c1_even) in R_small decrypts, under sk_small,
//      to the even coefficients of the original decryption.  If the plaintext is a polynomial in X^2 (the "embedding" of a small
//      plaintext, see embed_plaintext) this is the plaintext itself, and the noise is not even doubled (the original code
//      applies the trace X -> -X, which doubles the plaintext and needs a Galois key under sk_target at the large modulus --
//      that would be an N_small-dimensional RLWE sample with the large modulus, i.e. insecure -- and it is not needed here).
//
// Why embedding is free for the equality test: Y -> X^2 is a ring homomorphism R_small -> R_big, so additions, multiplications and
// constants computed on embedded plaintexts in R_big are exactly the same computation as in R_small (they never leave the image).
// Only rotations (Galois automorphisms) would not be compatible, and the equality test does not use any.
//
// The primes of the small chain have to be a prefix of the data primes of the big chain, i.e. a big ciphertext that has been
// mod-switched down to the small primes has exactly the RNS bases of the top level of the small context.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <stdexcept>
#include <vector>

#include "seal/seal.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"

namespace rsw {

using namespace seal;
using namespace seal::util;

// Randomness for secret keys and key-switching keys.  seed == 0 (what main_integrity.cpp uses): SEAL's default generator, a Blake2xb
// stream seeded from the operating system's entropy, i.e. the same source SEAL uses for its own keys and encryptions.
// seed != 0: deterministic std::mt19937_64, ONLY for reproducible tests (not secure).
class Rng {
public:
    explicit Rng(std::uint64_t seed) {
        if (seed) det_.reset(new std::mt19937_64(seed));
        else sec_ = UniformRandomGeneratorFactory::DefaultFactory()->create();
    }
    std::uint64_t next() {
        if (det_) return (*det_)();
        if (pos_ == buf_.size()) { sec_->generate(buf_.size() * sizeof(std::uint64_t), reinterpret_cast<seal_byte*>(buf_.data())); pos_ = 0; }
        return buf_[pos_++];
    }
private:
    std::unique_ptr<std::mt19937_64> det_;
    std::shared_ptr<UniformRandomGenerator> sec_;
    std::vector<std::uint64_t> buf_ = std::vector<std::uint64_t>(4096);
    std::size_t pos_ = 4096;
};

// uniform ternary secret (coefficients uniform in {-1, 0, 1}), like SEAL's own key generation
inline std::vector<int> sample_ternary(std::size_t N, std::uint64_t seed) {
    Rng rng(seed);
    std::vector<int> coeffs(N);
    for (std::size_t i = 0; i < N; i++) coeffs[i] = (int) (rng.next() % 3) - 1;
    return coeffs;
}

inline std::vector<int> embed_sk(const std::vector<int>& sk_small) {
    std::vector<int> sk_big(2 * sk_small.size(), 0);
    for (std::size_t i = 0; i < sk_small.size(); i++) sk_big[2 * i] = sk_small[i];
    return sk_big;
}

// SEAL SecretKey (key level of `ctx`, NTT form) from signed coefficients
inline SecretKey make_secret_key(const std::vector<int>& sk_coeffs, const SEALContext& ctx) {
    auto& key_cd = *ctx.key_context_data();
    auto& coeff_modulus = key_cd.parms().coeff_modulus();
    const std::size_t N = key_cd.parms().poly_modulus_degree();
    if (sk_coeffs.size() != N) throw std::invalid_argument("secret key coefficient count mismatch");

    SecretKey sk;
    sk.data().resize(mul_safe(N, coeff_modulus.size()));
    sk.data().parms_id() = parms_id_zero;
    std::uint64_t* ptr = sk.data().data();
    for (std::size_t k = 0; k < coeff_modulus.size(); k++) {
        const std::uint64_t q = coeff_modulus[k].value();
        for (std::size_t i = 0; i < N; i++) {
            int v = sk_coeffs[i];
            ptr[k * N + i] = (v >= 0) ? (std::uint64_t) v : q - (std::uint64_t) (-v);
        }
        ntt_negacyclic_harvey(ptr + k * N, key_cd.small_ntt_tables()[k]);
    }
    sk.data().parms_id() = key_cd.parms_id();
    return sk;
}

// ------------------------------------------------------------------------------------------------------------------
// BV-style key-switching key, RNS + gadget decomposition.   pieces[k][b] encrypts  sk_src * T_k * B^b  under sk_dst
// (T_k = CRT idempotent of prime q_k, B = 2^log_base).  Noise per piece ~ t * e with e a centered binomial (eta = 21).
// seed: see Rng (0 = OS entropy).
// ------------------------------------------------------------------------------------------------------------------
struct KSwitchKey {
    struct Piece {
        std::vector<std::vector<std::uint64_t>> a;   // [L][N], NTT form
        std::vector<std::vector<std::uint64_t>> b;   // [L][N], NTT form
    };
    std::vector<std::vector<Piece>> pieces;          // [RNS prime k][gadget digit b]
    std::vector<Modulus> q_chain;
    std::size_t N = 0;
    int log_base = 8, num_digits = 0;
};

inline std::vector<std::vector<std::uint64_t>> signed_to_ntt(const std::vector<int>& sk, const std::vector<Modulus>& q_chain,
                                                             const NTTTables* tables, std::size_t N) {
    std::vector<std::vector<std::uint64_t>> out(q_chain.size(), std::vector<std::uint64_t>(N));
    for (std::size_t k = 0; k < q_chain.size(); k++) {
        const std::uint64_t q = q_chain[k].value();
        for (std::size_t i = 0; i < N; i++) out[k][i] = (sk[i] >= 0) ? (std::uint64_t) sk[i] : q - (std::uint64_t) (-sk[i]);
        ntt_negacyclic_harvey(out[k].data(), tables[k]);
    }
    return out;
}

// the key is generated for the modulus level `parms_id` of `ctx` (the level at which the ciphertexts will be switched)
inline KSwitchKey gen_key_switch_key(const std::vector<int>& sk_src, const std::vector<int>& sk_dst, const SEALContext& ctx,
                                     const parms_id_type& parms_id, std::uint64_t plain_modulus, int log_base,
                                     std::uint64_t seed) {
    auto cd_ptr = ctx.get_context_data(parms_id);
    if (!cd_ptr) throw std::invalid_argument("gen_key_switch_key: bad parms_id");
    auto& cd = *cd_ptr;
    const auto& q_chain = cd.parms().coeff_modulus();
    const std::size_t L = q_chain.size(), N = cd.parms().poly_modulus_degree();
    if (sk_src.size() != N || sk_dst.size() != N) throw std::invalid_argument("gen_key_switch_key: secret key size != N");
    const NTTTables* tables = cd.small_ntt_tables();

    auto sk_src_ntt = signed_to_ntt(sk_src, q_chain, tables, N);
    auto sk_dst_ntt = signed_to_ntt(sk_dst, q_chain, tables, N);

    int max_log_q = 0;
    for (auto& q : q_chain) max_log_q = std::max(max_log_q, q.bit_count());

    KSwitchKey ksk;
    ksk.q_chain.assign(q_chain.begin(), q_chain.end());
    ksk.N = N;
    ksk.log_base = log_base;
    ksk.num_digits = (max_log_q + log_base - 1) / log_base;
    ksk.pieces.assign(L, std::vector<KSwitchKey::Piece>(ksk.num_digits));

    Rng rng(seed);
    Modulus t_mod(plain_modulus);
    std::vector<std::uint64_t> t_mod_q(L);
    for (std::size_t j = 0; j < L; j++) t_mod_q[j] = barrett_reduce_64(plain_modulus, q_chain[j]);

    std::vector<std::uint64_t> tmp(N), tmp2(N), e_ntt(N);
    for (std::size_t k = 0; k < L; k++) {
        for (int b = 0; b < ksk.num_digits; b++) {
            auto& piece = ksk.pieces[k][b];
            piece.a.assign(L, std::vector<std::uint64_t>(N));
            piece.b.assign(L, std::vector<std::uint64_t>(N));

            std::vector<int> e(N);                                  // one small error polynomial, reduced mod every prime
            const std::uint64_t mask21 = (std::uint64_t(1) << 21) - 1;
            for (std::size_t i = 0; i < N; i++) {                   // centered binomial, eta = 21: popcount(21 bits) - popcount(21 bits)
                std::uint64_t r = rng.next();
                e[i] = __builtin_popcountll(r & mask21) - __builtin_popcountll((r >> 21) & mask21);
            }
            // B^b mod q_k
            std::uint64_t pow_b = 1 % q_chain[k].value();
            for (int bit = 0; bit < b * log_base; bit++) pow_b = add_uint_mod(pow_b, pow_b, q_chain[k]);

            for (std::size_t j = 0; j < L; j++) {
                const std::uint64_t qj = q_chain[j].value();
                for (std::size_t i = 0; i < N; i++) piece.a[j][i] = rng.next() % qj;
                for (std::size_t i = 0; i < N; i++) e_ntt[i] = (e[i] >= 0) ? (std::uint64_t) e[i] : qj - (std::uint64_t) (-e[i]);
                ntt_negacyclic_harvey(e_ntt.data(), tables[j]);
                dyadic_product_coeffmod(piece.a[j].data(), sk_dst_ntt[j].data(), N, q_chain[j], tmp.data());       // a * s_dst
                multiply_poly_scalar_coeffmod(e_ntt.data(), N, t_mod_q[j], q_chain[j], tmp2.data());                // t * e
                sub_poly_coeffmod(tmp2.data(), tmp.data(), N, q_chain[j], piece.b[j].data());                       // t e - a s_dst
                if (j == k) {                                                                                       // + sk_src * B^b
                    multiply_poly_scalar_coeffmod(sk_src_ntt[k].data(), N, pow_b, q_chain[k], tmp.data());
                    add_poly_coeffmod(piece.b[j].data(), tmp.data(), N, q_chain[j], piece.b[j].data());
                }
            }
        }
    }
    return ksk;
}

// switches a size-2 NTT-form ciphertext under sk_src to sk_dst, same level, same plaintext
inline Ciphertext apply_key_switch(const Ciphertext& ct, const KSwitchKey& ksk, const SEALContext& ctx) {
    auto cd_ptr = ctx.get_context_data(ct.parms_id());
    if (!cd_ptr) throw std::invalid_argument("apply_key_switch: bad parms_id");
    auto& cd = *cd_ptr;
    const auto& q_chain = cd.parms().coeff_modulus();
    const std::size_t L = q_chain.size(), N = cd.parms().poly_modulus_degree();
    if (!ct.is_ntt_form() || ct.size() != 2) throw std::invalid_argument("apply_key_switch: expected a size-2 NTT-form ciphertext");
    if (L != ksk.q_chain.size() || N != ksk.N) throw std::invalid_argument("apply_key_switch: key was generated for another level");
    const NTTTables* tables = cd.small_ntt_tables();

    std::vector<std::vector<std::uint64_t>> new_c0(L), new_c1(L);
    for (std::size_t j = 0; j < L; j++) {
        new_c0[j].assign(ct.data(0) + j * N, ct.data(0) + (j + 1) * N);
        new_c1[j].assign(N, 0);
    }

    const std::uint64_t mask = (std::uint64_t(1) << ksk.log_base) - 1;
    std::vector<std::uint64_t> c1(N), digit(N), prod(N);
    for (std::size_t k = 0; k < L; k++) {
        std::memcpy(c1.data(), ct.data(1) + k * N, N * sizeof(std::uint64_t));
        inverse_ntt_negacyclic_harvey(c1.data(), tables[k]);           // c1 mod q_k, coefficients in [0, q_k)
        for (int b = 0; b < ksk.num_digits; b++) {
            const int shift = b * ksk.log_base;
            for (std::size_t i = 0; i < N; i++) digit[i] = (c1[i] >> shift) & mask;
            for (std::size_t j = 0; j < L; j++) {                      // digit < B <= q_j
                std::vector<std::uint64_t> d_ntt(digit);
                ntt_negacyclic_harvey(d_ntt.data(), tables[j]);
                dyadic_product_coeffmod(d_ntt.data(), ksk.pieces[k][b].a[j].data(), N, q_chain[j], prod.data());
                add_poly_coeffmod(new_c1[j].data(), prod.data(), N, q_chain[j], new_c1[j].data());
                dyadic_product_coeffmod(d_ntt.data(), ksk.pieces[k][b].b[j].data(), N, q_chain[j], prod.data());
                add_poly_coeffmod(new_c0[j].data(), prod.data(), N, q_chain[j], new_c0[j].data());
            }
        }
    }

    Ciphertext out(ctx, ct.parms_id());
    out.resize(ctx, ct.parms_id(), 2);
    out.is_ntt_form() = true;
    out.scale() = ct.scale();
    out.correction_factor() = ct.correction_factor();
    for (std::size_t j = 0; j < L; j++) {
        std::memcpy(out.data(0) + j * N, new_c0[j].data(), N * sizeof(std::uint64_t));
        std::memcpy(out.data(1) + j * N, new_c1[j].data(), N * sizeof(std::uint64_t));
    }
    return out;
}

// ------------------------------------------------------------------------------------------------------------------
// plaintext embedding and extraction
// ------------------------------------------------------------------------------------------------------------------

// plaintext polynomial of R_small (e.g. the result of a small BatchEncoder) -> plaintext polynomial p(X^2) of R_big
inline Plaintext embed_plaintext(const Plaintext& small, std::size_t N_big) {
    Plaintext big;
    big.resize(N_big);
    big.set_zero();
    for (std::size_t i = 0; i < small.coeff_count() && 2 * i < N_big; i++) big[2 * i] = small[i];
    return big;
}

// the level of the small context whose primes are exactly those of `ct_big` (the data primes of the big chain that survive)
inline parms_id_type matching_small_level(const Ciphertext& ct_big, const SEALContext& ctx_big, const SEALContext& ctx_small) {
    const auto& mods = ctx_big.get_context_data(ct_big.parms_id())->parms().coeff_modulus();
    for (auto cd = ctx_small.first_context_data(); cd; cd = cd->next_context_data()) {
        const auto& sm = cd->parms().coeff_modulus();
        if (sm.size() != mods.size()) continue;
        bool same = true;
        for (std::size_t i = 0; i < sm.size(); i++) same = same && (sm[i].value() == mods[i].value());
        if (same) return cd->parms_id();
    }
    throw std::invalid_argument("matching_small_level: the primes of the ciphertext are not a level of the small context");
}

// (c0, c1) under sk_target = embed(sk_small) in R_big  ->  (c0_even, c1_even), a ciphertext of the small context under sk_small
inline Ciphertext extract_to_small(const Ciphertext& ct, const SEALContext& ctx_big, const SEALContext& ctx_small) {
    auto& cd_big = *ctx_big.get_context_data(ct.parms_id());
    const parms_id_type small_id = matching_small_level(ct, ctx_big, ctx_small);
    auto& cd_small = *ctx_small.get_context_data(small_id);
    const std::size_t Nb = cd_big.parms().poly_modulus_degree(), Ns = cd_small.parms().poly_modulus_degree();
    if (Nb != 2 * Ns) throw std::invalid_argument("extract_to_small: N_big must be 2 * N_small");
    if (!ct.is_ntt_form() || ct.size() != 2) throw std::invalid_argument("extract_to_small: expected a size-2 NTT-form ciphertext");
    const std::size_t L = cd_big.parms().coeff_modulus().size();

    Ciphertext out(ctx_small, small_id);
    out.resize(ctx_small, small_id, 2);
    out.is_ntt_form() = true;
    out.scale() = ct.scale();
    out.correction_factor() = ct.correction_factor();

    std::vector<std::uint64_t> big(Nb);
    for (std::size_t p = 0; p < 2; p++) {
        for (std::size_t k = 0; k < L; k++) {
            std::memcpy(big.data(), ct.data(p) + k * Nb, Nb * sizeof(std::uint64_t));
            inverse_ntt_negacyclic_harvey(big.data(), cd_big.small_ntt_tables()[k]);
            std::uint64_t* dst = out.data(p) + k * Ns;
            for (std::size_t i = 0; i < Ns; i++) dst[i] = big[2 * i];
            ntt_negacyclic_harvey(dst, cd_small.small_ntt_tables()[k]);
        }
    }
    return out;
}

// key switch + extraction
inline Ciphertext ring_switch(const Ciphertext& ct_big, const KSwitchKey& ksk, const SEALContext& ctx_big,
                              const SEALContext& ctx_small) {
    Ciphertext switched = apply_key_switch(ct_big, ksk, ctx_big);
    return extract_to_small(switched, ctx_big, ctx_small);
}

}  // namespace rsw
