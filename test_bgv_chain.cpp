#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include "seal/seal.h"

using namespace std;
using namespace seal;

static void print_modulus_chain(const SEALContext &ctx) {
    cout << "Coeff modulus prime chain:\n";
    int total_bits = 0;
    auto ctx_data = ctx.key_context_data();
    int idx = 0;
    for (auto &prime : ctx_data->parms().coeff_modulus()) {
        int bits = (int)ceil(log2((double)prime.value()));
        cout << "  [" << idx++ << "] " << prime.value() << " (" << bits << " bits)";
        if (idx == (int)ctx_data->parms().coeff_modulus().size())
            cout << "  <- special (key-switch only)";
        cout << "\n";
        total_bits += bits;
    }
    int n_special = 1; // last prime is special
    int computation_bits = total_bits - (int)ceil(log2(
        (double)ctx_data->parms().coeff_modulus().back().value()));
    cout << "  Total modulus bits (incl. special): " << total_bits << "\n";
    cout << "  Computation primes only:            " << computation_bits << " bits\n\n";
}

int main() {
    size_t poly_modulus_degree = 16384;
    uint64_t plain_modulus_val = 65537; // 17-bit prime

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 17));

    // 8-level CT×CT chain:
    //   Need 9 computation primes (chain_index 8 → 0, one dropped per multiply+mod_switch)
    //   + 1 special prime for relinearization key quality.
    //
    // Budget ≈ sum(computation_prime_bits) - log2(2 * sqrt(3) * t * sigma * sqrt(n))
    //        ≈ sum - (17 + 14) ≈ sum - 31  (for t=65537, sigma=3.2, n=16384)
    // With 9 × 49-bit primes = 441 bits: budget ≈ 441 - 31 ≈ 410 bits
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {
        49, 49, 49, 49, 49, 49, 49, 49, 49,  // 9 computation primes (levels 8 → 0)
        60                                    // 1 special prime for key decomposition
    }));

    SEALContext context(parms, true, sec_level_type::none);

    print_modulus_chain(context);

    KeyGenerator keygen(context);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);
    RelinKeys rk;
    keygen.create_relin_keys(rk);

    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    // Encrypt plaintext 2 in every slot.
    // After 8 squarings: 2^(2^8) = 2^256 ≡ 1 (mod 65537)
    // Proof: 2^16 ≡ -1, 2^32 ≡ 1 (mod 65537) → 2^256 = (2^32)^8 ≡ 1.
    vector<uint64_t> msg(encoder.slot_count(), 2ULL);
    Plaintext pt;
    encoder.encode(msg, pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);

    int initial_budget = decryptor.invariant_noise_budget(ct);
    int initial_chain  = (int)context.get_context_data(ct.parms_id())->chain_index();
    cout << "Initial ciphertext:\n";
    cout << "  Chain index:   " << initial_chain << "\n";
    cout << "  Noise budget:  " << initial_budget << " bits\n\n";

    // Table header
    cout << left
         << setw(7)  << "Level"
         << setw(16) << "Budget before"
         << setw(24) << "After mul+relin"
         << setw(24) << "After mod_switch"
         << setw(16) << "Bits burned"
         << "Chain idx after\n";
    cout << string(90, '-') << "\n";

    int prev_budget = initial_budget;

    for (int lvl = 1; lvl <= 8; lvl++) {
        int before  = decryptor.invariant_noise_budget(ct);

        // CT×CT squaring + relinearize
        Ciphertext ct_next;
        evaluator.multiply(ct, ct, ct_next);
        evaluator.relinearize_inplace(ct_next, rk);
        int after_mul = decryptor.invariant_noise_budget(ct_next);

        // Mod-switch: drop the highest prime (restores invariant budget in BGV)
        evaluator.mod_switch_to_next_inplace(ct_next);
        int after_ms   = decryptor.invariant_noise_budget(ct_next);
        int chain_after = (int)context.get_context_data(ct_next.parms_id())->chain_index();
        int burned      = prev_budget - after_ms;

        cout << left
             << setw(7)  << lvl
             << setw(16) << (to_string(before) + " bits")
             << setw(24) << (to_string(after_mul) + " bits")
             << setw(24) << (to_string(after_ms) + " bits")
             << setw(16) << (to_string(burned) + " bits")
             << chain_after << "\n";

        ct           = ct_next;
        prev_budget  = after_ms;
    }

    // Verify result
    Plaintext pt_result;
    decryptor.decrypt(ct, pt_result);
    vector<uint64_t> result;
    encoder.decode(pt_result, result);

    bool ok = true;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i] != 1ULL) { ok = false; break; }
    }

    cout << "\nFinal noise budget: " << decryptor.invariant_noise_budget(ct) << " bits\n";
    cout << "Result slot[0] = " << result[0] << " (expected 1, " << (ok ? "PASS" : "FAIL") << ")\n";

    return 0;
}
