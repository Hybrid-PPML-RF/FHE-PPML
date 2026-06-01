#include "seal/seal.h"
#include "util.h"
#include "global.h"
#include <iomanip>
#include <numeric>
#include <stdio.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

using namespace seal;
using namespace std;

static void print_row(const string& step_name, int mod_cnt, int bgt, long long unit_us) {
    cout << left
         << setw(44) << step_name
         << setw(16) << mod_cnt
         << setw(18) << (to_string(bgt) + " bits")
         << unit_us << " us\n";
}

int main() {
    // Iris dataset
    data_size_glb       = 100;
    attr_size_glb       = 4;
    sqrt_attr_size_glb  = 4;
    value_size_glb      = 8;
    label_size_glb      = 3;
    depth_glb           = 6;

    for (auto &i : seed_glb) i = random_uint64();

    const int p = 65537;

    EncryptionParameters bgv_params(scheme_type::bgv);
    bgv_params.set_poly_modulus_degree(poly_modulus_degree_glb);

    // First prime 40 bits → budget at chain_index=0 ≈ 9 bits.
    // CT×CT at chain_index=1 (budget≈69) + mod_switch lands at chain_index=0 with ~6 bits ≤ 10.
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree_glb, {
        40, 60, 60, 60, 60, 60,   // 6 computation primes
        60                         // special prime for key-switching
    });
    bgv_params.set_coeff_modulus(coeff_modulus);
    bgv_params.set_plain_modulus(p);

    prng_seed_type seed;
    for (auto &i : seed) i = random_uint64();
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

    // Galois steps: same as main_extract_ops but only steps 1-3 are executed.
    vector<int> gal_steps = {0, 1};
    for (int i = 0; i < 2 * value_size_glb; i++)
        gal_steps.push_back(i * data_size_glb);
    for (int i = data_size_glb; i > 0; i /= 2) {
        if (i % 2) gal_steps.push_back(i - 1);
        gal_steps.push_back(i);
    }
    for (int j = 1; j < label_size_glb; j++)
        gal_steps.push_back(-j * data_size_glb);

    int iter_ga = 1;
    while (iter_ga < attr_size_glb) iter_ga *= 2;
    for (int i = 0; i < iter_ga; i++) {
        int s = (i * data_size_glb * value_size_glb) % (int)(poly_modulus_degree_glb / 2);
        gal_steps.push_back(s);
        if (s != 0) gal_steps.push_back(-s);
    }

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_steps, gal_keys);

    // Encrypt sample inputs
    vector<Ciphertext> inputs_X, inputs_Y;
    sample_one_hot_encoding_inputs(inputs_X, inputs_Y,
        data_size_glb, attr_size_glb, value_size_glb, label_size_glb,
        batch_encoder, encryptor);

    cout << "Initial budget (inputs_Y[0]): "
         << decryptor.invariant_noise_budget(inputs_Y[0]) << " bits\n";

    // Mod-switch inputs_Y[0] down to chain_index=1 to reduce runtime and focus budget.
    Ciphertext ct_Y = inputs_Y[0];
    while ((int)seal_context.get_context_data(ct_Y.parms_id())->chain_index() > 1)
        evaluator.mod_switch_to_next_inplace(ct_Y);

    cout << "Budget after mod_switch → chain_index=1: "
         << decryptor.invariant_noise_budget(ct_Y) << " bits\n\n";

    auto chain_idx = [&](const Ciphertext& ct) -> int {
        return (int)seal_context.get_context_data(ct.parms_id())->chain_index();
    };
    auto bgt = [&](const Ciphertext& ct) -> int {
        return decryptor.invariant_noise_budget(ct);
    };

    cout << left
         << setw(44) << "Step"
         << setw(16) << "Modulus Count"
         << setw(18) << "Budget (bits)"
         << "Unit Time (us)\n";
    cout << string(92, '-') << "\n";

    // ------------------------------------------------------------------
    // STEP 1: Extract column 0 from ct_Y (CT×PT mask) + rotation_and_fill
    // ------------------------------------------------------------------
    Plaintext mask_pl;
    mask_pl.resize(poly_modulus_degree_glb);
    mask_pl.parms_id() = parms_id_zero;
    for (size_t i = 0; i < poly_modulus_degree_glb; i++)
        mask_pl.data()[i] = (i < (size_t)data_size_glb) ? 1 : 0;

    // Unit time = single rotate_rows
    Ciphertext tmp_unit = ct_Y;
    auto t0 = chrono::high_resolution_clock::now();
    evaluator.rotate_rows_inplace(tmp_unit, data_size_glb, gal_keys);
    auto t1 = chrono::high_resolution_clock::now();
    long long single_rot_us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();

    Ciphertext ct_col;
    evaluator.multiply_plain(ct_Y, mask_pl, ct_col);
    Ciphertext Y_prime = rotation_and_fill(seal_context, ct_col, data_size_glb, evaluator, gal_keys);

    print_row("1. CT×PT extract + rotation_and_fill",
              chain_idx(Y_prime) + 1, bgt(Y_prime), single_rot_us);

    // ------------------------------------------------------------------
    // STEP 2: Initialize X' at matching chain_index; CT×CT + relin + mod_switch
    // ------------------------------------------------------------------
    srand(42);
    vector<uint64_t> x_plain(poly_modulus_degree_glb, 0);
    for (int i = 0; i < data_size_glb; i++) x_plain[i] = (uint64_t)((rand() % 100) + 1);
    Plaintext x_pl; batch_encoder.encode(x_plain, x_pl);
    Ciphertext ct_X; encryptor.encrypt(x_pl, ct_X);
    while (chain_idx(ct_X) > chain_idx(Y_prime))
        evaluator.mod_switch_to_next_inplace(ct_X);

    t0 = chrono::high_resolution_clock::now();
    Ciphertext ct_prod;
    evaluator.multiply(Y_prime, ct_X, ct_prod);
    evaluator.relinearize_inplace(ct_prod, relin_keys);
    evaluator.mod_switch_to_next_inplace(ct_prod);    // drop to chain_index=0
    t1 = chrono::high_resolution_clock::now();
    long long mul_us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();

    print_row("2. CT×CT + relin + mod_switch",
              chain_idx(ct_prod) + 1, bgt(ct_prod), mul_us);

    // ------------------------------------------------------------------
    // STEP 3a: rotation_and_add(data_size_glb, chunk=1) → h
    // ------------------------------------------------------------------
    Ciphertext tmp_3a = ct_prod;
    t0 = chrono::high_resolution_clock::now();
    evaluator.rotate_rows_inplace(tmp_3a, 1, gal_keys);
    t1 = chrono::high_resolution_clock::now();
    long long rot3a_us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();

    Ciphertext h = rotation_and_add(seal_context, ct_prod,
                                    data_size_glb, 1, evaluator, gal_keys, 0);

    print_row("3a. rot_add(D=100, chunk=1) → h",
              chain_idx(h) + 1, bgt(h), rot3a_us);

    // ------------------------------------------------------------------
    // STEP 3b: rotation_and_add(data_size*attr_size, chunk=data_size) → h'
    // ------------------------------------------------------------------
    Ciphertext tmp_3b = h;
    t0 = chrono::high_resolution_clock::now();
    evaluator.rotate_rows_inplace(tmp_3b, data_size_glb, gal_keys);
    t1 = chrono::high_resolution_clock::now();
    long long rot3b_us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();

    Ciphertext h_prime = rotation_and_add(seal_context, h,
        data_size_glb * attr_size_glb, data_size_glb, evaluator, gal_keys, 0);

    print_row("3b. rot_add(D*A=400, chunk=D=100) → h'",
              chain_idx(h_prime) + 1, bgt(h_prime), rot3b_us);

    cout << "\nFinal: chain_index=" << chain_idx(h_prime)
         << "  modulus_count=" << chain_idx(h_prime) + 1
         << "  budget=" << bgt(h_prime) << " bits\n";

    return 0;
}
