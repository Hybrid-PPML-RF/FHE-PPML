#include "seal/seal.h"
#include "global.h"
#include <chrono>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace seal;
using namespace std;
using namespace chrono;

// ---- helpers ----------------------------------------------------------------

struct BenchResult {
    double keygen_us;
    double encrypt_us;
    double mul_relin_modswitch_us;  // one CT×CT with relin + mod_switch (BGV) or just relin (BFV)
    double decrypt_us;
    double total_depth4_chain_us;   // 4 chained multiplications simulating tree depth
};

static double elapsed_us(high_resolution_clock::time_point t0, high_resolution_clock::time_point t1) {
    return duration_cast<microseconds>(t1 - t0).count();
}

// ---- BFV benchmark ----------------------------------------------------------

BenchResult bench_bfv(size_t poly_deg, int p) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_deg);
    // Original 5×60-bit chain
    parms.set_coeff_modulus(CoeffModulus::Create(poly_deg, {60, 60, 60, 60, 60}));
    parms.set_plain_modulus(p);

    SEALContext ctx(parms, true, sec_level_type::none);

    BenchResult r{};

    // keygen
    auto t0 = high_resolution_clock::now();
    KeyGenerator keygen(ctx);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;  keygen.create_public_key(pk);
    RelinKeys rlk; keygen.create_relin_keys(rlk);
    r.keygen_us = elapsed_us(t0, high_resolution_clock::now());

    Encryptor enc(ctx, pk);
    Evaluator eval(ctx);
    BatchEncoder benc(ctx);
    Decryptor dec(ctx, sk);

    vector<uint64_t> msg(poly_deg, 3);
    Plaintext pl;
    benc.encode(msg, pl);

    // encrypt
    Ciphertext ct_a, ct_b;
    t0 = high_resolution_clock::now();
    enc.encrypt(pl, ct_a);
    enc.encrypt(pl, ct_b);
    r.encrypt_us = elapsed_us(t0, high_resolution_clock::now()) / 2.0;

    // single multiply + relinearize (BFV: no mandatory mod_switch)
    Ciphertext ct_mul;
    t0 = high_resolution_clock::now();
    eval.multiply(ct_a, ct_b, ct_mul);
    eval.relinearize_inplace(ct_mul, rlk);
    r.mul_relin_modswitch_us = elapsed_us(t0, high_resolution_clock::now());

    // decrypt
    Plaintext pl_out;
    t0 = high_resolution_clock::now();
    dec.decrypt(ct_mul, pl_out);
    r.decrypt_us = elapsed_us(t0, high_resolution_clock::now());

    // 4 chained multiplications (simulating tree depth)
    Ciphertext chain = ct_a;
    t0 = high_resolution_clock::now();
    for (int i = 0; i < 4; i++) {
        Ciphertext tmp;
        enc.encrypt(pl, tmp);
        eval.mod_switch_to_inplace(tmp, chain.parms_id());
        eval.multiply(chain, tmp, chain);
        eval.relinearize_inplace(chain, rlk);
        // BFV: optional mod_switch every 2 levels (original code's pattern)
        if (i % 2 == 1) {
            eval.mod_switch_to_next_inplace(chain);
        }
    }
    r.total_depth4_chain_us = elapsed_us(t0, high_resolution_clock::now());

    return r;
}

// ---- BGV benchmark ----------------------------------------------------------

BenchResult bench_bgv(size_t poly_deg, int p) {
    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_deg);
    // New 9-prime chain: 60-bit base, 7×40-bit computation levels, 60-bit top
    parms.set_coeff_modulus(CoeffModulus::Create(poly_deg, {60, 40, 40, 40, 40, 40, 40, 40, 60}));
    parms.set_plain_modulus(p);

    SEALContext ctx(parms, true, sec_level_type::none);

    BenchResult r{};

    // keygen
    auto t0 = high_resolution_clock::now();
    KeyGenerator keygen(ctx);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;  keygen.create_public_key(pk);
    RelinKeys rlk; keygen.create_relin_keys(rlk);
    r.keygen_us = elapsed_us(t0, high_resolution_clock::now());

    Encryptor enc(ctx, pk);
    Evaluator eval(ctx);
    BatchEncoder benc(ctx);
    Decryptor dec(ctx, sk);

    vector<uint64_t> msg(poly_deg, 3);
    Plaintext pl;
    benc.encode(msg, pl);

    // encrypt
    Ciphertext ct_a, ct_b;
    t0 = high_resolution_clock::now();
    enc.encrypt(pl, ct_a);
    enc.encrypt(pl, ct_b);
    r.encrypt_us = elapsed_us(t0, high_resolution_clock::now()) / 2.0;

    // single multiply + relinearize + mod_switch (BGV: mandatory mod_switch)
    Ciphertext ct_mul;
    t0 = high_resolution_clock::now();
    eval.multiply(ct_a, ct_b, ct_mul);
    eval.relinearize_inplace(ct_mul, rlk);
    eval.mod_switch_to_next_inplace(ct_mul);
    r.mul_relin_modswitch_us = elapsed_us(t0, high_resolution_clock::now());

    // decrypt
    Plaintext pl_out;
    t0 = high_resolution_clock::now();
    dec.decrypt(ct_mul, pl_out);
    r.decrypt_us = elapsed_us(t0, high_resolution_clock::now());

    // 4 chained multiplications (simulating tree depth), mod_switch after every multiply
    Ciphertext chain = ct_a;
    t0 = high_resolution_clock::now();
    for (int i = 0; i < 4; i++) {
        Ciphertext tmp;
        enc.encrypt(pl, tmp);
        eval.mod_switch_to_inplace(tmp, chain.parms_id());
        eval.multiply(chain, tmp, chain);
        eval.relinearize_inplace(chain, rlk);
        eval.mod_switch_to_next_inplace(chain);
    }
    r.total_depth4_chain_us = elapsed_us(t0, high_resolution_clock::now());

    return r;
}

// ---- main -------------------------------------------------------------------

int main() {
    const size_t poly_deg = poly_modulus_degree_glb;  // 16384 from global.h
    const int p = 65537;
    const int REPS = 5;

    auto print_row = [](const string& name, const BenchResult& r) {
        cout << left << setw(6) << name
             << "  keygen=" << setw(10) << r.keygen_us / 1000.0 << " ms"
             << "  encrypt=" << setw(8) << r.encrypt_us / 1000.0 << " ms"
             << "  mul+relin(+modsw)=" << setw(8) << r.mul_relin_modswitch_us / 1000.0 << " ms"
             << "  decrypt=" << setw(8) << r.decrypt_us / 1000.0 << " ms"
             << "  depth-4 chain=" << setw(10) << r.total_depth4_chain_us / 1000.0 << " ms\n";
    };

    cout << "Benchmark: n=" << poly_deg << ", p=" << p
         << ", averaged over " << REPS << " repetitions\n";
    cout << string(110, '-') << "\n";

    BenchResult bfv_avg{}, bgv_avg{};

    for (int rep = 0; rep < REPS; rep++) {
        auto bfv = bench_bfv(poly_deg, p);
        auto bgv = bench_bgv(poly_deg, p);
        bfv_avg.keygen_us               += bfv.keygen_us;
        bfv_avg.encrypt_us              += bfv.encrypt_us;
        bfv_avg.mul_relin_modswitch_us  += bfv.mul_relin_modswitch_us;
        bfv_avg.decrypt_us              += bfv.decrypt_us;
        bfv_avg.total_depth4_chain_us   += bfv.total_depth4_chain_us;
        bgv_avg.keygen_us               += bgv.keygen_us;
        bgv_avg.encrypt_us              += bgv.encrypt_us;
        bgv_avg.mul_relin_modswitch_us  += bgv.mul_relin_modswitch_us;
        bgv_avg.decrypt_us              += bgv.decrypt_us;
        bgv_avg.total_depth4_chain_us   += bgv.total_depth4_chain_us;
    }

    auto div_rep = [&](BenchResult& r) {
        r.keygen_us              /= REPS;
        r.encrypt_us             /= REPS;
        r.mul_relin_modswitch_us /= REPS;
        r.decrypt_us             /= REPS;
        r.total_depth4_chain_us  /= REPS;
    };
    div_rep(bfv_avg);
    div_rep(bgv_avg);

    print_row("BFV", bfv_avg);
    print_row("BGV", bgv_avg);

    cout << string(110, '-') << "\n";
    cout << "BGV/BFV ratio:"
         << "  mul+relin(+modsw)="
         << fixed << setprecision(2)
         << bgv_avg.mul_relin_modswitch_us / bfv_avg.mul_relin_modswitch_us << "x"
         << "  depth-4 chain="
         << bgv_avg.total_depth4_chain_us  / bfv_avg.total_depth4_chain_us  << "x\n";

    return 0;
}
