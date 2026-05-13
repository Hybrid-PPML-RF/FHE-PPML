// BGV microbenchmark
// Operations: CT+CT add, PT×CT mul, CT×CT mul+relin+modsw, row rotation
// Ciphertext modulus total: 320–480 bits
// Ring dim n chosen as the minimum satisfying HE-standard 128-bit security:
//   n=16384 for total ≤ 438 bits,  n=32768 for total ≤ 881 bits

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

using namespace seal;
using namespace std;

static constexpr int TRIALS = 100;   // timed iterations
static constexpr int WARMUP = 5;     // discarded warm-up iterations
static constexpr int PMOD   = 65537; // BGV plain modulus (prime, supports batching)

// ─── statistics ──────────────────────────────────────────────────────────────
struct Stats { double mean, stdev, min_v, max_v; };

static Stats compute_stats(vector<double>& v) {
    Stats s;
    s.min_v = *min_element(v.begin(), v.end());
    s.max_v = *max_element(v.begin(), v.end());
    s.mean  = accumulate(v.begin(), v.end(), 0.0) / (double)v.size();
    double sq = 0;
    for (double x : v) sq += (x - s.mean) * (x - s.mean);
    s.stdev = sqrt(sq / (double)v.size());
    return s;
}

// ─── benchmark configurations ────────────────────────────────────────────────
// Modulus chain: {60-bit base, k×40-bit middles, 60-bit top}
//   total = 60 + 40k + 60
//   n=16384 supports ≤438 bits (128-bit security); n=32768 supports ≤881 bits
struct Config {
    int         bits;   // target total coeff-modulus bits
    size_t      n;      // ring dimension
    vector<int> chain;  // bit sizes for CoeffModulus::Create
};

static const vector<Config> CONFIGS = {
    { 320, 16384, {60, 40, 40, 40, 40, 40, 60}                         }, // 60+5×40+60
    { 360, 16384, {60, 40, 40, 40, 40, 40, 40, 60}                     }, // 60+6×40+60
    { 400, 16384, {60, 40, 40, 40, 40, 40, 40, 40, 60}                 }, // 60+7×40+60
    { 440, 32768, {60, 40, 40, 40, 40, 40, 40, 40, 40, 60}             }, // 60+8×40+60  (>438 → n=32768)
    { 480, 32768, {60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60}         }, // 60+9×40+60
};

// ─── result row ──────────────────────────────────────────────────────────────
struct Row {
    int    actual_bits;
    size_t n;
    Stats  ct_add, pt_mul, ct_mul, rotate;
};

// ─── benchmark one configuration ─────────────────────────────────────────────
static Row bench_one(const Config& cfg) {
    // context
    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(cfg.n);
    auto cm = CoeffModulus::Create(cfg.n, cfg.chain);
    parms.set_coeff_modulus(cm);
    parms.set_plain_modulus(PMOD);
    SEALContext ctx(parms, /*expand_mod_chain=*/true, sec_level_type::tc128);

    int actual_bits = 0;
    for (auto& m : cm) actual_bits += m.bit_count();

    // keys
    KeyGenerator keygen(ctx);
    auto       sk  = keygen.secret_key();
    PublicKey  pk;  keygen.create_public_key(pk);
    RelinKeys  rlk; keygen.create_relin_keys(rlk);
    GaloisKeys glk; keygen.create_galois_keys(vector<int>{1}, glk);

    Encryptor    enc (ctx, pk);
    Evaluator    eval(ctx);
    BatchEncoder benc(ctx);

    // plaintexts
    Plaintext pl_a, pl_b;
    { vector<uint64_t> m(cfg.n, 7); benc.encode(m, pl_a); benc.encode(m, pl_b); }

    auto fresh = [&]() { Ciphertext ct; enc.encrypt(pl_a, ct); return ct; };

    // pre-encrypt a pool for the CT×CT test (fresh pair per trial)
    const int TOTAL = TRIALS + WARMUP;
    vector<Ciphertext> pool_a(TOTAL), pool_b(TOTAL);
    for (int i = 0; i < TOTAL; i++) {
        enc.encrypt(pl_a, pool_a[i]);
        enc.encrypt(pl_b, pool_b[i]);
    }

    auto ns_to_us = [](long long ns) { return (double)ns / 1000.0; };
    auto elapsed  = [](auto t0, auto t1) {
        return chrono::duration_cast<chrono::nanoseconds>(t1 - t0).count();
    };
    auto tic = [] { return chrono::high_resolution_clock::now(); };

    Row row{ actual_bits, cfg.n, {}, {}, {}, {} };

    // ── 1. CT+CT addition ────────────────────────────────────────────────────
    {
        Ciphertext ct_a = fresh(), ct_b = fresh(), out;
        vector<double> t;
        t.reserve(TRIALS);
        for (int i = 0; i < TOTAL; i++) {
            auto t0 = tic();
            eval.add(ct_a, ct_b, out);
            if (i >= WARMUP) t.push_back(ns_to_us(elapsed(t0, tic())));
        }
        row.ct_add = compute_stats(t);
    }

    // ── 2. PT×CT multiplication ──────────────────────────────────────────────
    {
        Ciphertext ct_a = fresh(), out;
        vector<double> t;
        t.reserve(TRIALS);
        for (int i = 0; i < TOTAL; i++) {
            auto t0 = tic();
            eval.multiply_plain(ct_a, pl_b, out);
            if (i >= WARMUP) t.push_back(ns_to_us(elapsed(t0, tic())));
        }
        row.pt_mul = compute_stats(t);
    }

    // ── 3. CT×CT multiplication + relinearization + mod_switch ──────────────
    // Fresh ciphertext pair per trial (from pool) so every trial starts at the
    // top chain level, making timings independent of prior mod-downs.
    {
        vector<double> t;
        t.reserve(TRIALS);
        for (int i = 0; i < TOTAL; i++) {
            Ciphertext ct_a = pool_a[i];   // copy; encryption not timed
            Ciphertext ct_b = pool_b[i];
            auto t0 = tic();
            eval.multiply(ct_a, ct_b, ct_a);
            eval.relinearize_inplace(ct_a, rlk);
            eval.mod_switch_to_next_inplace(ct_a);
            if (i >= WARMUP) t.push_back(ns_to_us(elapsed(t0, tic())));
        }
        row.ct_mul = compute_stats(t);
    }

    // ── 4. Row rotation (step = 1) ───────────────────────────────────────────
    {
        Ciphertext ct_a = fresh(), out;
        vector<double> t;
        t.reserve(TRIALS);
        for (int i = 0; i < TOTAL; i++) {
            auto t0 = tic();
            eval.rotate_rows(ct_a, 1, glk, out);
            if (i >= WARMUP) t.push_back(ns_to_us(elapsed(t0, tic())));
        }
        row.rotate = compute_stats(t);
    }

    return row;
}

// ─── table ───────────────────────────────────────────────────────────────────
static void print_table(const vector<Row>& rows) {
    // format: "mean ±stdev [min, max]"
    auto cell = [](const Stats& s) {
        ostringstream oss;
        oss << fixed << setprecision(2)
            << s.mean << " ±" << s.stdev
            << "  [" << s.min_v << ", " << s.max_v << "]";
        return oss.str();
    };

    const int B = 6, N = 7, C = 28;
    const int W = B + 2 + N + 2 + 4 * C;
    const string sep(W, '-');

    cout << "\n";
    cout << "BGV Microbenchmark   (p=" << PMOD
         << ",  " << TRIALS << " trials / " << WARMUP << " warmup,  time in µs)\n";
    cout << "n = minimum ring dim for HE-standard 128-bit security "
            "(n=16384: ≤438 bits; n=32768: ≤881 bits)\n";
    cout << "CT×CT column includes: multiply + relinearize + mod_switch_to_next\n";
    cout << "Format: mean ±stdev  [min, max]\n";
    cout << sep << "\n";
    cout << left
         << setw(B) << "bits"  << "  "
         << setw(N) << "n"     << "  "
         << setw(C) << "CT+CT add (µs)"
         << setw(C) << "PT×CT mul (µs)"
         << setw(C) << "CT×CT mul (µs)"
         << setw(C) << "Rotation row,step=1 (µs)"
         << "\n";
    cout << sep << "\n";
    for (auto& r : rows) {
        cout << left
             << setw(B) << r.actual_bits << "  "
             << setw(N) << r.n           << "  "
             << setw(C) << cell(r.ct_add)
             << setw(C) << cell(r.pt_mul)
             << setw(C) << cell(r.ct_mul)
             << setw(C) << cell(r.rotate)
             << "\n";
    }
    cout << sep << "\n";
}

int main() {
    vector<Row> rows;
    for (auto& cfg : CONFIGS) {
        cerr << "Benchmarking " << cfg.bits << "-bit modulus, n=" << cfg.n << "...\n" << flush;
        rows.push_back(bench_one(cfg));
    }
    print_table(rows);
    return 0;
}
