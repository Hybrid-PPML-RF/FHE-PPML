#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <cmath>
#include <string>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// SEAL_PLAIN_MOD_BIT_COUNT_MAX = 60, so a 60-bit prime is the closest feasible
// value to "64-bit". We use PlainModulus::Batching(N, 60) for the largest prime
// t ≡ 1 (mod 2N) that SEAL can support.

// Iris dataset dimensions
static const int DATA_SIZE   = 100;
static const int LABEL_SIZE  = 3;
static const int VALUE_SIZE  = 8;
static const int DEPTH       = 6;

using Clock = chrono::high_resolution_clock;
using us    = chrono::microseconds;

static long long us_since(Clock::time_point t0) {
    return chrono::duration_cast<us>(Clock::now() - t0).count();
}

// Rotation steps needed for rotation_and_add(DATA_SIZE, 1):
// Trace the algorithm for length=100, chunk_size=1:
//   iter=100→step=50, iter=50→step=25, iter=25→step=12 (carry=24),
//   iter=12→step=6,   iter=6→step=3,   iter=3→step=1   (carry=2)
static const vector<int> ROT_STEPS_INNER = {1, 2, 3, 6, 12, 24, 25, 50};
// Plus replication for LABEL_SIZE=3: shift by -1*DATA_SIZE and -2*DATA_SIZE
static const vector<int> ROT_STEPS_REPL = {-100, -200};

// Simplified rotation_and_add matching util.h for length=DATA_SIZE, chunk_size=1
static Ciphertext rot_and_add(Evaluator &ev, const Ciphertext &in,
                               GaloisKeys &gk) {
    Ciphertext out = in;
    int iter = DATA_SIZE; // 100
    bool co_init = false;
    Ciphertext carry;
    while (iter > 1) {
        int step = (iter / 2);
        Ciphertext tmp;
        ev.rotate_rows(out, step, gk, tmp);
        if (iter % 2) {
            int co_step = (iter - 1);
            if (!co_init) { ev.rotate_rows(out, co_step, gk, carry); co_init = true; }
            else          { Ciphertext t2; ev.rotate_rows(out, co_step, gk, t2);
                            ev.add_inplace(carry, t2); }
        }
        ev.add_inplace(out, tmp);
        iter /= 2;
    }
    if (co_init) ev.add_inplace(out, carry);
    return out;
}

struct Row { string label; int b0, b1; long long t_us; };

static void print_table(const vector<Row> &rows) {
    cout << "\n"
         << left  << setw(48) << "Operation"
         << right << setw(14) << "Before (bits)"
         << setw(14) << "After (bits)"
         << setw(14) << "Burned (bits)"
         << setw(14) << "Time (µs)" << "\n"
         << string(104, '-') << "\n";
    for (auto &r : rows)
        cout << left  << setw(48) << r.label
             << right << setw(14) << r.b0
             << setw(14) << r.b1
             << setw(14) << (r.b0 - r.b1)
             << setw(14) << r.t_us << "\n";
}

int main() {
    const size_t N = 16384;

    // ── Plaintext modulus: 60-bit prime ≡ 1 (mod 2N) ──────────────────────
    // SEAL's hard limit is SEAL_PLAIN_MOD_BIT_COUNT_MAX=60 (64-bit primes
    // overflow Montgomery reduction used internally for NTT on the plaintext).
    // 60-bit is the closest feasible substitute for a "64-bit" plaintext prime.
    Modulus t60 = PlainModulus::Batching(N, 60);
    cout << "Plaintext modulus t = " << t60.value()
         << "  (" << t60.bit_count() << " bits)\n";
    cout << "  (SEAL hard limit is 60 bits; 64-bit exceeds SEAL_PLAIN_MOD_BIT_COUNT_MAX)\n\n";

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(N);
    parms.set_plain_modulus(t60);

    // ── Ciphertext modulus sizing ──────────────────────────────────────────
    // Budget ≈ sum(comp_bits) - log2(t) - log2(2·√3·σ·√N)
    //        ≈ sum(comp_bits) - 60 - 10.5   (σ=3.2, N=16384)
    //        ≈ sum(comp_bits) - 70.5
    //
    // Protocol critical path (iris, depth=6):
    //   1 preprocess CT×CT  + 1 ms
    //   + 6×(1 sel_vec update CT×CT + 2 partition CT×CT) + 7 ms
    //   = 7 CT×CT multiplications, each followed by mod_switch
    //
    // With 9×60-bit computation primes (540 bits):
    //   Initial budget ≈ 540 - 70.5 ≈ 469 bits
    //   After 7 levels (each burns 60 bits): 469 - 420 = 49 bits remaining ✓
    parms.set_coeff_modulus(CoeffModulus::Create(N, {
        60, 60, 60, 60, 60, 60, 60, 60, 60,   // 9 computation primes
        60                                      // 1 special prime (key-switch)
    }));

    SEALContext ctx(parms, true, sec_level_type::none);

    // Print coeff_modulus structure
    {
        auto &cd = *ctx.key_context_data();
        int total = 0, cidx = 0;
        cout << "Ciphertext modulus primes:\n";
        for (auto &p : cd.parms().coeff_modulus()) {
            int b = p.bit_count();
            cout << "  [" << cidx++ << "] " << p.value() << "  (" << b << " bits)"
                 << (cidx == (int)cd.parms().coeff_modulus().size() ? "  ← special" : "")
                 << "\n";
            total += b;
        }
        int special_bits = cd.parms().coeff_modulus().back().bit_count();
        cout << "  Total: " << total << " bits  |  Computation primes: "
             << (total - special_bits) << " bits  |  Special: "
             << special_bits << " bits\n\n";
    }

    // ── Key generation ─────────────────────────────────────────────────────
    KeyGenerator keygen(ctx);
    SecretKey sk = keygen.secret_key();
    PublicKey  pk; keygen.create_public_key(pk);
    RelinKeys  rk; keygen.create_relin_keys(rk);

    vector<int> gal_steps;
    for (int s : ROT_STEPS_INNER) gal_steps.push_back(s);
    for (int s : ROT_STEPS_REPL)  gal_steps.push_back(s);
    GaloisKeys gk; keygen.create_galois_keys(gal_steps, gk);

    BatchEncoder enc(ctx);
    Encryptor    encryptor(ctx, pk);
    Evaluator    eval(ctx);
    Decryptor    dec(ctx, sk);

    // ── Fresh ciphertexts ──────────────────────────────────────────────────
    auto make_ct = [&](uint64_t val) {
        Plaintext pt;
        enc.encode(vector<uint64_t>(N, val), pt);
        Ciphertext ct; encryptor.encrypt(pt, ct);
        return ct;
    };
    auto bud = [&](const Ciphertext &c) { return dec.invariant_noise_budget(c); };

    Ciphertext ctA = make_ct(2), ctB = make_ct(3);
    Plaintext  ptC; enc.encode(vector<uint64_t>(N, 5ULL), ptC);

    int init_budget = bud(ctA);
    cout << "Fresh ciphertext:  budget=" << init_budget
         << " bits  chain_index="
         << ctx.get_context_data(ctA.parms_id())->chain_index() << "\n\n";

    // ══════════════════════════════════════════════════════════════════════
    //  PART 1 — Per-operation benchmarks
    // ══════════════════════════════════════════════════════════════════════
    cout << "══════════════════════════════════════════════════════\n"
         << " Part 1: Per-operation noise and timing benchmarks\n"
         << "══════════════════════════════════════════════════════\n";

    vector<Row> rows;

    // ── CT+CT addition ────────────────────────────────────────────────────
    {
        Ciphertext c = ctA;
        int b0 = bud(c); auto t0 = Clock::now();
        eval.add_inplace(c, ctB);
        rows.push_back({"CT+CT add", b0, bud(c), us_since(t0)});
    }

    // ── CT×PT multiply ────────────────────────────────────────────────────
    {
        Ciphertext c = ctA;
        int b0 = bud(c); auto t0 = Clock::now();
        eval.multiply_plain_inplace(c, ptC);
        rows.push_back({"CT×PT multiply", b0, bud(c), us_since(t0)});
    }

    // ── Single row rotation ───────────────────────────────────────────────
    {
        Ciphertext c = ctA, out;
        int b0 = bud(c); auto t0 = Clock::now();
        eval.rotate_rows(c, 1, gk, out);
        rows.push_back({"CT rotate_rows (step=1)", b0, bud(out), us_since(t0)});
    }

    // ── CT×CT multiply only (no relin) ────────────────────────────────────
    {
        Ciphertext out;
        int b0 = bud(ctA); auto t0 = Clock::now();
        eval.multiply(ctA, ctB, out);
        rows.push_back({"CT×CT multiply (no relin)", b0, bud(out), us_since(t0)});
        // relin separately on the same result
        int b1 = bud(out); t0 = Clock::now();
        eval.relinearize_inplace(out, rk);
        rows.push_back({"  └─ relinearize_inplace", b1, bud(out), us_since(t0)});
    }

    // ── CT×CT multiply+relin (combined, the standard single operation) ─────
    {
        Ciphertext out;
        int b0 = bud(ctA); auto t0 = Clock::now();
        eval.multiply(ctA, ctB, out);
        eval.relinearize_inplace(out, rk);
        rows.push_back({"CT×CT mul+relin (combined)", b0, bud(out), us_since(t0)});
    }

    // ── mod_switch_to_next (standalone) ──────────────────────────────────
    {
        Ciphertext c = ctA;
        int b0 = bud(c); auto t0 = Clock::now();
        eval.mod_switch_to_next_inplace(c);
        rows.push_back({"mod_switch_to_next", b0, bud(c), us_since(t0)});
    }

    // ── CT×CT mul+relin+mod_switch (one full level) ───────────────────────
    {
        Ciphertext out;
        int b0 = bud(ctA); auto t0 = Clock::now();
        eval.multiply(ctA, ctB, out);
        eval.relinearize_inplace(out, rk);
        eval.mod_switch_to_next_inplace(out);
        rows.push_back({"CT×CT mul+relin+mod_switch (1 level)", b0, bud(out), us_since(t0)});
    }

    // ── rotation_and_add (sum 100 slots, ~7 rot+add calls) ────────────────
    {
        Ciphertext c = ctA;
        int b0 = bud(c); auto t0 = Clock::now();
        Ciphertext out = rot_and_add(eval, c, gk);
        rows.push_back({"rotation_and_add(100 slots, ~7 rot+add)", b0, bud(out), us_since(t0)});
    }

    // ── CT×CT + relin + rotation_and_add + mod_switch (partition step) ───
    {
        Ciphertext out;
        int b0 = bud(ctA); auto t0 = Clock::now();
        eval.multiply(ctA, ctB, out);
        eval.relinearize_inplace(out, rk);
        out = rot_and_add(eval, out, gk);
        eval.mod_switch_to_next_inplace(out);
        rows.push_back({"CT×CT+relin+rot_add+mod_switch (partition)", b0, bud(out), us_since(t0)});
    }

    print_table(rows);

    // ══════════════════════════════════════════════════════════════════════
    //  PART 2 — Protocol critical-path simulation
    //  (Iris, depth=6: one representative path through the tree)
    // ══════════════════════════════════════════════════════════════════════
    cout << "\n"
         << "══════════════════════════════════════════════════════\n"
         << " Part 2: Protocol critical-path simulation (depth=6)\n"
         << "══════════════════════════════════════════════════════\n\n";

    auto track = [&](const string &label, const Ciphertext &c) {
        cout << "  " << left << setw(60) << label
             << " budget=" << right << setw(4) << bud(c)
             << " bits  chain=" << ctx.get_context_data(c.parms_id())->chain_index()
             << "\n";
    };

    // Fresh inputs (simulate inputs_X and inputs_Y at full chain)
    Ciphertext ct_X = make_ct(1);   // one-hot encoded feature (0/1 values)
    Ciphertext ct_Y = make_ct(1);   // label indicator (0/1 values)
    track("inputs_X / inputs_Y (fresh):", ct_X);

    // ── Preprocessing ─────────────────────────────────────────────────────
    cout << "\n[Preprocessing]\n";

    // rotation_and_add on inputs_X → partitioned (no multiply depth)
    {
        Ciphertext t0 = Clock::now();
        auto t_start = Clock::now();
        Ciphertext partitioned = rot_and_add(eval, ct_X, gk);
        long long dt = us_since(t_start);
        track("partitioned (rotation_and_add on X):", partitioned);
        cout << "    ↳ time=" << dt << " µs\n";

        // preprocess_label: CT×PT on inputs_Y + rotation_and_fill (no mul depth)
        Ciphertext processed_labels = ct_Y;
        eval.multiply_plain_inplace(processed_labels, ptC); // simulate CT×PT extraction
        track("processed_labels (CT×PT on Y):", processed_labels);

        // CT×CT (partitioned × processed_labels) + relin + mod_switch → depth=1
        t_start = Clock::now();
        Ciphertext partitioned_labels;
        eval.multiply(partitioned, processed_labels, partitioned_labels);
        eval.relinearize_inplace(partitioned_labels, rk);
        eval.mod_switch_to_next_inplace(partitioned_labels);
        dt = us_since(t_start);
        track("partitioned_labels (CT×CT+relin+ms):", partitioned_labels);
        cout << "    ↳ time=" << dt << " µs\n";

        // Carry these into Phase 2
        ct_X = partitioned;
        ct_Y = partitioned_labels;
    }

    // ── Tree training (depth = 6 levels) ──────────────────────────────────
    cout << "\n[Tree training]\n";

    // Selection vector starts fresh (encrypted zero/one)
    Ciphertext sel_vec = make_ct(1);
    track("sel_vec (fresh):", sel_vec);

    for (int d = 0; d < DEPTH; d++) {
        cout << "\n  -- Level " << d << " --\n";

        // update_selection_vector:
        //   CT×PT (multiply by threshold indicator) + CT×CT × sel_vec + relin + ms
        {
            // CT×PT part (no depth cost)
            Ciphertext threshold_data = ct_X; // simulate threshold extraction
            eval.mod_switch_to_inplace(threshold_data, sel_vec.parms_id());
            eval.multiply_plain_inplace(threshold_data, ptC);
            track("  threshold_data (CT×PT, no depth cost):", threshold_data);

            // CT×CT (sel_vec × threshold) + relin + mod_switch
            auto t_start = Clock::now();
            Ciphertext new_sel;
            eval.multiply(sel_vec, threshold_data, new_sel);
            eval.relinearize_inplace(new_sel, rk);
            eval.mod_switch_to_next_inplace(new_sel);
            long long dt = us_since(t_start);
            sel_vec = new_sel;
            track("  sel_vec after CT×CT+relin+ms:", sel_vec);
            cout << "      ↳ time=" << dt << " µs\n";
        }

        // Check if we still have enough chain depth for partition step
        if (ctx.get_context_data(sel_vec.parms_id())->chain_index() < 1) {
            cout << "  [chain exhausted at depth " << d << ", stopping]\n";
            break;
        }

        // perform_partition_for_node:
        //   CT×CT (partitioned × sel_vec) + relin + rotation_and_add + mod_switch
        {
            Ciphertext part = ct_X;
            eval.mod_switch_to_inplace(part, sel_vec.parms_id());
            auto t_start = Clock::now();
            Ciphertext pnode;
            eval.multiply(part, sel_vec, pnode);
            eval.relinearize_inplace(pnode, rk);
            pnode = rot_and_add(eval, pnode, gk);
            eval.mod_switch_to_next_inplace(pnode);
            long long dt = us_since(t_start);
            track("  partition_node (CT×CT+relin+rot_add+ms):", pnode);
            cout << "      ↳ time=" << dt << " µs\n";
        }

        // CT×CT (partition_labels × sel_vec) + relin + rotation_and_add + mod_switch
        {
            Ciphertext lbl = ct_Y;
            eval.mod_switch_to_inplace(lbl, sel_vec.parms_id());
            auto t_start = Clock::now();
            Ciphertext lnode;
            eval.multiply(lbl, sel_vec, lnode);
            eval.relinearize_inplace(lnode, rk);
            lnode = rot_and_add(eval, lnode, gk);
            eval.mod_switch_to_next_inplace(lnode);
            long long dt = us_since(t_start);
            track("  label_node    (CT×CT+relin+rot_add+ms):", lnode);
            cout << "      ↳ time=" << dt << " µs\n";
        }
    }

    // ── Vec-mat multiplication ─────────────────────────────────────────────
    cout << "\n[Vec-mat multiplication]\n";

    // inputs_Y[0] is the original label matrix (fresh, not the processed one)
    // We mod-switch it and a fresh vector ciphertext to chain_index=1
    Ciphertext ct_v   = make_ct(2);
    Ciphertext ct_mat = make_ct(1);   // simulates inputs_Y[0]
    while (ctx.get_context_data(ct_v.parms_id())->chain_index() > 1)
        eval.mod_switch_to_next_inplace(ct_v);
    while (ctx.get_context_data(ct_mat.parms_id())->chain_index() > 1)
        eval.mod_switch_to_next_inplace(ct_mat);
    track("ct_v and ct_Y (mod-switched to chain=1):", ct_v);

    // Replication: LABEL_SIZE-1 = 2 rotations+adds
    {
        auto t_start = Clock::now();
        Ciphertext ct_rep = ct_v;
        for (int j = 1; j < LABEL_SIZE; j++) {
            Ciphertext tmp;
            eval.rotate_rows(ct_v, -j * DATA_SIZE, gk, tmp);
            eval.add_inplace(ct_rep, tmp);
        }
        long long dt = us_since(t_start);
        track("ct_rep after replication (2 rot+add):", ct_rep);
        cout << "    ↳ time=" << dt << " µs\n";

        // CT×CT (ct_rep × ct_mat) + relin
        t_start = Clock::now();
        Ciphertext ct_prod;
        eval.multiply(ct_rep, ct_mat, ct_prod);
        eval.relinearize_inplace(ct_prod, rk);
        dt = us_since(t_start);
        track("ct_prod after CT×CT+relin (vec×mat):", ct_prod);
        cout << "    ↳ time=" << dt << " µs\n";

        // rotation_and_add to compute column sums
        t_start = Clock::now();
        Ciphertext ct_result = rot_and_add(eval, ct_prod, gk);
        dt = us_since(t_start);
        track("ct_result after rotation_and_add:", ct_result);
        cout << "    ↳ time=" << dt << " µs\n";

        cout << "\n  Final vec-mat budget: " << bud(ct_result) << " bits  "
             << (bud(ct_result) > 0 ? "→ PASS (decryptable)" : "→ FAIL (budget exhausted)")
             << "\n";
    }

    // ── Summary ───────────────────────────────────────────────────────────
    cout << "\n══════════════════════════════════════════════════════\n"
         << " Summary\n"
         << "══════════════════════════════════════════════════════\n"
         << "  Plain modulus:      " << t60.value() << "  (" << t60.bit_count() << " bits)\n"
         << "  Computation primes: 9 × 60 bits = 540 bits\n"
         << "  Special prime:      1 × 60 bits\n"
         << "  Initial budget:     " << init_budget << " bits\n"
         << "  Budget per CT×CT multiply:      ~"
         << (init_budget - rows[5].b1) << " bits  (combined mul+relin)\n"
         << "  Budget per mod_switch:          ~"
         << (rows[5].b1 - rows[6].b1) << " bits\n"
         << "  Budget per full level (mul+ms): ~"
         << (init_budget - rows[6].b1) << " bits  (= one prime = 60 bits)\n"
         << "  Max supported depth:            "
         << ((init_budget - 20) / 60) << " levels  (with ≥20 bit safety margin)\n";

    return 0;
}
