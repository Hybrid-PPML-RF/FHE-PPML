#pragma once
// Selection-vector update with a private model, with the selection computed in MPC (default path of main_integrity.cpp).
//
// ------------------------------------------------------------------------------------------------------------------
// MPC side (simulated here; its cost is counted by mpc/Programs/Source/bench_onehot.py)
// ------------------------------------------------------------------------------------------------------------------
//   BestSplit keeps the comparison bit of every merge of its argmax tournament and expands the bits top-down into the one-hot
//   <e*_l> of the best of the K candidates of node l (one multiplication per merge).  The servers hold Shamir shares <X'> of the
//   processed data (converted once), so the left-child indicator of node l is a linear function of shares:
//       <sel_l>[i] = sum_k e*_l[k] <X'_{b(k)}>[i]      (b(k): block of candidate k, i.e. [x_{i, attr_k} < theta_k])
//   i.e. n inner products, one degree reduction each.  Nothing about the split is opened.
//
// ------------------------------------------------------------------------------------------------------------------
// FHE side (this file)
// ------------------------------------------------------------------------------------------------------------------
//   1. every server converts its shares of sel to additive shares mod p (ToAdditive) and encrypts them, PACKED: node g of a group
//      sits in region g = (row g / R, position q = g mod R), slots [q n, (q+1) n) of that batching row, R = floor((N/2) / n),
//      so G = 2R nodes per ciphertext.  The server encrypts at the level just above the one at which the selection is used
//      (the mask below takes that level), so a share ciphertext has as few primes as possible.
//   2. the sum of the M share ciphertexts encrypts sel_l of all nodes of the group (M - 1 additions).
//   3. per node: mask region g (1 plaintext product, then one mod switch), move it to slot 0 of its row (popcount(q) rotations by
//      2^i n), copy it into the other row (1 column rotation), tile it with period n (O(log R) rotations): T, the left-child
//      indicator in the layout of oblivious_multi.h (period n in both rows).
//   4. S_left = S_parent * T, S_right = S_parent - S_left   (root: S_left = T, S_right = 1 - T, no multiplication).
//   No partition ciphertexts, no equality test, no second ring: the modulus chain is the one of the plaintext-split path.
//   Variant `tiled` (G = 1): every server encrypts its share already tiled (one ciphertext per node at the level of use), step 3
//   disappears, at G times the communication.

#include "util.h"
#include <random>

struct ShareSelCtx {
    int n = 0;                       // datapoints
    int M = 10;                      // servers, each one encrypts its additive share
    bool tiled = false;              // one ciphertext per node, already tiled (no extraction)
    int R = 0;                       // regions of n slots per batching row = copies of the n-bit vector per row (tile)
    int G = 0;                       // nodes per share ciphertext: 2R (packed) or 1 (tiled)
    uint64_t p = 65537;
    vector<Plaintext> region_mask;   // [g]: 1 on the n slots of region g (packed)
    Plaintext ones_pl;               // all ones (the root's selection vector is public)
    // statistics of the share ciphertexts
    double enc_us = 0, sum_us = 0;   // all servers' encryptions (sequential here), aggregation
    long long cts_per_server = 0, bytes_per_server = 0;
};

inline size_t ssc_row_len() { return poly_modulus_degree_glb / 2; }

inline size_t ssc_region_slot(const ShareSelCtx& c, int g) {
    return (size_t) (g / c.R) * ssc_row_len() + (size_t) (g % c.R) * c.n;
}

inline void ssc_init(ShareSelCtx& c, int n, int M, bool tiled, uint64_t p, BatchEncoder& batch_encoder) {
    c.n = n;
    c.M = M;
    c.tiled = tiled;
    c.p = p;
    c.R = (int) (ssc_row_len() / n);
    c.G = tiled ? 1 : 2 * c.R;
    vector<uint64_t> ones(poly_modulus_degree_glb, 1);
    batch_encoder.encode(ones, c.ones_pl);
    if (!tiled) {
        c.region_mask.resize(c.G);
        for (int g = 0; g < c.G; g++) {
            vector<uint64_t> m(poly_modulus_degree_glb, 0);
            fill(m.begin() + ssc_region_slot(c, g), m.begin() + ssc_region_slot(c, g) + n, 1);
            batch_encoder.encode(m, c.region_mask[g]);
        }
    }
}

// Galois steps of the extraction (step 0: column rotation)
inline vector<int> ssc_rotation_steps(const ShareSelCtx& c) {
    vector<int> steps = {0};
    if (!c.tiled) {
        for (int k = 1; k < c.R; k *= 2) steps.push_back(k * c.n);
        for (int s : obl_window_sum_steps(c.R, c.n, -1)) steps.push_back(s);
    }
    return steps;
}

// slot vector of a group: the n-bit vectors sels[g] of its nodes, packed (region g) or tiled (period n, both rows, one node)
inline vector<uint64_t> ssc_slot_vector(const ShareSelCtx& c, const vector<vector<int>>& sels) {
    vector<uint64_t> v(poly_modulus_degree_glb, 0);
    if (c.tiled) {
        for (int row = 0; row < 2; row++)
            for (int t = 0; t < c.R; t++)
                for (int i = 0; i < c.n; i++) v[row * ssc_row_len() + (size_t) t * c.n + i] = sels[0][i];
    } else {
        for (int g = 0; g < (int) sels.size(); g++)
            for (int i = 0; i < c.n; i++) v[ssc_region_slot(c, g) + i] = sels[g][i];
    }
    return v;
}

// Steps 1-2 for one group: the M servers' additive shares mod p of the slot vector, each encrypted at `enc_level`, and their sum.
// (The shares are drawn here from the plaintext selection; in the protocol they are the outputs of ToAdditive.)
inline Ciphertext ssc_encrypt_group(ShareSelCtx& c, const vector<vector<int>>& sels, parms_id_type enc_level, mt19937_64& rng,
                                    BatchEncoder& batch_encoder, Encryptor& encryptor, Evaluator& evaluator) {
    vector<uint64_t> target = ssc_slot_vector(c, sels), last = target;
    Ciphertext sum;
    for (int s = 0; s < c.M; s++) {
        vector<uint64_t> share(poly_modulus_degree_glb);
        if (s + 1 < c.M) {
            for (size_t i = 0; i < share.size(); i++) {
                share[i] = rng() % c.p;
                last[i] = (last[i] + c.p - share[i]) % c.p;
            }
        } else {
            share = last;                                       // target minus all other shares
        }
        auto t0 = chrono::high_resolution_clock::now();
        Plaintext pt;
        batch_encoder.encode(share, pt);
        Ciphertext ct;
        encryptor.encrypt_zero(enc_level, ct);                  // fresh encryption directly at the level of use
        evaluator.add_plain_inplace(ct, pt);
        auto t1 = chrono::high_resolution_clock::now();
        if (s == 0) sum = ct;
        else evaluator.add_inplace(sum, ct);
        auto t2 = chrono::high_resolution_clock::now();
        c.enc_us += chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
        c.sum_us += chrono::duration_cast<chrono::microseconds>(t2 - t1).count();
        if (s == 0) {
            c.cts_per_server++;
            c.bytes_per_server += (long long) ct.save_size(compr_mode_type::none);
        }
    }
    return sum;
}

// Step 3 for node g of a group: T at the level `target` (the share ciphertext U sits one level above it when packed).
inline Ciphertext ssc_node_threshold_data(const SEALContext& context, Evaluator& evaluator, const ShareSelCtx& c,
                                          const GaloisKeys& gal_keys, const Ciphertext& U, int g) {
    if (c.tiled) return U;
    Ciphertext T;
    evaluator.multiply_plain(U, c.region_mask[g], T);
    evaluator.mod_switch_to_next_inplace(T);
    int q = g % c.R;
    for (int k = 1; k < c.R; k *= 2)
        if (q & k) evaluator.rotate_rows_inplace(T, k * c.n, gal_keys);    // region q -> slot 0 of its row
    Ciphertext other_row;
    evaluator.rotate_columns(T, gal_keys, other_row);                      // into both rows
    evaluator.add_inplace(T, other_row);
    return obl_window_sum(evaluator, T, c.R, c.n, -1, gal_keys);          // period n
}

// Step 4
inline void ssc_apply_children(vector<Ciphertext>& selection_vector, const Ciphertext& T, int cur_depth, int curr_node,
                               const ShareSelCtx& c, Evaluator& evaluator, const RelinKeys& relin_keys) {
    int parent_sel_ind = (1 << cur_depth) - 1 + curr_node;
    int child_sel_ind = parent_sel_ind * 2 + 1;
    if (cur_depth == 0) {
        selection_vector[child_sel_ind] = T;
        evaluator.negate(T, selection_vector[child_sel_ind + 1]);
        evaluator.add_plain_inplace(selection_vector[child_sel_ind + 1], c.ones_pl);
        return;
    }
    Ciphertext parent = selection_vector[parent_sel_ind], threshold_data = T;
    if (threshold_data.parms_id() != parent.parms_id()) evaluator.mod_switch_to_inplace(threshold_data, parent.parms_id());
    evaluator.multiply(parent, threshold_data, selection_vector[child_sel_ind]);
    evaluator.relinearize_inplace(selection_vector[child_sel_ind], relin_keys);
    evaluator.mod_switch_to_next_inplace(selection_vector[child_sel_ind]);
    evaluator.mod_switch_to_inplace(parent, selection_vector[child_sel_ind].parms_id());
    evaluator.sub(parent, selection_vector[child_sel_ind], selection_vector[child_sel_ind + 1]);
}

// left-child indicators of the nodes of a level (plaintext; what the MPC computes in shares)
inline vector<int> ssc_plain_selection(const vector<vector<int>>& x, int attr, int theta) {
    vector<int> sel(x.size());
    for (size_t i = 0; i < x.size(); i++) sel[i] = x[i][attr] < theta;
    return sel;
}

// decrypts the selection vectors of all nodes below the root and compares every copy of the tile with plaintext training
inline int ssc_verify_selection_vectors(const vector<Ciphertext>& selection_vector, const vector<int>& split_attr,
                                        const vector<int>& split_val, const vector<vector<int>>& x, int depth,
                                        Decryptor& decryptor, BatchEncoder& batch_encoder, const ShareSelCtx& c, int* min_budget = nullptr) {
    int num_nodes = (1 << depth) - 1, n = c.n;
    vector<vector<int>> expected(num_nodes, vector<int>(n, 0));
    fill(expected[0].begin(), expected[0].end(), 1);
    Plaintext pl;
    vector<uint64_t> dec;
    int wrong = 0;
    if (min_budget) *min_budget = 1 << 30;
    for (int parent = 0; parent < (1 << (depth - 1)) - 1; parent++) {
        for (int j = 0; j < n; j++) {
            bool in_left = x[j][split_attr[parent]] < split_val[parent];
            expected[2 * parent + 1][j] = expected[parent][j] && in_left;
            expected[2 * parent + 2][j] = expected[parent][j] && !in_left;
        }
        for (int ch = 2 * parent + 1; ch <= 2 * parent + 2; ch++) {
            if (min_budget) *min_budget = min(*min_budget, decryptor.invariant_noise_budget(selection_vector[ch]));
            decryptor.decrypt(selection_vector[ch], pl);
            batch_encoder.decode(pl, dec);
            for (int row = 0; row < 2; row++)
                for (int t = 0; t < c.R; t++)
                    for (int j = 0; j < n; j++)
                        if ((int) dec[row * ssc_row_len() + (size_t) t * n + j] != expected[ch][j]) wrong++;
        }
    }
    return wrong;
}
