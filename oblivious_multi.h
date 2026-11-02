// Oblivious selection-vector update for datasets whose packed left partitions P do not fit in one ciphertext
// (wine, cancer, digits; anything with A*V*n > N/2).  Generalizes util.h (single-ciphertext case, iris).
//
// ------------------------------------------------------------------------------------------------------------------
// Layout of P (the "x < theta" partitions of all attributes and thresholds)
// ------------------------------------------------------------------------------------------------------------------
//   block   b = a * (V-1) + (theta - 1),   a in [0,A), theta in [1,V-1],        B = A * (V-1) blocks
//   A block holds, for one chunk of n' datapoints, the indicator [x_{j,a} < theta]  (n' consecutive slots).
//   datapoints are cut in J = ceil(n / n') chunks (the last one is zero padded).
//   one ciphertext holds kk = 2 * rho' blocks (rho' = floor((N/2) / n') per batching row), block position p = b mod kk
//   at row p / rho', first slot (p mod rho') * n'.
//   P[jc][c] = the ciphertext of datapoint chunk jc and block group c = b div kk,   m_b = ceil(B / kk) groups.
//   n' = n gives one block per datapoint vector as in the single-ciphertext layout (J = 1); a smaller n' makes the selectors
//   (below) shorter and shares them between the J chunks (see omc_choose_chunk for the cost model).
//   P is the output of the preprocessing; here it is encrypted directly from the plaintext data (omc_encrypt_partitions), the
//   preprocessing of the repo is only a runtime simulation for these sizes (its one-hot encoding does not even fit the layout).
//
// ------------------------------------------------------------------------------------------------------------------
// Pipeline for the splits (attr_g, theta_g) of a group of G nodes  (equality test in the big ring, as in util.h)
// ------------------------------------------------------------------------------------------------------------------
//   1. COMPACT one-hot over the blocks (one slot per block, a region of B slots per node, G = floor((N/2)/B) nodes per
//      ciphertext):  u_g[b] = selector_scale * [b == b*_g].   Product tree on the digit differences (attribute, threshold),
//      exactly the polynomial test of util.h, evaluated in the big ring and ring-switched (1 ciphertext per group of G nodes --
//      instead of one per node and per P-ciphertext).  Every node is stored in BOTH batching rows, the copy in row 1 shifted by
//      rho' slots (row 1 slot s holds what row 0 slot s + rho' holds): the blocks of row 1 of a P-ciphertext are the blocks
//      rho' positions further along, so one rotation of this ciphertext serves the stretch of both rows.
//   2. per node: move the node's region to region 0 (1 rotation).  Chunk it per P-ciphertext c (u[c*kk .. c*kk+kk)): one rotation
//      by c*kk, then stretch every entry to the first slot of its block (baby-step giant-step over plaintext diagonals, both rows
//      at once: 1 level), then fill the n' slots of the block with ones (rotation_and_add, no level) -> selector S_c, shared by
//      all datapoint chunks.
//   3. E_jc = sum_c S_c * P[jc][c]   (m_b multiplications without relinearization, one relinearization per chunk, 1 level)
//   4. per chunk: fold the blocks of a row into block 0 and mask block 0 of both rows (1 level, the mask also removes the selector
//      scale), put the chunks next to each other (one rotation by -n' each, Horner), add the two rows (one column rotation) and tile
//      the n-bit vector over the batching rows (period n): T, the left-child indicator.
//   5. S_left = S_parent * T, S_right = S_parent - S_left   (root: S_left = T, S_right = 1 - T, no multiplication).
//   Levels after the ring switch: stretch, P, mask, and one S*T per further tree level (one more than the single-ciphertext layout).

#pragma once
#include "util.h"
#include <cmath>
#include <functional>

struct ObliviousMultiCtx {
    int n = 0, A = 0, V = 0;                 // datapoints, attributes, values
    int nprime = 0, J = 0;                   // datapoint chunk size n', number of chunks
    int B = 0;                               // blocks: A * (V-1)
    int rho_p = 0, kk = 0, m_b = 0;          // blocks per row / per ciphertext, ciphertexts per chunk
    int bs = 0, gs = 0;                      // baby-step / giant-step counts of the stretch (bs * gs >= rho_p)
    int rho_c = 0, G = 0;                    // compact regions per row = nodes per compact ciphertext (each node is stored in both rows)
    int rho_n = 0;                           // copies of the n-bit selection vector per batching row
    uint64_t selector_scale = 1;
    ObliviousSelCtx eq_small;                // compact index plaintexts (small ring) of the equality test; see oblivious_ring_switch_init
    Plaintext mask_chunk;                    // selector_scale^-1 on the n' first slots of both rows
    Plaintext ones_pl;                       // all slots 1 (the root's selection vector is public)
    vector<Plaintext> pt_diag;               // [g * bs + h]: 1 at slot h*n' + g*bs of both rows, NTT form at the top level of the data context
    vector<vector<Ciphertext>> P;            // [J][m_b]
};

inline size_t omc_row_len() { return poly_modulus_degree_glb / 2; }

// slot of the first element of block position p (0 <= p < kk) inside a ciphertext
inline size_t omc_block_slot(const ObliviousMultiCtx& c, int p) {
    return (size_t) (p / c.rho_p) * omc_row_len() + (size_t) (p % c.rho_p) * c.nprime;
}

// first slot of the compact region of node g (0 <= g < G) in a batching row: row 0 at g*B, row 1 shifted by rho' (cyclically)
inline size_t omc_region_base(const ObliviousMultiCtx& c, int g, int row) {
    const size_t R = omc_row_len();
    return (size_t) row * R + (((size_t) g * c.B + (row ? R - (size_t) c.rho_p : 0)) % R);
}

// Cost model (in units of one rotation of the data ring, ~30 ms at N = 16384 with 10 primes; a plaintext product + addition costs ~1.3 ms
// but streams a whole plaintext, so it is weighted 0.1 rotations per diagonal) for the chunk size n':
//   per P-ciphertext group c (m_b of them):  base rotation + baby + giant steps + fill of n' slots + the rho' diagonals of the stretch
//   per datapoint chunk (J of them):         relinearization + fold of a row (log rho') + mask + placement
// Measured at N = 16384: digits n' = 128 is 25% faster per node than 64, cancer n' = 128 is 17% faster than 64.
inline int omc_choose_chunk(int n, int A, int V, size_t N) {
    const size_t R = N / 2;
    const int B = A * (V - 1);
    int best = n;
    double best_cost = 1e300;
    vector<int> cands;
    for (int p = 1; p <= (int) R && p < n; p *= 2) cands.push_back(p);
    cands.push_back(n);
    for (int np : cands) {
        int rho = (int) (R / np);
        if (rho < 1 || rho > 1024) continue;                        // too many plaintext diagonals
        int kk = 2 * rho, m_b = (B + kk - 1) / kk, J = (n + np - 1) / np;
        int bs = (int) ceil(sqrt((double) rho)), gs = (rho + bs - 1) / bs;
        double per_group = 1.0 + bs + gs + log2((double) np) + 0.1 * rho;
        double per_chunk = log2((double) rho) + 4;
        double cost = m_b * per_group + J * per_chunk;
        if (cost <= best_cost + 1e-9) { best_cost = cost; best = np; }   // ties: the larger chunk (candidates ascend)
    }
    return best;
}

// Builds the geometry and the plaintexts.  nprime = 0: chosen by the cost model.
inline void omc_init(ObliviousMultiCtx& c, int n, int A, int V, const SEALContext& context, Evaluator& evaluator,
                     BatchEncoder& batch_encoder, int nprime = 0) {
    const size_t N = poly_modulus_degree_glb, R = N / 2;
    c.n = n; c.A = A; c.V = V;
    c.B = A * (V - 1);
    if ((size_t) c.B > R) throw invalid_argument("oblivious multi: A*(V-1) blocks must fit in one batching row (compact one-hot)");
    c.nprime = nprime ? nprime : omc_choose_chunk(n, A, V, N);
    c.J = (n + c.nprime - 1) / c.nprime;
    c.rho_p = (int) (R / c.nprime);
    c.kk = 2 * c.rho_p;
    c.m_b = (c.B + c.kk - 1) / c.kk;
    c.bs = (int) ceil(sqrt((double) c.rho_p));
    c.gs = (c.rho_p + c.bs - 1) / c.bs;
    c.rho_c = (int) (R / c.B);
    c.G = c.rho_c;
    c.rho_n = (int) (R / n);
    if (c.rho_n < 1) throw invalid_argument("oblivious multi: a datapoint vector must fit in one batching row");

    // compact equality test: slot of region g, block b  <->  (attribute, threshold) digits of b (in both rows, see omc_region_base)
    ObliviousSelCtx& eq = c.eq_small;
    eq.attr_size = A; eq.val_size = V; eq.equality_poly = true;
    vector<uint64_t> va(N, (uint64_t) A), vv(N, 0);
    for (int g = 0; g < c.G; g++) {
        for (int row = 0; row < 2; row++) {
            size_t base = omc_region_base(c, g, row), R_ = R;
            for (int b = 0; b < c.B; b++) {
                size_t slot = (size_t) row * R + ((base - (size_t) row * R + (size_t) b) % R_);
                va[slot] = b / (V - 1); vv[slot] = b % (V - 1) + 1;
            }
        }
    }
    batch_encoder.encode(va, eq.idx_attr_pl);
    batch_encoder.encode(vv, eq.idx_val_pl);
    // value of the polynomial selector at a match: prod_{c=1}^{V-1} (-c^2) * prod_{c=1}^{A-1} (-c^2) * (-A)  (mod t), see util.h
    const uint64_t t = context.first_context_data()->parms().plain_modulus().value();
    unsigned __int128 k = 1;
    for (int j = 1; j < V; j++) k = k * ((t - (uint64_t) j * j % t) % t) % t;
    for (int j = 1; j < A; j++) k = k * ((t - (uint64_t) j * j % t) % t) % t;
    k = k * ((t - (uint64_t) A % t) % t) % t;
    c.selector_scale = eq.selector_scale = (uint64_t) k;
    const uint64_t scale_inv = obl_pow_mod(c.selector_scale, t - 2, t);

    vector<uint64_t> vec(N, 0);
    for (int j = 0; j < c.nprime; j++) vec[j] = vec[R + j] = scale_inv;
    batch_encoder.encode(vec, c.mask_chunk);
    fill(vec.begin(), vec.end(), 1);
    batch_encoder.encode(vec, c.ones_pl);
    fill(vec.begin(), vec.end(), 0);

    // plaintext diagonals of the stretch (one set for both rows), NTT form at the level of the ring-switched compact ciphertext (= top)
    const parms_id_type top = context.first_parms_id();
    c.pt_diag.assign(c.gs * c.bs, Plaintext());
    for (int g = 0; g < c.gs; g++) {
        for (int h = 0; h < c.bs; h++) {
            int p0 = g * c.bs + h;
            if (p0 >= c.rho_p) break;
            size_t slot = (size_t) h * c.nprime + (size_t) g * c.bs;
            if (slot >= R) throw invalid_argument("oblivious multi: diagonal slot leaves its row");
            fill(vec.begin(), vec.end(), 0);
            vec[slot] = vec[R + slot] = 1;
            batch_encoder.encode(vec, c.pt_diag[p0]);
            evaluator.transform_to_ntt_inplace(c.pt_diag[p0], top);
        }
    }
}

// all Galois steps of the per-node pipeline (data ring)
inline vector<int> omc_rotation_steps(const ObliviousMultiCtx& c) {
    vector<int> steps;
    steps.push_back(0);                                                                       // column rotation (merging the rows)
    for (int k = 1; k < c.rho_c; k++) steps.push_back(obl_norm_step((long long) k * c.B));    // align a region
    for (int cc = 1; cc < c.m_b; cc++) steps.push_back(obl_norm_step((long long) cc * c.kk)); // chunk c of the compact vector
    for (int h = 1; h < c.bs; h++) steps.push_back(obl_norm_step(-(long long) h * (c.nprime - 1)));              // baby steps
    for (int g = 1; g < c.gs; g++) steps.push_back(obl_norm_step(-(long long) g * c.bs * (c.nprime - 1)));        // giant steps
    for (int s : obl_window_sum_steps(c.nprime, 1, -1)) steps.push_back(s);                  // fill the block
    for (int s : obl_window_sum_steps(c.rho_p, c.nprime, +1)) steps.push_back(s);            // fold the blocks of a row
    steps.push_back(obl_norm_step(-c.nprime));                                                // place the chunks
    for (int s : obl_window_sum_steps(c.rho_n, c.n, -1)) steps.push_back(s);                 // tile the selection vector
    return steps;
}

// plaintext slot vector of a group: region g carries values[g] in all its B slots (what the parties encrypt)
inline vector<uint64_t> omc_compact_vector(const ObliviousMultiCtx& c, const vector<int>& values) {
    vector<uint64_t> vec(poly_modulus_degree_glb, 0);
    const size_t R = omc_row_len();
    for (int g = 0; g < (int) values.size(); g++) {
        for (int row = 0; row < 2; row++) {
            size_t base = omc_region_base(c, g, row) - (size_t) row * R;
            for (int b = 0; b < c.B; b++) vec[(size_t) row * R + (base + b) % R] = values[g];
        }
    }
    return vec;
}

inline Ciphertext omc_encrypt_group_big(const ObliviousMultiCtx& c, const vector<int>& values, BatchEncoder& small_encoder,
                                        const Encryptor& enc_big, size_t N_big) {
    Plaintext p;
    small_encoder.encode(omc_compact_vector(c, values), p);
    Ciphertext ct;
    enc_big.encrypt(rsw::embed_plaintext(p, N_big), ct);
    return ct;
}

// P from the plaintext data  x[j][a] (value of attribute a of datapoint j), encrypted with the public key and switched to the level
// at which the selectors meet them (one level below the top).  Stand-in for the preprocessing output.
inline void omc_encrypt_partitions(ObliviousMultiCtx& c, const vector<vector<int>>& x, const SEALContext& context,
                                   Evaluator& evaluator, BatchEncoder& batch_encoder, const Encryptor& encryptor) {
    const size_t N = poly_modulus_degree_glb;
    c.P.assign(c.J, vector<Ciphertext>(c.m_b));
    vector<uint64_t> vec(N);
    for (int jc = 0; jc < c.J; jc++) {
        for (int cc = 0; cc < c.m_b; cc++) {
            fill(vec.begin(), vec.end(), 0);
            for (int p = 0; p < c.kk; p++) {
                int b = cc * c.kk + p;
                if (b >= c.B) break;
                int a = b / (c.V - 1), theta = b % (c.V - 1) + 1;
                size_t slot = omc_block_slot(c, p);
                for (int j = 0; j < c.nprime; j++) {
                    int i = jc * c.nprime + j;
                    if (i < c.n) vec[slot + j] = (x[i][a] < theta) ? 1 : 0;
                }
            }
            Plaintext pl;
            batch_encoder.encode(vec, pl);
            encryptor.encrypt(pl, c.P[jc][cc]);
            evaluator.mod_switch_to_next_inplace(c.P[jc][cc]);
        }
    }
}

// Steps 2-4 for node g of a compact group.  U: the ring-switched compact selector (top level of the data context).
// Returns T at chain index top - 3: the n-bit left-child indicator of the node, tiled with period n in both batching rows.
// selectors_out (testing): receives the selectors S_c, i.e. selector_scale on the n' slots of the selected block, 0 elsewhere.
inline Ciphertext omc_node_threshold_data(const SEALContext& context, Evaluator& evaluator, const ObliviousMultiCtx& c,
                                          const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const Ciphertext& U, int g,
                                          vector<Ciphertext>* selectors_out = nullptr) {
    // 2a. region g -> region 0 (both rows move together; row 1 keeps its shift by rho')
    Ciphertext u = U;
    if (g) evaluator.rotate_rows_inplace(u, obl_norm_step((long long) g * c.B), gal_keys);
    OBL_TRACE("aligned", u);

    // 2b. selectors S_c: entry u[c*kk + p] on the n' slots of block p (p < rho': row 0, p >= rho': row 1)
    vector<Ciphertext> selector(c.m_b);
    for (int cc = 0; cc < c.m_b; cc++) {
        // after this rotation: slot s of row 0 holds u[c*kk + s], slot s of row 1 holds u[c*kk + rho' + s]
        Ciphertext shifted = u;
        if (cc) evaluator.rotate_rows_inplace(shifted, obl_norm_step((long long) cc * c.kk), gal_keys);
        vector<Ciphertext> baby(c.bs);
        baby[0] = shifted;
        for (int h = 1; h < c.bs; h++)
            evaluator.rotate_rows(shifted, obl_norm_step(-(long long) h * (c.nprime - 1)), gal_keys, baby[h]);
        // slot p0 -> slot p0 * n' in both rows:  sum_g rot_{-g bs (n'-1)}( sum_h pt'_{g,h} * rot_{-h (n'-1)}(shifted) )
        // (blocks beyond the A*(V-1) real ones read junk but meet zeros of P)
        Ciphertext stretched;
        bool init = false;
        for (int gg = 0; gg < c.gs; gg++) {
            Ciphertext inner;
            bool inner_init = false;
            for (int h = 0; h < c.bs; h++) {
                int p0 = gg * c.bs + h;
                if (p0 >= c.rho_p) break;
                Ciphertext term;
                evaluator.multiply_plain(baby[h], c.pt_diag[p0], term);
                if (!inner_init) { inner = term; inner_init = true; }
                else evaluator.add_inplace(inner, term);
            }
            if (!inner_init) continue;
            if (gg) evaluator.rotate_rows_inplace(inner, obl_norm_step(-(long long) gg * c.bs * (c.nprime - 1)), gal_keys);
            if (!init) { stretched = inner; init = true; }
            else evaluator.add_inplace(stretched, inner);
        }
        evaluator.mod_switch_to_next_inplace(stretched);                           // the plaintext products cost one level
        selector[cc] = obl_window_sum(evaluator, stretched, c.nprime, 1, -1, gal_keys);   // n' ones per block
    }
    OBL_TRACE("selectors", selector[0]);
    if (selectors_out) *selectors_out = selector;

    // 3.-4. per datapoint chunk: E_jc = sum_c S_c * P[jc][c], fold the blocks of each row, mask block 0 of both rows, place
    Ciphertext T0;
    bool t_init = false;
    for (int jc = c.J - 1; jc >= 0; jc--) {
        Ciphertext e;
        for (int cc = 0; cc < c.m_b; cc++) {
            Ciphertext prod;
            evaluator.multiply(selector[cc], c.P[jc][cc], prod);                   // size 3, summed before the single relinearization
            if (cc == 0) e = prod;
            else evaluator.add_inplace(e, prod);
        }
        evaluator.relinearize_inplace(e, relin_keys);
        evaluator.mod_switch_to_next_inplace(e);
        e = obl_window_sum(evaluator, e, c.rho_p, c.nprime, +1, gal_keys);        // blocks of a row -> block 0 of the row
        evaluator.multiply_plain_inplace(e, c.mask_chunk);                         // block 0 of both rows, selector scale removed
        if (!t_init) { T0 = e; t_init = true; }
        else {
            evaluator.rotate_rows_inplace(T0, obl_norm_step(-c.nprime), gal_keys); // Horner: chunk jc goes to slots [jc n', (jc+1) n')
            evaluator.add_inplace(T0, e);
        }
    }
    Ciphertext other_row;                                                          // the selected block is in one of the two rows: add them
    evaluator.rotate_columns(T0, gal_keys, other_row);
    evaluator.add_inplace(T0, other_row);
    evaluator.mod_switch_to_next_inplace(T0);
    OBL_TRACE("chunks placed", T0);

    // n-bit vector (now in both rows) -> period n over the rows
    Ciphertext T = obl_window_sum(evaluator, T0, c.rho_n, c.n, -1, gal_keys);
    OBL_TRACE("threshold data", T);
    return T;
}

// Step 5: the children of tree node (cur_depth, curr_node):  S_left = S_parent * T,  S_right = S_parent - S_left.
// At the root (public all-ones vector) there is nothing to multiply: S_left = T, S_right = 1 - T (one level less).
inline void omc_apply_children(vector<Ciphertext>& selection_vector, const Ciphertext& T, int cur_depth, int curr_node,
                               const ObliviousMultiCtx& c, const SEALContext& context, Evaluator& evaluator, const RelinKeys& relin_keys) {
    int parent_sel_ind = (1 << cur_depth) - 1 + curr_node;
    int child_sel_ind = parent_sel_ind * 2 + 1;
    if (cur_depth == 0) {
        selection_vector[child_sel_ind] = T;
        evaluator.negate(T, selection_vector[child_sel_ind + 1]);
        evaluator.add_plain_inplace(selection_vector[child_sel_ind + 1], c.ones_pl);
        return;
    }
    Ciphertext parent = selection_vector[parent_sel_ind], threshold_data = T;
    obl_match_levels(context, evaluator, parent, threshold_data);
    evaluator.multiply(parent, threshold_data, selection_vector[child_sel_ind]);
    evaluator.relinearize_inplace(selection_vector[child_sel_ind], relin_keys);
    evaluator.mod_switch_to_next_inplace(selection_vector[child_sel_ind]);
    evaluator.mod_switch_to_inplace(parent, selection_vector[child_sel_ind].parms_id());
    evaluator.sub(parent, selection_vector[child_sel_ind], selection_vector[child_sel_ind + 1]);
}

// The whole group: equality test in the big ring, ring switch, per-node thresholds.  Returns one T per node of the group.
inline vector<Ciphertext> omc_group_threshold_data(const SEALContext& context, Evaluator& evaluator, const ObliviousMultiCtx& c,
                                                   const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                                                   const ObliviousRingSwitch& rs, const Ciphertext& ct_attr_big,
                                                   const Ciphertext& ct_val_big, int nodes) {
    Ciphertext selector_big = oblivious_selector_poly(*rs.ctx_big, *rs.eval_big, rs.oc_big, *rs.relin_big, ct_attr_big, ct_val_big);
    Ciphertext U = rsw::ring_switch(selector_big, *rs.ksk, *rs.ctx_big, context);
    OBL_TRACE("compact selector (ring-switched)", U);
    vector<Ciphertext> T(nodes);
    for (int g = 0; g < nodes; g++) T[g] = omc_node_threshold_data(context, evaluator, c, relin_keys, gal_keys, U, g);
    return T;
}

// plaintext reference: expected selection vectors of the first levels, compared with the decrypted ones in all copies of the tile
inline int omc_verify_selection_vectors(const vector<Ciphertext>& selection_vector, const vector<int>& split_attr,
                                        const vector<int>& split_val, const vector<vector<int>>& x, int depth,
                                        Decryptor& decryptor, BatchEncoder& batch_encoder, const ObliviousMultiCtx& c) {
    int num_nodes = (1 << depth) - 1, n = c.n;
    vector<vector<int>> expected(num_nodes, vector<int>(n, 0));
    fill(expected[0].begin(), expected[0].end(), 1);
    Plaintext pl;
    vector<uint64_t> dec;
    int wrong = 0;
    const size_t R = omc_row_len();
    for (int parent = 0; parent < (1 << (depth - 1)) - 1; parent++) {
        for (int j = 0; j < n; j++) {
            bool in_left = x[j][split_attr[parent]] < split_val[parent];
            expected[2 * parent + 1][j] = expected[parent][j] && in_left;
            expected[2 * parent + 2][j] = expected[parent][j] && !in_left;
        }
        for (int ch = 2 * parent + 1; ch <= 2 * parent + 2; ch++) {
            decryptor.decrypt(selection_vector[ch], pl);
            batch_encoder.decode(pl, dec);
            for (int row = 0; row < 2; row++)
                for (int tcopy = 0; tcopy < c.rho_n; tcopy++)
                    for (int j = 0; j < n; j++)
                        if ((int) dec[row * R + (size_t) tcopy * n + j] != expected[ch][j]) wrong++;
        }
    }
    return wrong;
}
