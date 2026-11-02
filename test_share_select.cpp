// Selection-vector updates with the selection computed in MPC (share_select.h), without the node processing:
// a depth-`depth` tree walk with random splits on random data, every selection vector checked slot by slot against plaintext
// training, plus the cost of the per-node update compared with the plaintext-split update of the original code
// (update_selection_vector in util.h: mask a block of the stored partitions, fill, multiply, for both children).
//
// usage: ./test_share [N n A V depth M tiled prime_bits]
//   iris: ./test_share 16384 100 4 8 6     wine: 16384 119 13 8 6     cancer: 16384 380 30 8 6     digits: 16384 1203 64 8 6
#include "seal/seal.h"
#include "global.h"
#include "util.h"
#include "share_select.h"
#include <random>
#include <set>

using namespace seal;
using namespace std;

int main(int argc, char* argv[]) {
    auto arg = [&](int i, int def) { return argc > i ? stoi(argv[i]) : def; };
    poly_modulus_degree_glb = arg(1, 16384);
    data_size_glb = arg(2, 100);
    attr_size_glb = arg(3, 4);
    value_size_glb = arg(4, 8);
    const int depth = arg(5, 6), M = arg(6, 10);
    const bool tiled = arg(7, 0) != 0;
    const int prime_bits = arg(8, 34);
    const int n = data_size_glb;
    const uint64_t p = 65537;

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_modulus_degree_glb);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree_glb, vector<int>(depth < 6 ? 8 : 9, prime_bits)));
    parms.set_plain_modulus(p);
    SEALContext context(parms, true, sec_level_type::none);
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, keygen.secret_key());
    BatchEncoder batch_encoder(context);

    ShareSelCtx c;
    ssc_init(c, n, M, tiled, p, batch_encoder);
    // steps of the plaintext-split update: fill with stride n*V (rotation_and_fill), and the row / column moves of the block
    vector<int> steps = ssc_rotation_steps(c);
    int iter = 1;
    while (iter < attr_size_glb) iter *= 2;
    for (int k = iter / 2; k >= 1; k /= 2) steps.push_back((int) (((size_t) k * n * value_size_glb) % (poly_modulus_degree_glb / 2)));
    steps.push_back(n);
    std::set<int> uniq(steps.begin(), steps.end());
    uniq.erase(0);
    steps.assign(uniq.begin(), uniq.end());
    steps.push_back(0);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps, gal_keys);

    cout << "N=" << poly_modulus_degree_glb << " n=" << n << " A=" << attr_size_glb << " V=" << value_size_glb << " depth=" << depth
         << ", " << M << " servers, " << (tiled ? "tiled (1 node" : "packed (" + to_string(c.G) + " nodes") << " per share ciphertext), "
         << context.first_context_data()->parms().coeff_modulus().size() << " primes of " << prime_bits << " bits\n";

    mt19937 rng(7);
    vector<vector<int>> x(n, vector<int>(attr_size_glb));
    for (auto& row : x) for (auto& v : row) v = rng() % value_size_glb;
    const int num_internal = (1 << (depth - 1)) - 1;
    vector<int> split_attr(num_internal), split_val(num_internal);
    for (int i = 0; i < num_internal; i++) {
        split_attr[i] = rng() % attr_size_glb;
        split_val[i] = 1 + rng() % (value_size_glb - 1);
    }

    vector<Ciphertext> S((1 << depth) - 1);
    encryptor.encrypt(c.ones_pl, S[0]);
    mt19937_64 share_rng(99);
    double extract_us = 0, children_us = 0;
    for (int d = 0; d < depth - 1; d++) {
        parms_id_type use_level = d == 0 ? context.first_context_data()->next_context_data()->parms_id() : S[(1 << d) - 1].parms_id();
        parms_id_type enc_level = tiled ? use_level : context.get_context_data(use_level)->prev_context_data()->parms_id();
        int groups = ((1 << d) + c.G - 1) / c.G;
        double enc0 = c.enc_us, sum0 = c.sum_us;
        long long bytes0 = c.bytes_per_server;
        double ex0 = extract_us, ch0 = children_us;
        for (int gi = 0; gi < groups; gi++) {
            vector<vector<int>> sels;
            for (int g = 0; g < c.G && gi * c.G + g < (1 << d); g++) {
                int node = (1 << d) - 1 + gi * c.G + g;
                sels.push_back(ssc_plain_selection(x, split_attr[node], split_val[node]));
            }
            Ciphertext U = ssc_encrypt_group(c, sels, enc_level, share_rng, batch_encoder, encryptor, evaluator);
            for (int g = 0; g < (int) sels.size(); g++) {
                int nd = gi * c.G + g;
                auto t0 = chrono::high_resolution_clock::now();
                Ciphertext T = ssc_node_threshold_data(context, evaluator, c, gal_keys, U, g);
                auto t1 = chrono::high_resolution_clock::now();
                ssc_apply_children(S, T, d, nd, c, evaluator, relin_keys);
                auto t2 = chrono::high_resolution_clock::now();
                extract_us += chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
                children_us += chrono::duration_cast<chrono::microseconds>(t2 - t1).count();
            }
        }
        cout << "level " << d << " (" << (1 << d) << " nodes): " << groups << " share ciphertext(s) per server at chain index "
             << context.get_context_data(enc_level)->chain_index() << ", " << (c.bytes_per_server - bytes0) / 1024 << " KiB; encryption "
             << (c.enc_us - enc0) / M / 1000 << " ms per server, aggregation " << (c.sum_us - sum0) / 1000 << " ms; per node: extraction "
             << (extract_us - ex0) / (1 << d) / 1000 << " ms, children " << (children_us - ch0) / (1 << d) / 1000 << " ms\n";
    }
    int min_budget = 0;
    int wrong = ssc_verify_selection_vectors(S, split_attr, split_val, x, depth, decryptor, batch_encoder, c, &min_budget);
    cout << "selection vectors of all " << (1 << depth) - 2 << " nodes below the root (every slot of every copy): "
         << (wrong ? "WRONG slots: " + to_string(wrong) : string("ok")) << ", lowest budget " << min_budget << " bits\n";

    // the plaintext-split update of the original code on the same chain, at the level of depth 1 (per node, both children)
    {
        Ciphertext part, parent = S[1], child;
        vector<uint64_t> rnd(poly_modulus_degree_glb);
        for (auto& v : rnd) v = rng() % 2;
        Plaintext pt;
        batch_encoder.encode(rnd, pt);
        encryptor.encrypt(pt, part);
        evaluator.mod_switch_to_inplace(part, parent.parms_id());
        vector<uint64_t> mask(poly_modulus_degree_glb, 0);
        fill(mask.begin(), mask.begin() + n, 1);
        Plaintext mask_pl;
        batch_encoder.encode(mask, mask_pl);
        const int reps = 4;
        auto t0 = chrono::high_resolution_clock::now();
        for (int r = 0; r < reps; r++) {
            for (int i = 0; i < 2; i++) {
                Ciphertext td;
                evaluator.multiply_plain(part, mask_pl, td);
                Ciphertext out = td, tmp;
                for (int k = iter / 2; k >= 1; k /= 2) {
                    evaluator.rotate_rows(out, (int) (((size_t) k * n * value_size_glb) % (poly_modulus_degree_glb / 2)), gal_keys, tmp);
                    evaluator.add_inplace(out, tmp);
                }
                evaluator.multiply(parent, out, child);
                evaluator.relinearize_inplace(child, relin_keys);
                evaluator.mod_switch_to_next_inplace(child);
            }
        }
        auto t1 = chrono::high_resolution_clock::now();
        // the same node with the selection from shares (packed), same level
        double share_node = 0;
        if (!tiled) {
            vector<vector<int>> sels(c.G, ssc_plain_selection(x, split_attr[1], split_val[1]));
            Ciphertext U = ssc_encrypt_group(c, sels, context.get_context_data(parent.parms_id())->prev_context_data()->parms_id(), share_rng,
                                             batch_encoder, encryptor, evaluator);
            vector<Ciphertext> Sv(7);
            Sv[1] = parent;
            auto s0 = chrono::high_resolution_clock::now();
            for (int r = 0; r < reps; r++) {
                Ciphertext T = ssc_node_threshold_data(context, evaluator, c, gal_keys, U, (r * 37) % c.G);
                ssc_apply_children(Sv, T, 1, 0, c, evaluator, relin_keys);
            }
            auto s1 = chrono::high_resolution_clock::now();
            share_node = chrono::duration_cast<chrono::microseconds>(s1 - s0).count() / (double) reps / 1000;
        }
        cout << "per-node update at depth 1: plaintext split (original code) "
             << chrono::duration_cast<chrono::microseconds>(t1 - t0).count() / (double) reps / 1000 << " ms";
        if (!tiled) cout << ", selection from shares " << share_node << " ms";
        cout << "\n";
    }
    return wrong != 0;
}
