#include "utils.h"
#include "decision_tree_node.h"
#include "tree_eval_server.h"
#include "soft_if.h"
#include "fhe_client.h"
#include "tree_train_server.h"
#include <fstream>
#include <utility>
#include <chrono>
#include <cstring>

#undef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT

using Clock = chrono::high_resolution_clock;

struct DatasetCfg {
    string train_file;
    int features;
    int labels;
};

static const map<string, DatasetCfg> DATASETS = {
    {"iris",   {"../data/iris_train.csv",    4,  3}},
    {"wine",   {"../data/wine_train.csv",   13,  3}},
    {"cancer", {"../data/cancer_train.csv", 30,  2}},
    {"digits", {"../data/digits_train.csv", 64, 10}},
};

int main(int argc, char* argv[]) {
    string dataset     = "iris";
    int    depth       = 4;
    int    degree      = 16;  // soft-if polynomial degree: 8, 16, or 32

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--dataset") == 0 && i+1 < argc) dataset = argv[++i];
        else if (strcmp(argv[i], "--depth")   == 0 && i+1 < argc) depth   = stoi(argv[++i]);
        else if (strcmp(argv[i], "--degree")  == 0 && i+1 < argc) degree  = stoi(argv[++i]);
    }

    auto it = DATASETS.find(dataset);
    if (it == DATASETS.end()) {
        cerr << "[ERROR] Unknown dataset: " << dataset
             << "  (choices: iris wine cancer digits)\n";
        return 1;
    }
    const DatasetCfg& cfg = it->second;

    cout << "============================================================\n"
         << " Akavia et al. 2022 — Privacy-Preserving Decision Trees\n"
         << "  dataset  : " << dataset   << "\n"
         << "  depth    : " << depth     << "\n"
         << "  degree   : " << degree    << "\n"
         << "  features : " << cfg.features << "\n"
         << "  labels   : " << cfg.labels   << "\n"
         << "============================================================\n";

    // CKKS parameters fixed to match the paper's setup
    int polyModulusDegree = 15;   // ring dimension 2^15 = 32768
    int scale = 50;               // scale 2^50
    vector<int> bitSizes = { 60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60 };
    double split_step_size = 0.5;
    string plain_tree_path = "/tmp/akavia_plain_tree.txt";
    stringstream data_stream;

    // ── Training ─────────────────────────────────────────────────────────
    cout << "\n[train] Initialising client and encrypting data...\n";
    auto t0 = Clock::now();

    fhe_client client(scale, polyModulusDegree, bitSizes, split_step_size);
    string train_file = cfg.train_file;
    auto enc_data = client.get_encrypted_data(train_file, cfg.features, cfg.labels);
    PublicKeys pk = client.get_public_keys();

    cout << "[train] Server training (depth=" << depth << ")...\n";
    tree_train_server server(scale, polyModulusDegree, bitSizes, pk, client,
                             cfg.features, cfg.labels, depth, degree,
                             enc_data, split_step_size);
    server.execute(data_stream);

    cout << "[train] Client decrypting and saving tree...\n";
    client.decrypt_and_save_tree(data_stream, plain_tree_path);

    auto t1 = Clock::now();
    long long ms = chrono::duration_cast<chrono::milliseconds>(t1 - t0).count();

    cout << "\n============================================================\n"
         << " Training complete.  Wall-clock: " << ms << " ms\n"
         << "============================================================\n";

    return 0;
}
