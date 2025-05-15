#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>
#include "seal/util/polyarithsmallmod.h"
#include "seal/seal.h"
#include "global.h"

using namespace seal::util;
using namespace std;
using namespace seal;

// for a length n vector, fill in into whole ciphertext
Ciphertext rotation_and_fill(Ciphertext& input, int length, Evaluator& evaluator, GaloisKeys& rot_keys) {
    Ciphertext output = input;

    int iter = 1;
    while (iter < attr_size_glb) { // round it to a power of 2
        iter *= 2;
    }

    Ciphertext tmp;
    while (iter > 1) {
        int step = (int) (iter / 2) * length; // march by half each time
        evaluator.rotate_rows(output, -step, rot_keys, tmp);
        evaluator.add_inplace(output, tmp);

        iter = iter / 2;
    }

    return output;
}

// for a length n vector, sum all chunks into one
Ciphertext rotation_and_add(Ciphertext& input, int length, int chunk_size, Evaluator& evaluator, GaloisKeys& rot_keys,
                            int offset = 0) {
    int iter = length / chunk_size;

    Ciphertext output = input;
    Ciphertext carry_over;
    bool carry_over_init = false;

    while (iter > 1) {
        int step = (int) (iter / 2) * chunk_size; // march by half each time
        Ciphertext tmp1, tmp2;
        evaluator.rotate_rows(output, step+offset, rot_keys, tmp1);
        if (iter % 2) {
            step = (iter - 1) * chunk_size;
            if (!carry_over_init) {
                evaluator.rotate_rows(output, step+offset, rot_keys, carry_over);
                carry_over_init = true;
            } else {
                evaluator.rotate_rows(output, step+offset, rot_keys, tmp2);
                evaluator.add_inplace(carry_over, tmp2);
            }
        }
        evaluator.add_inplace(output, tmp1);

        iter = iter / 2;
    }

    if (carry_over_init) {
        evaluator.add_inplace(output, carry_over);
    }

    return output;
}

void sample_one_hot_encoding_inputs(vector<Ciphertext>& inputs_X, vector<Ciphertext>& inputs_Y, int data_size,
                                    int attr_size, int val_size, int label_size, BatchEncoder& batch_encoder,
                                    Encryptor& encryptor) {
    
    vector<vector<vector<int>>> inputs(data_size);
    vector<vector<int>> labels(data_size);

    auto rng = std::make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed_glb));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint32_t> dist(0, val_size), dist_label(0, label_size);

    for (int i = 0; i < data_size; i++) {
        inputs[i].resize(attr_size);
        for (int j = 0; j < attr_size; j++) {
            inputs[i][j].resize(val_size, 0);
            inputs[i][j][dist(engine) % val_size] = 1; // randomly assign a value to the attribute
        }
    }
    for (int i = 0; i < data_size; i++) {
        labels[i].resize(label_size, 0);
        labels[i][dist_label(engine) % label_size] = 1; // randomly assign a label to the datapoints
    }

    // cout << inputs << endl;

    int num_of_ct = ceil((double) data_size * attr_size * val_size / (double) poly_modulus_degree_glb);
    cout << "Encoding inputs to " << num_of_ct << " ciphertexts...\n";

    inputs_X.resize(num_of_ct);
    inputs_Y.resize(1); // default

    // arranged by attributes --> values --> datapoints
    vector<uint64_t> x(poly_modulus_degree_glb, 0);
    Plaintext pl;
    for (int i = 0; i < num_of_ct; i++) {
        for (int j = 0; j < (int) poly_modulus_degree_glb; j++) {
            int attr_ind = j / (val_size * data_size);
            int val_ind = (j / data_size) % val_size;
            int data_ind = j % data_size;
            if (attr_ind < attr_size) {
                x[j] = inputs[data_ind][attr_ind][val_ind];
                // cout << data_ind << " , " << attr_ind << " , " << val_ind << " , " << x[j] << endl;
            }
        }
        batch_encoder.encode(x, pl);

        // for (int c = 0; c < (int) poly_modulus_degree_glb; c++) {
        //     cout << x[c] << " ";
        // }
        // cout << endl;
        encryptor.encrypt(pl, inputs_X[i]);
    }
    //arrange by label values --> datapoints
    for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
        int label_ind = i / data_size;
        int data_ind = i % data_size;
        if (label_ind < label_size) {
            x[i] = labels[data_ind][label_ind];
        } else {
            x[i] = 0;
        }
    }
    batch_encoder.encode(x, pl);
    encryptor.encrypt(pl, inputs_Y[0]);
}


// make #label_size label-ciphertexts, each encodes many chunks, each chunk has the first #data_size entry to be label indicators 
vector<Ciphertext> preprocess_label(vector<Ciphertext>& inputs_Y, Encryptor& encryptor, Evaluator& evaluator, GaloisKeys& gal_keys,
                                    int data_size = data_size_glb, int label_size = label_size_glb) {
    
    vector<Ciphertext> outputs(label_size);

    Plaintext pl_ext;
    pl_ext.resize(poly_modulus_degree_glb);
	pl_ext.parms_id() = parms_id_zero;

    for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
        pl_ext.data()[i] = 0;
    }

    for (int i = 0; i < label_size; i++) {
        for (int j = data_size * i; j < data_size * (i+1); j++) {
            pl_ext.data()[j] = 1;
        }
        evaluator.multiply_plain(inputs_Y[0], pl_ext, outputs[i]);
    }

    for (int i = 0; i < (int) outputs.size(); i++) {
        outputs[i] = rotation_and_fill(outputs[i], data_size * value_size_glb, evaluator, gal_keys);
    }

    return outputs;
}

// arrange the parition by threshold_within_value --> label_value, notice that all attribuutes are packed together
void preprocess_all_threshold(vector<Ciphertext>& inputs_X, vector<Ciphertext>& inputs_Y, vector<Ciphertext>& partitioned,
                              BatchEncoder& batch_encoder, Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys,
                              RelinKeys& relin_keys, int data_size = data_size_glb, int attr_size = attr_size_glb,
                              int val_size = value_size_glb, int label_size = label_size_glb) {
                    
    partitioned.resize(label_size * (val_size*2-1)); // there are that many possible threshold values for partitioning

    cout << "Preprocessing for all possible threshold values...\n";

    // since all attributes are packed together, rotation and addition could be applied to all attributes for
    // a specific threshold value simultaneously
    Ciphertext tmp;
    for (int i = 0; i < val_size; i++) {
        if (i == 0) { // group all datapoints together
            for (int cnt = 0; cnt < (int) inputs_X.size(); cnt++) { 
                tmp = inputs_X[cnt];
                partitioned[0] = rotation_and_add(tmp, data_size * val_size, data_size, evaluator, gal_keys, 0);
            }
        } else {
            for (int cnt = 0; cnt < (int) inputs_X.size(); cnt++) { 
                tmp = inputs_X[cnt];
                partitioned[(2*i-1)*label_size] = rotation_and_add(tmp, data_size * i, data_size, evaluator, gal_keys, 0); // left partition
                
                tmp = inputs_X[cnt];
                partitioned[2*i*label_size] = rotation_and_add(tmp, data_size * (val_size-i), data_size, evaluator, gal_keys, data_size * i); // right partition
                evaluator.rotate_rows_inplace(partitioned[2*i*label_size], data_size * i, gal_keys);
            }
        }
    }

    vector<Ciphertext> processed_labels = preprocess_label(inputs_Y, encryptor, evaluator, gal_keys);


	for (int i = 0; i < (int) val_size; i++) {
        if (i == 0) {
            for (int j = 0; j < label_size; j++) {
                evaluator.multiply(partitioned[i], processed_labels[j], partitioned[i + j]);
                evaluator.relinearize_inplace(partitioned[i + j], relin_keys);
            }
        } else {
            for (int j = 0; j < label_size; j++) {
                evaluator.multiply(partitioned[(2*i-1)*label_size], processed_labels[j], partitioned[(2*i-1)*label_size + j]);
                evaluator.relinearize_inplace(partitioned[(2*i-1)*label_size + j], relin_keys);
                evaluator.multiply(partitioned[2*i*label_size], processed_labels[j], partitioned[2*i*label_size + j]);
                evaluator.relinearize_inplace(partitioned[2*i*label_size + j], relin_keys);
            }
        }
	}
}