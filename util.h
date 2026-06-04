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
Ciphertext rotation_and_fill(SEALContext& context, Ciphertext& input, int length, Evaluator& evaluator, GaloisKeys& rot_keys) {
    Ciphertext output = input;

    int iter = 1;
    while (iter < attr_size_glb) { // round it to a power of 2
        iter *= 2;
    }

    Ciphertext tmp;
    while (iter > 1) {
        int step = (int) (iter / 2) * length; // march by half each time
        if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
            if (step > poly_modulus_degree_glb / 2) {
                evaluator.rotate_vector(output, data_size_glb, rot_keys, tmp); // simulation step size... buggy
            } else {
                evaluator.rotate_vector(output, (step) % (poly_modulus_degree_glb/2), rot_keys, tmp);
            }
        } else {
            if (step > poly_modulus_degree_glb / 2) {
                evaluator.rotate_rows(output, data_size_glb, rot_keys, tmp); // simulation step size... buggy
            } else {
                evaluator.rotate_rows(output, (step) % (poly_modulus_degree_glb/2), rot_keys, tmp);
            }
        }
        evaluator.add_inplace(output, tmp);

        iter = iter / 2;
    }

    return output;
}

// for a length n vector, group by chunk_size; so if chunk_size = 1, then sum up the whole vector; one ciphertext could pack multi vectors
Ciphertext rotation_and_add(SEALContext& context, Ciphertext& input, int length, int chunk_size, Evaluator& evaluator,
                            GaloisKeys& rot_keys, int offset = 0) {
    int iter = length / chunk_size;

    Ciphertext output = input;
    Ciphertext carry_over;
    bool carry_over_init = false;

    while (iter > 1) {
        int step = (int) (iter / 2) * chunk_size; // march by half each time
        Ciphertext tmp1, tmp2;
        if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
            evaluator.rotate_vector(output, step+offset, rot_keys, tmp1);
            if (iter % 2) {
                step = (iter - 1) * chunk_size;
                if (!carry_over_init) {
                    evaluator.rotate_vector(output, (step+offset)% (poly_modulus_degree_glb/2), rot_keys, carry_over);
                    carry_over_init = true;
                } else {
                    evaluator.rotate_vector(output, (step+offset)% (poly_modulus_degree_glb/2), rot_keys, tmp2);
                    evaluator.add_inplace(carry_over, tmp2);
                }
            }
            evaluator.add_inplace(output, tmp1);
        } else {
            evaluator.rotate_rows(output, (step+offset) % (poly_modulus_degree_glb/2), rot_keys, tmp1);
            if (iter % 2) {
                step = (iter - 1) * chunk_size;
                if (!carry_over_init) {
                    evaluator.rotate_rows(output, (step+offset) % (poly_modulus_degree_glb/2), rot_keys, carry_over);
                    carry_over_init = true;
                } else {
                    evaluator.rotate_rows(output, (step+offset) % (poly_modulus_degree_glb/2), rot_keys, tmp2);
                    evaluator.add_inplace(carry_over, tmp2);
                }
            }
            evaluator.add_inplace(output, tmp1);
        }

        iter = iter / 2;
    }

    if (carry_over_init) {
        evaluator.add_inplace(output, carry_over);
    }

    return output;
}

void sample_one_hot_encoding_inputs_ckks(vector<Ciphertext>& inputs_X, vector<Ciphertext>& inputs_Y, int data_size,
                                    int attr_size, int val_size, int label_size, CKKSEncoder& ckks_encoder,
                                    Encryptor& encryptor) {
    
    vector<vector<vector<int>>> inputs(data_size);
    vector<vector<double>> labels(data_size);

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

    int num_of_ct = ceil((double) data_size * attr_size * val_size / (double) poly_modulus_degree_glb);

    inputs_X.resize(num_of_ct);
    inputs_Y.resize(1); // default

    // arranged by attributes --> values --> datapoints
    vector<double> x(poly_modulus_degree_glb, 0);
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
        ckks_encoder.encode(x, scale, pl);

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
    ckks_encoder.encode(x, scale, pl);
    encryptor.encrypt(pl, inputs_Y[0]);

    cout << "Encoding inputs to " << num_of_ct << " ciphertexts...\n";
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

    int num_of_ct = ceil((double) data_size * attr_size * val_size / (double) poly_modulus_degree_glb);

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
            }
        }
        batch_encoder.encode(x, pl);


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

    cout << "Encoding inputs to " << num_of_ct << " ciphertexts...\n";
}


// make #label_size label-ciphertexts, each encodes many chunks, each chunk has the first #data_size entry to be label indicators 
// chunk size: data_size * value_size, which aligns with the chunk size of preprocessed_partitions (which packs all attributes in one)
// for example, if we have 5 datapoints, with 3 labels, and the mapping is: 1 -> 1, 2 --> 1, 3 --> 3, 4 --> 2, 5 --> 3
// then we could have the final outputs to be ((1,1,0,0,0), (0,0,0,1,0), (0,0,1,0,1))
// if the vector length if way bigger than data size, then the indicator vector would repeat and fill the whole ciphertext vector
vector<Ciphertext> preprocess_label(SEALContext& context, vector<Ciphertext>& inputs_Y, Encryptor& encryptor, Evaluator& evaluator,
                                    GaloisKeys& gal_keys, int data_size = data_size_glb, int label_size = label_size_glb) {
    
    vector<Ciphertext> outputs(label_size);

    if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
        Plaintext pl_ext;
        CKKSEncoder encoder(context);
        vector<double> extractor_vec(poly_modulus_degree_glb);

        int label_per_ct = poly_modulus_degree_glb / (data_size);

        for (int i = 0; i < label_size; i++) {
            int ct_ind = i * data_size / poly_modulus_degree_glb;

            for (size_t i = 0; i < poly_modulus_degree_glb; i++) {
                if (i >= data_size * (i % label_per_ct) && i < data_size * ((i%label_per_ct)+1)) {
                    extractor_vec[i] = 1.0;
                } else {
                    extractor_vec[i] = 0.0;
                }
            }
            encoder.encode(extractor_vec, scale, pl_ext);

            evaluator.multiply_plain(inputs_Y[ct_ind], pl_ext, outputs[i]);
        }

        for (int i = 0; i < (int) outputs.size(); i++) {
            outputs[i] = rotation_and_fill(context, outputs[i], data_size * value_size_glb, evaluator, gal_keys);
        }

    } else {
        Plaintext pl_ext;

        pl_ext.resize(poly_modulus_degree_glb);
        pl_ext.parms_id() = parms_id_zero;
        for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
            pl_ext.data()[i] = 0;
        }

        int label_per_ct = poly_modulus_degree_glb / (data_size);

        for (int i = 0; i < label_size; i++) {
            int ct_ind = i * data_size / poly_modulus_degree_glb;
            for (int j = data_size * (i % label_per_ct); j < data_size * ((i%label_per_ct)+1); j++) {
                pl_ext.data()[j] = 1;
            }
            evaluator.multiply_plain(inputs_Y[ct_ind], pl_ext, outputs[i]);
        }

        for (int i = 0; i < (int) outputs.size(); i++) {
            outputs[i] = rotation_and_fill(context, outputs[i], data_size * value_size_glb, evaluator, gal_keys);
        }
    }

    return outputs;
}

// arrange the parition by threshold_within_value --> left/right --> label_value, notice that all attributes are packed together
void preprocess_all_threshold(vector<Ciphertext>& inputs_X, vector<Ciphertext>& inputs_Y, vector<vector<Ciphertext>>& partitioned,
                              vector<vector<vector<Ciphertext>>>& partitioned_labels, SEALContext& context, 
                              Evaluator& evaluator, Encryptor& encryptor, GaloisKeys& gal_keys,
                              RelinKeys& relin_keys, int data_size = data_size_glb, int attr_size = attr_size_glb,
                              int val_size = value_size_glb, int label_size = label_size_glb) {
                    
    cout << "Preprocessing for all possible threshold values...\n";

    for (int i = 0; i < (int) partitioned.size(); i++) {
        partitioned[i].resize((val_size*2-1)); // there are that many possible threshold values for partitioning
    }
    for (int i = 0; i < (int) partitioned.size(); i++) {
        partitioned_labels[i].resize(label_size, vector<Ciphertext>(val_size*2-1));
    }
    
    // notice that all attributes are packed together
    // i.e., each ciphertext encrypts "the indicators of datapoints for threshold \theta for all attributes"
    // since all attributes are packed together, rotation and addition could be applied to all attributes for
    // a specific threshold value simultaneously

    int thread_chunk = max(1, (int)ceil((float)val_size / (float)num_cores));

    NTL::SetNumThreads(num_cores);
    NTL_EXEC_RANGE(num_cores, first, last);
    for (int tt = first; tt < last; tt++) {
        Ciphertext tmp;
        for (int i = tt*thread_chunk; i < min(val_size, (tt+1)*thread_chunk); i++) {
            if (i == 0) { // group all datapoints together
                for (int cnt = 0; cnt < (int) inputs_X.size(); cnt++) { 
                    tmp = inputs_X[cnt];
                    partitioned[cnt][0] = rotation_and_add(context, tmp, data_size * val_size, data_size, evaluator, gal_keys, 0);
                }
            } else {
                for (int cnt = 0; cnt < (int) inputs_X.size(); cnt++) { 
                    tmp = inputs_X[cnt];
                    partitioned[cnt][(2*i-1)] = rotation_and_add(context, tmp, data_size * i, data_size, evaluator, gal_keys, 0); // left partition
                    
                    tmp = inputs_X[cnt];
                    partitioned[cnt][2*i] = rotation_and_add(context, tmp, data_size * (val_size-i), data_size, evaluator, gal_keys, data_size * i); // right partition
                    if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
                        evaluator.rotate_vector_inplace(partitioned[cnt][2*i], data_size * i, gal_keys);
                    } else {
                        evaluator.rotate_rows_inplace(partitioned[cnt][2*i], (data_size * i)%(poly_modulus_degree_glb/2), gal_keys);
                    }
                }
            }
        }
    }
    NTL_EXEC_RANGE_END;
    cout << "   Input X preprocessed.\n";

    // since for ckks, you need to rescale to next each time for whatever multiplication you perform, and cost 40 bits of noise
    // let the parties directly supply the form of preprocess_label, this will blow up the communication cost for the label part a little, but not much
    vector<Ciphertext> processed_labels;
    // if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
    //     processed_labels.resize(label_size);
    //     for (int i = 0; i < label_size; i++) {
    //         processed_labels[i] = inputs_Y[0];
    //     }
    // } else {
    processed_labels = preprocess_label(context, inputs_Y, encryptor, evaluator, gal_keys);
    // }
    
    thread_chunk = max(1, (int)ceil((float) partitioned.size() / (float) num_cores));
    NTL_EXEC_RANGE(num_cores, first, last);
    for (int tt = first; tt < last; tt++) {
        for (int cnt = tt*thread_chunk; cnt < min((int) partitioned.size(), (tt+1)*thread_chunk); cnt++) {
            for (int i = 0; i < (int) val_size; i++) {
                if (i == 0) {
                    for (int j = 0; j < label_size; j++) {
                        evaluator.multiply(partitioned[cnt][i], processed_labels[j], partitioned_labels[cnt][j][i]);
                        evaluator.relinearize_inplace(partitioned_labels[cnt][j][i], relin_keys);
                        if (context.key_context_data()->parms().scheme() == scheme_type::ckks && log2(partitioned_labels[cnt][j][i].scale()) >= 60) {
                            evaluator.rescale_to_next_inplace(partitioned_labels[cnt][j][i]);
                        } else {
                            evaluator.mod_switch_to_next_inplace(partitioned_labels[cnt][j][i]);
                        }
                    }
                } else {
                    for (int j = 0; j < label_size; j++) {
                        evaluator.multiply(partitioned[cnt][(2*i-1)], processed_labels[j], partitioned_labels[cnt][j][(2*i-1)]);
                        evaluator.relinearize_inplace(partitioned_labels[cnt][j][(2*i-1)], relin_keys);
                        evaluator.multiply(partitioned[cnt][2*i], processed_labels[j], partitioned_labels[cnt][j][2*i]);
                        evaluator.relinearize_inplace(partitioned_labels[cnt][j][2*i], relin_keys);
                        if (context.key_context_data()->parms().scheme() == scheme_type::ckks && log2(partitioned_labels[cnt][j][2*i].scale()) >= 60) {
                            evaluator.rescale_to_next_inplace(partitioned_labels[cnt][j][2*i-1]);
                            evaluator.rescale_to_next_inplace(partitioned_labels[cnt][j][2*i]);
                        } else {
                            evaluator.mod_switch_to_next_inplace(partitioned_labels[cnt][j][2*i-1]);
                            evaluator.mod_switch_to_next_inplace(partitioned_labels[cnt][j][2*i]);
                        }
                    }
                }
            }
        }
    }
    NTL_EXEC_RANGE_END;
    cout << "   Input Y preprocessed.\n";
}

// based on the selection vector, "partitions_for_node" records all selected datapoints for each threshold value
// and "partition_labels_for_node" records all selected datapoints for for each threshold with certain label
// after rotation_and_add, each ciphertext encodes multiple chunks, chunk_size = data_size
// the first entry of each chunk is |D|, where D is the dataset partitioned based on threshold, selection_vector 
// notice that as for preprocessed_partitions, each ciphertext pack all attributes, as long as data_size * attr_size < poly_deg
// (and label, if the ciphertext is "partition_labels_for_node")
// we also take the square to facilitate the MPC computation of MGI
void perform_partition_for_node(vector<vector<Ciphertext>>& preprocessed_partitions,
                                vector<vector<vector<Ciphertext>>>& preprocessed_partitioned_labels,
                                vector<vector<Ciphertext>>& partitions_for_node,
                                vector<vector<vector<Ciphertext>>>& partition_labels_for_node, SEALContext& context, 
                                Ciphertext& selection_vector, Evaluator& evaluator, RelinKeys& relin_keys, GaloisKeys& gal_keys,
                                bool multi_thread = false) {

    for (int cnt = 0; cnt < (int) preprocessed_partitions.size(); cnt++) {
        partitions_for_node[cnt].resize((int) preprocessed_partitions[cnt].size());
    }

    for (int cnt = 0; cnt < (int) preprocessed_partitioned_labels.size(); cnt ++) {
        partition_labels_for_node[cnt].resize(label_size_glb, vector<Ciphertext>((int) preprocessed_partitioned_labels[0][0].size()));
    }

    // multi_thread = false;

    if (multi_thread) {
        NTL::SetNumThreads(num_cores);
        int thread_chunk_size_1 = (int) preprocessed_partitions[0].size() / num_cores;
        int thread_chunk_size_2 = (int) preprocessed_partitioned_labels[0][0].size() / num_cores;

        NTL_EXEC_RANGE(num_cores, first, last);
        for (int tt = first; tt < last; tt++) {
            int end_1 = (tt == last-1) ? (int) preprocessed_partitions[0].size() : (tt+1) * thread_chunk_size_1;
            for (int cnt = 0; cnt < (int) preprocessed_partitions.size(); cnt++) {
                for (int i = tt * thread_chunk_size_1; i < end_1; i++) {
                    Ciphertext tmp = preprocessed_partitions[cnt][i];
                    Ciphertext sel_local = selection_vector;
                    if (context.get_context_data(tmp.parms_id())->chain_index() < context.get_context_data(sel_local.parms_id())->chain_index()) {
                        evaluator.mod_switch_to_inplace(sel_local, tmp.parms_id());
                    } else {
                        evaluator.mod_switch_to_inplace(tmp, sel_local.parms_id());
                    }
                    evaluator.multiply(tmp, sel_local, partitions_for_node[cnt][i]);
                    evaluator.relinearize_inplace(partitions_for_node[cnt][i], relin_keys);
                    if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partitions_for_node[cnt][i].scale()) > 60) {
                        // if (cnt == 0 && i == 0) cout << "   Now switch for data1: " << log2(tmp.scale()) << ", " << log2(selection_vector.scale()) << ", " << context.get_context_data(partitions_for_node[cnt][i].parms_id())->chain_index() <<\
                        //         ", " << log2(partitions_for_node[cnt][i].scale()) << " --> ";
                        evaluator.rescale_to_next_inplace(partitions_for_node[cnt][i]);
                        // if (cnt == 0 && i == 0) cout << log2(partitions_for_node[cnt][i].scale()) << endl;
                    } else {
                        // cout << "Skip first for data\n";
                    }
                    //else {
                    //     evaluator.mod_switch_to_next_inplace(partitions_for_node[cnt][i]);
                    // }
                    partitions_for_node[cnt][i] = rotation_and_add(context, partitions_for_node[cnt][i], data_size_glb, 1, evaluator, gal_keys, 0);

                    // evaluator.multiply_inplace(partitions_for_node[cnt][i], partitions_for_node[cnt][i]);
                    // evaluator.relinearize_inplace(partitions_for_node[cnt][i], relin_keys);
                    if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partitions_for_node[cnt][i].scale()) > 60) {
                        // if (cnt == 0 && i == 0) cout << "   Now switch for data2: " << log2(partitions_for_node[cnt][i].scale()) << " --> ";
                        evaluator.rescale_to_next_inplace(partitions_for_node[cnt][i]);
                        // if (cnt == 0 && i == 0) cout << log2(partitions_for_node[cnt][i].scale()) << endl;
                        // cout << log2(partitions_for_node[cnt][i].scale()) << endl;
                        // evaluator.mod_switch_to_inplace(partitions_for_node[cnt][i], context.last_parms_id());
                    } else {
                        evaluator.mod_switch_to_next_inplace(partitions_for_node[cnt][i]);
                    }
                }
            }
        }
        NTL_EXEC_RANGE_END;

        // this bug is really something.... somehow if I have two different for loops inside this multi-thread, then the second for loop would have only one thread executing
        // the last chunk, i.e., for 4 cores, I would always have first = 3 for the second for loop, ridiculous!!!!
        // so I split them into two separate thread pool, small overhead for spinning up the pool, but..... WHY...
        NTL_EXEC_RANGE(num_cores, first, last);
        for (int tt = first; tt < last; tt++) {
            int end_2 = (tt == last-1) ? (int) preprocessed_partitioned_labels[0][0].size() : (tt+1) * thread_chunk_size_2;
            for (int cnt = 0; cnt < (int) preprocessed_partitioned_labels.size(); cnt++) {
                for (int l = 0; l < label_size_glb; l++) {
                    for (int i = tt * thread_chunk_size_2; i < end_2; i++) {
                        Ciphertext tmp = preprocessed_partitioned_labels[cnt][l][i];
                        Ciphertext sel_local = selection_vector;
                        if (context.get_context_data(tmp.parms_id())->chain_index() < context.get_context_data(sel_local.parms_id())->chain_index()) {
                            evaluator.mod_switch_to_inplace(sel_local, tmp.parms_id());
                        } else {
                            evaluator.mod_switch_to_inplace(tmp, sel_local.parms_id());
                        }

                        evaluator.multiply(tmp, sel_local, partition_labels_for_node[cnt][l][i]);
                        evaluator.relinearize_inplace(partition_labels_for_node[cnt][l][i], relin_keys);
                        if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partition_labels_for_node[cnt][l][i].scale()) > 60) {
                            // if (cnt == 0 && i == 0 && l == 0) cout << "   Now switch for label1: " << log2(partition_labels_for_node[cnt][l][i].scale()) << " --> ";
                            evaluator.rescale_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                            // if (cnt == 0 && i == 0 && l == 0) cout << log2(partition_labels_for_node[cnt][l][i].scale()) << endl;
                        }
                        partition_labels_for_node[cnt][l][i] = rotation_and_add(context, partition_labels_for_node[cnt][l][i], data_size_glb, 1, evaluator, gal_keys, 0);

                        // evaluator.square_inplace(partition_labels_for_node[cnt][l][i]);
                        // evaluator.relinearize_inplace(partition_labels_for_node[cnt][l][i], relin_keys);
                        if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partition_labels_for_node[cnt][l][i].scale()) > 60) {
                            // if (cnt == 0 && i == 0 && l == 0) cout << "   Now switch for label2: " << log2(partition_labels_for_node[cnt][l][i].scale()) << " --> ";
                            evaluator.rescale_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                            // if (cnt == 0 && i == 0 && l == 0) cout << log2(partition_labels_for_node[cnt][l][i].scale()) << endl;
                            // evaluator.mod_switch_to_inplace(partition_labels_for_node[cnt][l][i], context.last_parms_id());
                        } else {
                            evaluator.mod_switch_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                        }
                    }
                }
            }
        }
        NTL_EXEC_RANGE_END;
    } else {
        // cout << "here?\n";
        for (int cnt = 0; cnt < (int) preprocessed_partitions.size(); cnt++) {
            for (int i = 0; i < (int) preprocessed_partitions[0].size(); i++) {
                // cout << "       " << cnt << ", " << i << endl;
                Ciphertext tmp = preprocessed_partitions[cnt][i];
                Ciphertext sel_local = selection_vector;
                if (context.get_context_data(tmp.parms_id())->chain_index() < context.get_context_data(sel_local.parms_id())->chain_index()) {
                    evaluator.mod_switch_to_inplace(sel_local, tmp.parms_id());
                } else {
                    evaluator.mod_switch_to_inplace(tmp, sel_local.parms_id());
                }

                evaluator.multiply(tmp, sel_local, partitions_for_node[cnt][i]);
                evaluator.relinearize_inplace(partitions_for_node[cnt][i], relin_keys);

                if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partitions_for_node[cnt][i].scale()) > 60) {
                    // if (cnt == 0 && i == 0) cout << "   Now switch for data1: " << log2(tmp.scale()) << ", " << log2(selection_vector.scale()) << ", " << context.get_context_data(partitions_for_node[cnt][i].parms_id())->chain_index() <<\
                    //      ", " << log2(partitions_for_node[cnt][i].scale()) << " --> ";
                    evaluator.rescale_to_next_inplace(partitions_for_node[cnt][i]);
                    // if (cnt == 0 && i == 0) cout << log2(partitions_for_node[cnt][i].scale()) << endl;
                }
                // } else {
                //     evaluator.mod_switch_to_next_inplace(partitions_for_node[cnt][i]);
                // }
                partitions_for_node[cnt][i] = rotation_and_add(context, partitions_for_node[cnt][i], data_size_glb, 1, evaluator, gal_keys, 0);

                // evaluator.multiply_inplace(partitions_for_node[cnt][i], partitions_for_node[cnt][i]);
                // evaluator.relinearize_inplace(partitions_for_node[cnt][i], relin_keys);
                if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partitions_for_node[cnt][i].scale()) > 60) {
                    // if (cnt == 0 && i == 0) cout << "   Now switch for data2: " << context.get_context_data(partitions_for_node[cnt][i].parms_id())->chain_index() <<\
                    //      ", " << log2(partitions_for_node[cnt][i].scale()) << " --> ";
                    evaluator.rescale_to_next_inplace(partitions_for_node[cnt][i]);
                    // if (cnt == 0 && i == 0) cout << log2(partitions_for_node[cnt][i].scale()) << endl;
                    // evaluator.mod_switch_to_inplace(partitions_for_node[cnt][i], context.last_parms_id());
                } else {
                    evaluator.mod_switch_to_next_inplace(partitions_for_node[cnt][i]);
                }
            }
        }

        for (int cnt = 0; cnt < (int) preprocessed_partitioned_labels.size(); cnt++) {
            for (int l = 0; l < label_size_glb; l++) {
                for (int i = 0; i < (int) preprocessed_partitioned_labels.size(); i++) {
                    // cout << "       " << cnt << ", " << l << ", " << i << endl;
                    Ciphertext tmp = preprocessed_partitioned_labels[cnt][l][i];
                    Ciphertext sel_local = selection_vector;
                    if (context.get_context_data(tmp.parms_id())->chain_index() < context.get_context_data(sel_local.parms_id())->chain_index()) {
                        evaluator.mod_switch_to_inplace(sel_local, tmp.parms_id());
                    } else {
                        evaluator.mod_switch_to_inplace(tmp, sel_local.parms_id());
                    }
                    evaluator.multiply(tmp, sel_local, partition_labels_for_node[cnt][l][i]);
                    evaluator.relinearize_inplace(partition_labels_for_node[cnt][l][i], relin_keys);

                    if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partition_labels_for_node[cnt][l][i].scale()) > 60) {
                        // if (cnt == 0 && i == 0) cout << "   Now switch for label1: " << context.get_context_data(partition_labels_for_node[cnt][l][i].parms_id())->chain_index() <<\
                        //  ", " << log2(partition_labels_for_node[cnt][l][i].scale()) << " --> ";
                        evaluator.rescale_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                        // if (cnt == 0 && i == 0 && l == 0) cout << log2(partition_labels_for_node[cnt][l][i].scale()) << endl;
                    }
                    partition_labels_for_node[cnt][l][i] = rotation_and_add(context, partition_labels_for_node[cnt][l][i], data_size_glb, 1, evaluator, gal_keys, 0);
                    // if (context.key_context_data()->parms().scheme() == scheme_type::ckks) {
                    //     evaluator.rescale_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                    // }
                    // evaluator.square_inplace(partition_labels_for_node[cnt][l][i]);
                    // evaluator.relinearize_inplace(partition_labels_for_node[cnt][l][i], relin_keys);
                    if (context.key_context_data()->parms().scheme() == scheme_type::ckks && (int)log2(partition_labels_for_node[cnt][l][i].scale()) > 60) {
                        // if (cnt == 0 && i == 0) cout << "   Now switch for label2: " << context.get_context_data(partition_labels_for_node[cnt][l][i].parms_id())->chain_index() <<\
                        //  ", " << log2(partition_labels_for_node[cnt][l][i].scale()) << " --> ";
                        evaluator.rescale_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                        // if (cnt == 0 && i == 0 && l == 0) cout << log2(partition_labels_for_node[cnt][l][i].scale()) << endl;
                        // evaluator.mod_switch_to_inplace(partition_labels_for_node[cnt][l][i], context.last_parms_id());
                    } else {
                        evaluator.mod_switch_to_next_inplace(partition_labels_for_node[cnt][l][i]);
                    }
                }
            }
        }
    }
}

void update_selection_vector_ckks(vector<Ciphertext>& selection_vector, vector<vector<Ciphertext>>& preprocessed_partitions,
                             int threshold_attr_ind, int threshold_val_ind, int cur_depth, int curr_node, SEALContext& context, 
                             CKKSEncoder& ckks_encoder, Evaluator& evaluator, RelinKeys& relin_keys, GaloisKeys& gal_keys) {

    int parent_sel_ind = pow(2, cur_depth)-1 + curr_node;
    int child_sel_ind = parent_sel_ind * 2 + 1;
    
   
    Ciphertext threshold_data;
    vector<double> extractor_msg(poly_modulus_degree_glb, 0);

    int attr_per_ct = poly_modulus_degree_glb / (label_size_glb * data_size_glb); // how many attr one ciphertext can pack

    int start_ind = (threshold_attr_ind % attr_per_ct) * data_size_glb * value_size_glb; 
    int end_ind = start_ind + data_size_glb;
    for (int i = start_ind; i < end_ind; i++) {
        extractor_msg[i] = 1;
    }
    Plaintext extractor_pl;
    ckks_encoder.encode(extractor_msg, scale, extractor_pl);

    // cout << "   --- inside update: " << \
    //      context.get_context_data(preprocessed_partitions[threshold_attr_ind / attr_per_ct][threshold_val_ind + 1].parms_id())->chain_index() << ", " << \
    //      context.get_context_data(selection_vector[parent_sel_ind].parms_id())->chain_index() << endl;


    for (int i = 0; i < 2; i++) { // for left and right children
        evaluator.multiply_plain(preprocessed_partitions[threshold_attr_ind / attr_per_ct][threshold_val_ind + 1 - i%2],
                                 extractor_pl,
                                 threshold_data);
        // if (start_ind > poly_modulus_degree_glb / 2) {
        //     evaluator.rotate_columns_inplace(threshold_data, gal_keys);
        //     evaluator.rotate_rows_inplace(threshold_data, start_ind - poly_modulus_degree_glb/2, gal_keys);
        // }
        threshold_data = rotation_and_fill(context, threshold_data, data_size_glb * value_size_glb, evaluator, gal_keys);
        // evaluator.rescale_to_next_inplace(threshold_data);
        if (context.get_context_data(threshold_data.parms_id())->chain_index() < context.get_context_data(selection_vector[parent_sel_ind].parms_id())->chain_index()) {
            evaluator.mod_switch_to_inplace(selection_vector[parent_sel_ind], threshold_data.parms_id());
        } else {
            evaluator.mod_switch_to_inplace(threshold_data, selection_vector[parent_sel_ind].parms_id());
        }
        
        evaluator.multiply(selection_vector[parent_sel_ind], threshold_data, selection_vector[child_sel_ind+i]);
        // cout << "???? " << log2(selection_vector[parent_sel_ind].scale()) << ", " << log2(threshold_data.scale()) << ", " << \
        //      log2(selection_vector[child_sel_ind+i].scale()) << endl;
        evaluator.relinearize_inplace(selection_vector[child_sel_ind+i], relin_keys);

        if (log2(selection_vector[child_sel_ind+i].scale()) > 60) {
            // cout << "   Scale down at depth: " << cur_depth << ", update selection chain: " << \
            //      context.get_context_data(selection_vector[child_sel_ind+i].parms_id())->chain_index() \
            //      << ", " << log2(selection_vector[child_sel_ind+i].scale()) << " --> ";
            evaluator.rescale_to_next_inplace(selection_vector[child_sel_ind+i]);
            // cout << context.get_context_data(selection_vector[child_sel_ind+i].parms_id())->chain_index() \
            //      << ", " << log2(selection_vector[child_sel_ind+i].scale()) << endl;
        } else {
            // cout << "   No scale down at depth: " << cur_depth << ", with " << \
            //      context.get_context_data(selection_vector[child_sel_ind+i].parms_id())->chain_index() \
            //      << ", " << log2(selection_vector[child_sel_ind+i].scale()) << endl;
        }
    }
    // if (cur_depth == depth_glb-1 && curr_node == 0) {
    //     cout << "	Final selection chain: " << context.get_context_data(selection_vector[child_sel_ind].parms_id())->chain_index() << endl;
    // }
}


void update_selection_vector(vector<Ciphertext>& selection_vector, vector<vector<Ciphertext>>& preprocessed_partitions,
                             int threshold_attr_ind, int threshold_val_ind, int cur_depth, int curr_node, SEALContext& context,
                             BatchEncoder& batch_encoder, Evaluator& evaluator, RelinKeys& relin_keys, GaloisKeys& gal_keys) {

    int parent_sel_ind = pow(2, cur_depth)-1 + curr_node;
    int child_sel_ind = parent_sel_ind * 2 + 1;
    
   
    Ciphertext threshold_data;
    vector<uint64_t> extractor_msg(poly_modulus_degree_glb, 0);

    int attr_per_ct = poly_modulus_degree_glb / (label_size_glb * data_size_glb); // how many attr one ciphertext can pack

    int start_ind = (threshold_attr_ind % attr_per_ct) * data_size_glb * value_size_glb; 
    int end_ind = start_ind + data_size_glb;
    for (int i = start_ind; i < end_ind; i++) {
        extractor_msg[i] = 1;
    }
    Plaintext extractor_pl;
    batch_encoder.encode(extractor_msg, extractor_pl);


    for (int i = 0; i < 2; i++) {
        evaluator.multiply_plain(preprocessed_partitions[threshold_attr_ind / attr_per_ct][threshold_val_ind + 1 - i%2],
                                 extractor_pl,
                                 threshold_data);
        if (start_ind > poly_modulus_degree_glb / 2) {
            evaluator.rotate_columns_inplace(threshold_data, gal_keys);
            evaluator.rotate_rows_inplace(threshold_data, (start_ind - poly_modulus_degree_glb/2) % (poly_modulus_degree_glb/2), gal_keys);
        }
        threshold_data = rotation_and_fill(context, threshold_data, data_size_glb * value_size_glb, evaluator, gal_keys);
        evaluator.mod_switch_to_inplace(threshold_data, selection_vector[parent_sel_ind].parms_id());
        evaluator.multiply(selection_vector[parent_sel_ind], threshold_data, selection_vector[child_sel_ind+i]);
        evaluator.relinearize_inplace(selection_vector[child_sel_ind+i], relin_keys);

        evaluator.mod_switch_to_next_inplace(selection_vector[child_sel_ind+i]);
    }
}

void simulate_random_select_sqrt_attributes(vector<vector<Ciphertext>>& preprocessed_partitions,
                                            vector<vector<vector<Ciphertext>>>& preprocessed_partitioned_labels,
                                            vector<vector<Ciphertext>>& random_preprocessed_partitions,
                                            vector<vector<vector<Ciphertext>>>& random_preprocessed_partitioned_labels,
                                            SEALContext& context, Evaluator& evaluator, GaloisKeys& gal_keys,
                                            bool multi_thread = false) {
    int packed = 2 * (floor((double)(poly_modulus_degree_glb/2) / (double) (data_size_glb*value_size_glb)));
    int num_ct = ceil((double) (sqrt_attr_size_glb) / (double) packed );
    // cout << "   repack number of ct: " << num_ct << endl;;
    
    // direct simulation for digits...
    // int num_ct = 8;


    random_preprocessed_partitions.resize(num_ct);
    random_preprocessed_partitioned_labels.resize(num_ct);
    for (int i = 0; i < (int) random_preprocessed_partitions.size(); i++) {
        random_preprocessed_partitions[i].resize(preprocessed_partitions[0].size());
        for (int j = 0; j < (int) random_preprocessed_partitions[i].size(); j++) {
            random_preprocessed_partitions[i][j] = preprocessed_partitions[0][j];
        }
        random_preprocessed_partitioned_labels[i].resize(preprocessed_partitioned_labels[i].size());
        for (int j = 0; j < (int) random_preprocessed_partitioned_labels[i].size(); j++) {
            random_preprocessed_partitioned_labels[i][j].resize((int)preprocessed_partitioned_labels[i][j].size());
            for (int k = 0; k < (int) random_preprocessed_partitioned_labels[i][j].size(); k++) {
                random_preprocessed_partitioned_labels[i][j][k] = preprocessed_partitioned_labels[0][j][k];
            }
        }
    }

    if (sqrt_attr_size_glb == attr_size_glb) { // no need for iris...
        return;
    }

    chrono::high_resolution_clock::time_point time_start, time_end;
    time_start = chrono::high_resolution_clock::now();


    if (multi_thread) {
        NTL::SetNumThreads(num_cores);
        NTL_EXEC_RANGE(num_cores, first, last);
        int thread_chunk_size_1 = sqrt_attr_size_glb / num_cores;
        for (int tt = first; tt < last; tt++) {
            int end = (tt == last-1) ? (int) sqrt_attr_size_glb : (tt+1) * thread_chunk_size_1;
            for (int ii = tt * thread_chunk_size_1; ii < end; ii++) {
                for (int jj = 0 ; jj < preprocessed_partitions[0].size(); jj++) {
                    Plaintext pll;
                    pll.resize(poly_modulus_degree_glb);
                    pll.parms_id() = parms_id_zero;
                    for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
                        pll.data()[i] = 1;
                    }
                    Ciphertext tmp = preprocessed_partitions[0][jj];
                    evaluator.multiply_plain_inplace(tmp, pll);
                    evaluator.rotate_rows_inplace(tmp, (data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2), gal_keys);
                    evaluator.add_inplace(random_preprocessed_partitions[0][jj], tmp);
                }

                for (int jj = 0 ; jj < preprocessed_partitioned_labels[0].size(); jj++) {
                    for (int kk = 0; kk < preprocessed_partitioned_labels[0][0].size(); kk++) {
                        Plaintext pll;
                        pll.resize(poly_modulus_degree_glb);
                        pll.parms_id() = parms_id_zero;
                        for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
                            pll.data()[i] = 1;
                        }
                        Ciphertext tmp = preprocessed_partitioned_labels[0][jj][kk];
                        evaluator.multiply_plain_inplace(tmp, pll);
                        evaluator.rotate_rows_inplace(tmp, (data_size_glb * value_size_glb) % (poly_modulus_degree_glb/2), gal_keys);
                        evaluator.add_inplace(random_preprocessed_partitioned_labels[0][jj][kk], tmp);
                    }
                }
            }
        }

        NTL_EXEC_RANGE_END;
    } else {
        
        for (int ii = 0; ii < sqrt_attr_size_glb; ii++) {
            for (int jj = 0 ; jj < preprocessed_partitions[0].size(); jj++) {
                Plaintext pll;
                pll.resize(poly_modulus_degree_glb);
                pll.parms_id() = parms_id_zero;
                for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
                    pll.data()[i] = 1;
                }
                Ciphertext tmp = preprocessed_partitions[0][jj];
                evaluator.multiply_plain_inplace(tmp, pll);
                evaluator.rotate_rows_inplace(tmp, (data_size_glb * value_size_glb)% (poly_modulus_degree_glb/2), gal_keys);
                evaluator.add_inplace(random_preprocessed_partitions[0][jj], tmp);
            }
        }

        for (int ii = 0; ii < sqrt_attr_size_glb; ii++) {
            for (int jj = 0 ; jj < preprocessed_partitioned_labels[0].size(); jj++) {
                for (int kk = 0; kk < preprocessed_partitioned_labels[0][0].size(); kk++) {
                    Plaintext pll;
                    pll.resize(poly_modulus_degree_glb);
                    pll.parms_id() = parms_id_zero;
                    for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
                        pll.data()[i] = 1;
                    }
                    Ciphertext tmp = preprocessed_partitioned_labels[0][jj][kk];
                    evaluator.multiply_plain_inplace(tmp, pll);
                    evaluator.rotate_rows_inplace(tmp, (data_size_glb * value_size_glb)% (poly_modulus_degree_glb/2), gal_keys);
                    evaluator.add_inplace(random_preprocessed_partitioned_labels[0][jj][kk], tmp);
                }
            }
        }
    }

    time_end = chrono::high_resolution_clock::now();
	// cout << "   re-select attributes time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us.\n";

}

