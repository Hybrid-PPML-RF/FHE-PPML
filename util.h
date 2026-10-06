#pragma once
#include <functional>
#include <string>
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

    NTL::SetNumThreads(min(num_cores, val_size));
    NTL_EXEC_RANGE(min(num_cores, val_size), first, last);
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
    NTL_EXEC_RANGE(min(num_cores, val_size), first, last);
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

    partitions_for_node.resize((int) preprocessed_partitions.size());
    for (int cnt = 0; cnt < (int) preprocessed_partitions.size(); cnt++) {
        partitions_for_node[cnt].resize((int) preprocessed_partitions[cnt].size());
    }
    partition_labels_for_node.resize((int) preprocessed_partitioned_labels.size());
    for (int cnt = 0; cnt < (int) preprocessed_partitioned_labels.size(); cnt ++) {
        partition_labels_for_node[cnt].resize(label_size_glb, vector<Ciphertext>((int) preprocessed_partitioned_labels[0][0].size()));
    }

    // multi_thread = false;

    if (multi_thread) {
        const size_t partition_size = preprocessed_partitions[0].size();
        const long long end = min(static_cast<int>(partition_size), num_cores);
        NTL::SetNumThreads(end);
        int thread_chunk_size_1 = (int) preprocessed_partitions[0].size() / end;
        int thread_chunk_size_2 = (int) preprocessed_partitioned_labels[0][0].size() / end;

        NTL_EXEC_RANGE(end, first, last);
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
        NTL_EXEC_RANGE(end, first, last);
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
                                            bool multi_thread = false, bool is_digits = false) {
    int packed = 2 * (floor((double)(poly_modulus_degree_glb/2) / (double) (data_size_glb*value_size_glb)));
    int num_ct = is_digits ? 8 : ceil((double) (sqrt_attr_size_glb) / (double) packed );
    

    random_preprocessed_partitions.resize(num_ct);
    random_preprocessed_partitioned_labels.resize(num_ct);
    for (int i = 0; i < (int) random_preprocessed_partitions.size(); i++) {
        random_preprocessed_partitions[i].resize(preprocessed_partitions[0].size());
        for (int j = 0; j < (int) random_preprocessed_partitions[i].size(); j++) {
            random_preprocessed_partitions[i][j] = preprocessed_partitions[0][j];
        }
        random_preprocessed_partitioned_labels[i].resize(preprocessed_partitioned_labels[0].size());
        for (int j = 0; j < (int) random_preprocessed_partitioned_labels[i].size(); j++) {
            random_preprocessed_partitioned_labels[i][j].resize((int)preprocessed_partitioned_labels[0][j].size());
            for (int k = 0; k < (int) random_preprocessed_partitioned_labels[i][j].size(); k++) {
                random_preprocessed_partitioned_labels[i][j][k] = preprocessed_partitioned_labels[0][j][k];
            }
        }
    }

    if (sqrt_attr_size_glb == attr_size_glb) {
        return;
    }

    chrono::high_resolution_clock::time_point time_start, time_end;
    time_start = chrono::high_resolution_clock::now();   

    if (multi_thread) {
        NTL::SetNumThreads(min(sqrt_attr_size_glb, num_cores));
        NTL_EXEC_RANGE(min(sqrt_attr_size_glb, num_cores), first, last);
        int thread_chunk_size_1 = sqrt_attr_size_glb / min(sqrt_attr_size_glb, num_cores);
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



// =====================================================================================================================
//  OBLIVIOUS selection-vector update  (UpdateSel of Algorithm 6 in the paper, but the split (iota*, theta*) stays secret)
// =====================================================================================================================
//
//  Data layout (unchanged from the rest of the repo, one ciphertext for iris):
//      slot  a * V * n  +  v * n  +  j        a = attribute, v = value, j = datapoint,   n = data_size, V = value_size
//  Preprocessed partitions: preprocessed_partitions[0][2*theta-1] holds, in the first n slots of every attribute chunk
//  (slot a*V*n + j), the indicator "x_{j,a} < theta"  (all other slots of the chunk are garbage).
//
//  Pipeline for ONE tree node (all inputs are ciphertexts, nothing about the split is ever in the clear):
//
//    0. (offline, once)  P := packed "left" partitions.  P has the same layout as X: slot a*V*n + theta*n + j equals
//                        [x_{j,a} < theta]  (zero for theta = 0, and zero outside [0, A*V*n)).  See build_oblivious_sel_ctx.
//    1. r  = (attr * V + theta) * n                   (slot 0 only; linear in the two fresh input ciphertexts)
//    2. ObliviousRotation:   (r,0,..,0)  ->  (0,..,0,1,0,..,0)   with the single 1 at slot r      [Qelect, 16 squarings]
//    3. rotation_and_add:    (0,..,1,..,0) -> selector = n consecutive ones at slots [r, r+n)
//    4. E = selector * P  (CT x CT)                    -> only block (attr, theta) of P survives
//    5. fold E over all A*V blocks into block 0, mask block 0, then tile it back over all A*V blocks
//       => T = the n-bit left-child indicator, repeated (period n) over the whole packed region
//    6. S_left  = S_parent * T       (CT x CT)
//       S_right = S_parent - S_left  (children partition the parent, so no second oblivious extraction is needed)
//
//  Rows: everything lives in the first batching row (slots [0, N/2)); that is enough for iris (A*V*n = 3200 < 8192).
// =====================================================================================================================

// Optional debugging hook (e.g. to print the noise budget after each stage).  Empty by default.
static std::function<void(const std::string&, const Ciphertext&)> oblivious_trace_glb;
#define OBL_TRACE(name, ct) do { if (oblivious_trace_glb) oblivious_trace_glb(name, ct); } while (0)

// every cached plaintext / ciphertext the oblivious update needs; built once by build_oblivious_sel_ctx
struct ObliviousSelCtx {
    Plaintext idx_pl;               // slot j  ->  j                      (the "[0, 1, ..., N-1]" vector of Qelect)
    Plaintext ones_pl;              // all slots = 1
    Plaintext first_block_mask_pl;  // slots [0, n) = 1, otherwise 0
    Ciphertext packed_partitions;   // P, see above
    int fermat_switch_every = 1;    // mod-switch after every k-th squaring of the x^(p-1) evaluation
};

inline int obl_norm_step(long long s) {  // keep the sign, make |step| < N/2
    return (int) (s % (long long) (poly_modulus_degree_glb / 2));
}

inline int obl_chain_index(const SEALContext& context, const Ciphertext& ct) {
    return (int) context.get_context_data(ct.parms_id())->chain_index();
}

// mod-switch whichever of the two ciphertexts is on the higher level down to the level of the other
inline void obl_match_levels(const SEALContext& context, Evaluator& evaluator, Ciphertext& a, Ciphertext& b) {
    int ia = obl_chain_index(context, a), ib = obl_chain_index(context, b);
    if (ia > ib) evaluator.mod_switch_to_inplace(a, b.parms_id());
    else if (ib > ia) evaluator.mod_switch_to_inplace(b, a.parms_id());
}

// plaintext that is the constant polynomial c  (== multiplying every slot by c)
inline Plaintext obl_const_plain(uint64_t c) {
    Plaintext pl(1);
    pl[0] = c;
    return pl;
}

// sum_{k=0}^{len-1} rotate_rows(ct, sign * k * unit), using O(log len) rotations.
// sign = +1: slot s gets sum of ct[s], ct[s+unit], ..., ct[s+(len-1)*unit]   (the "forward" window of rotation_and_add)
// sign = -1: slot s gets sum of ct[s], ct[s-unit], ..., ct[s-(len-1)*unit]   (copies a block "to the right")
inline vector<int> obl_window_sum_steps(int len, int unit, int sign) {
    vector<int> steps;
    if (len <= 1) return steps;
    int hb = 0;
    while ((1 << (hb + 1)) <= len) hb++;
    for (int i = 0; i < hb; i++) steps.push_back(obl_norm_step((long long) sign * (1 << i) * unit));
    int offs = 0;
    for (int i = hb; i >= 0; i--) {
        if ((len >> i) & 1) {
            if (offs) steps.push_back(obl_norm_step((long long) sign * offs * unit));
            offs += (1 << i);
        }
    }
    return steps;
}

inline Ciphertext obl_window_sum(Evaluator& evaluator, const Ciphertext& input, int len, int unit, int sign,
                                 const GaloisKeys& gal_keys) {
    if (len <= 1) return input;
    int hb = 0;
    while ((1 << (hb + 1)) <= len) hb++;

    // w[i] = window of 2^i shifts
    vector<Ciphertext> w(hb + 1);
    w[0] = input;
    for (int i = 1; i <= hb; i++) {
        Ciphertext rot;
        evaluator.rotate_rows(w[i-1], obl_norm_step((long long) sign * (1 << (i-1)) * unit), gal_keys, rot);
        evaluator.add(w[i-1], rot, w[i]);
    }

    // the binary expansion of len, from the highest bit down; each piece is shifted by the length already covered
    Ciphertext result;
    bool init = false;
    int offs = 0;
    for (int i = hb; i >= 0; i--) {
        if (!((len >> i) & 1)) continue;
        Ciphertext term = w[i];
        if (offs) evaluator.rotate_rows_inplace(term, obl_norm_step((long long) sign * offs * unit), gal_keys);
        if (!init) { result = term; init = true; }
        else evaluator.add_inplace(result, term);
        offs += (1 << i);
    }
    return result;
}

// (r, 0, ..., 0)  ->  (r, r, ..., r, 0, ..., 0) with r in all N/2 slots of the first row (13 rotations for N = 16384)
inline vector<int> obl_expand_steps() {
    vector<int> steps;
    for (int i = 0; (1 << i) < (int) (poly_modulus_degree_glb / 2); i++) steps.push_back(-(1 << i));
    return steps;
}

inline Ciphertext obl_expand_first_slot_to_row(Evaluator& evaluator, const Ciphertext& input, const GaloisKeys& gal_keys) {
    Ciphertext out = input, rot;
    for (int i = 0; (1 << i) < (int) (poly_modulus_degree_glb / 2); i++) {
        evaluator.rotate_rows(out, -(1 << i), gal_keys, rot);
        evaluator.add_inplace(out, rot);
    }
    return out;
}

// All Galois steps the oblivious update needs (add them to the GaloisKeys that are passed to the functions below).
inline vector<int> oblivious_update_rotation_steps(int data_size, int attr_size, int val_size) {
    vector<int> steps = obl_expand_steps();
    for (int s : obl_window_sum_steps(data_size, 1, -1)) steps.push_back(s);                      // selector (n ones)
    for (int s : obl_window_sum_steps(attr_size * val_size, data_size, +1)) steps.push_back(s);   // fold  into block 0
    for (int s : obl_window_sum_steps(attr_size * val_size, data_size, -1)) steps.push_back(s);   // tile  from block 0
    steps.push_back(obl_norm_step(-data_size));                                                    // building P
    return steps;
}

// ObliviousRotation (Qelect, MPE_docker_version.cpp l.227-235):
//   input : ct_r encrypting (r, 0, ..., 0),  0 <= r < N/2
//   output: ct encrypting the unit vector e_r  (1 at slot r, 0 elsewhere, every slot of both rows)
// Evaluates 1 - (j - r)^(p-1) in every slot j  (Fermat: x^(p-1) = 1 for x != 0 mod p) -- log2(p-1) = 16 squarings for p = 65537.
inline Ciphertext oblivious_rotation(const SEALContext& context, Evaluator& evaluator, const ObliviousSelCtx& oc,
                                     const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const Ciphertext& ct_r) {
    uint64_t t = context.first_context_data()->parms().plain_modulus().value();
    int num_sq = 0;
    while (((uint64_t) 1 << num_sq) < t - 1) num_sq++;
    if (((uint64_t) 1 << num_sq) != t - 1) throw invalid_argument("oblivious_rotation: plain modulus - 1 must be a power of 2");

    Ciphertext x = obl_expand_first_slot_to_row(evaluator, ct_r, gal_keys);   // slots [0, N/2): r;  second row: 0
    OBL_TRACE("expanded r", x);
    evaluator.negate_inplace(x);
    evaluator.add_plain_inplace(x, oc.idx_pl);                                // slot j: j - r  (second row: j, never 0)
    OBL_TRACE("j - r", x);

    for (int i = 0; i < num_sq; i++) {
        evaluator.square_inplace(x);
        evaluator.relinearize_inplace(x, relin_keys);
        if ((i + 1) % oc.fermat_switch_every == 0 && obl_chain_index(context, x) > 0) {
            evaluator.mod_switch_to_next_inplace(x);
        }
        if (i == 0 || i == num_sq / 2 - 1 || i == num_sq - 1) OBL_TRACE("square " + to_string(i + 1), x);
    }

    evaluator.negate_inplace(x);
    evaluator.add_plain_inplace(x, oc.ones_pl);                               // 1 - (j-r)^(p-1)  =  [j == r]
    OBL_TRACE("unit vector", x);
    return x;
}

// the unit vector e_r  ->  n consecutive ones at [r, r+n)   (rotation + add, no multiplication)
inline Ciphertext oblivious_selector(const SEALContext& context, Evaluator& evaluator, const ObliviousSelCtx& oc,
                                     const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const Ciphertext& ct_r,
                                     int data_size) {
    Ciphertext unit_vec = oblivious_rotation(context, evaluator, oc, relin_keys, gal_keys, ct_r);
    Ciphertext selector = obl_window_sum(evaluator, unit_vec, data_size, 1, -1, gal_keys);
    OBL_TRACE("selector", selector);
    return selector;
}

// selector (n ones at block (attr, theta)) x P  ->  the n-bit left-child indicator, tiled with period n over the packed region
inline Ciphertext oblivious_extract_threshold_data(const SEALContext& context, Evaluator& evaluator, const ObliviousSelCtx& oc,
                                                   const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                                                   const Ciphertext& selector, int data_size, int attr_size, int val_size) {
    Ciphertext sel_local = selector, packed = oc.packed_partitions, extracted;
    obl_match_levels(context, evaluator, sel_local, packed);
    evaluator.multiply(sel_local, packed, extracted);
    evaluator.relinearize_inplace(extracted, relin_keys);
    evaluator.mod_switch_to_next_inplace(extracted);
    OBL_TRACE("selector x P", extracted);

    // only block (attr, theta) is non-zero; adding up all A*V blocks moves it to block 0 (blocks 0..b of the result hold it)
    int blocks = attr_size * val_size;
    extracted = obl_window_sum(evaluator, extracted, blocks, data_size, +1, gal_keys);
    // keep only block 0 (CT x PT with a batch-encoded 0/1 mask), otherwise the tiling below would count the block several times
    evaluator.multiply_plain_inplace(extracted, oc.first_block_mask_pl);
    evaluator.mod_switch_to_next_inplace(extracted);
    OBL_TRACE("fold + mask", extracted);
    // chunk of n slots -> repeated over all A*V blocks (so it lines up with every attribute chunk of the partitions)
    extracted = obl_window_sum(evaluator, extracted, blocks, data_size, -1, gal_keys);
    OBL_TRACE("threshold data", extracted);
    return extracted;
}

// Oblivious replacement of update_selection_vector: the split is given as two fresh ciphertexts
//   ct_attr_ind = Enc(threshold_attr_ind, 0, ..., 0)        attribute index in [0, A)
//   ct_val_ind  = Enc(threshold_val_ind,  0, ..., 0)        split is  x < theta  /  x >= theta,  theta in [1, V-1]
// Writes the left child  (x_attr <  theta)  to selection_vector[2*parent+1]
//        the right child (x_attr >= theta)  to selection_vector[2*parent+2].
inline void oblivious_update_selection_vector(vector<Ciphertext>& selection_vector, const ObliviousSelCtx& oc,
                                              const Ciphertext& ct_attr_ind, const Ciphertext& ct_val_ind,
                                              int cur_depth, int curr_node, const SEALContext& context, Evaluator& evaluator,
                                              const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                                              int data_size = data_size_glb, int attr_size = attr_size_glb,
                                              int val_size = value_size_glb) {
    int parent_sel_ind = (1 << cur_depth) - 1 + curr_node;
    int child_sel_ind = parent_sel_ind * 2 + 1;

    // slot of the first datapoint of block (attr, theta) in P:  r = (attr * V + theta) * n.  Linear => plaintext scalars only.
    Ciphertext ct_r, tmp;
    evaluator.multiply_plain(ct_attr_ind, obl_const_plain((uint64_t) val_size * data_size), ct_r);
    evaluator.multiply_plain(ct_val_ind, obl_const_plain((uint64_t) data_size), tmp);
    evaluator.add_inplace(ct_r, tmp);
    OBL_TRACE("r", ct_r);

    Ciphertext selector = oblivious_selector(context, evaluator, oc, relin_keys, gal_keys, ct_r, data_size);
    Ciphertext threshold_data = oblivious_extract_threshold_data(context, evaluator, oc, relin_keys, gal_keys, selector,
                                                                 data_size, attr_size, val_size);

    Ciphertext parent = selection_vector[parent_sel_ind];
    obl_match_levels(context, evaluator, parent, threshold_data);
    evaluator.multiply(parent, threshold_data, selection_vector[child_sel_ind]);
    evaluator.relinearize_inplace(selection_vector[child_sel_ind], relin_keys);
    evaluator.mod_switch_to_next_inplace(selection_vector[child_sel_ind]);
    OBL_TRACE("left child", selection_vector[child_sel_ind]);

    // right = parent - left  (the two children partition the parent's datapoints)
    evaluator.mod_switch_to_inplace(parent, selection_vector[child_sel_ind].parms_id());
    evaluator.sub(parent, selection_vector[child_sel_ind], selection_vector[child_sel_ind + 1]);
}

// Build everything the oblivious update caches: the batch-encoded constant vectors and the packed partitions P.
// P is obtained from the already preprocessed partitions (only the "x < theta" ones, odd indices 2*theta-1):
//     P = sum_{theta=1}^{V-1}  rotate_right( first_block_of_every_attribute_chunk(partitions[0][2*theta-1]),  theta * n )
// (Horner scheme: V-1 rotations by the single step -n.)   Only the single-ciphertext case (iris) is handled.
inline void build_oblivious_sel_ctx(ObliviousSelCtx& oc, vector<vector<Ciphertext>>& preprocessed_partitions,
                                    const SEALContext& context, Evaluator& evaluator, BatchEncoder& batch_encoder,
                                    const GaloisKeys& gal_keys, int data_size = data_size_glb, int attr_size = attr_size_glb,
                                    int val_size = value_size_glb) {
    if (preprocessed_partitions.size() != 1) throw invalid_argument("oblivious update: inputs must fit in one ciphertext");
    if ((size_t) attr_size * val_size * data_size > poly_modulus_degree_glb / 2)
        throw invalid_argument("oblivious update: A*V*n must fit in one batching row");

    size_t N = poly_modulus_degree_glb;
    vector<uint64_t> vec(N);

    for (size_t j = 0; j < N; j++) vec[j] = j;
    batch_encoder.encode(vec, oc.idx_pl);
    for (size_t j = 0; j < N; j++) vec[j] = 1;
    batch_encoder.encode(vec, oc.ones_pl);
    for (size_t j = 0; j < N; j++) vec[j] = (j < (size_t) data_size) ? 1 : 0;
    batch_encoder.encode(vec, oc.first_block_mask_pl);

    // keeps the first n slots of every attribute chunk (the only slots of the partitions that are meaningful)
    Plaintext chunk_start_mask;
    for (size_t j = 0; j < N; j++) vec[j] = (j < (size_t) attr_size * val_size * data_size && (j % ((size_t) val_size * data_size)) < (size_t) data_size) ? 1 : 0;
    batch_encoder.encode(vec, chunk_start_mask);

    Ciphertext acc;
    for (int theta = val_size - 1; theta >= 1; theta--) {
        Ciphertext masked;
        evaluator.multiply_plain(preprocessed_partitions[0][2 * theta - 1], chunk_start_mask, masked);
        if (theta == val_size - 1) {
            acc = masked;
        } else {
            evaluator.rotate_rows_inplace(acc, obl_norm_step(-data_size), gal_keys);
            evaluator.add_inplace(acc, masked);
        }
    }
    evaluator.rotate_rows_inplace(acc, obl_norm_step(-data_size), gal_keys);
    oc.packed_partitions = acc;
}

// ---- plaintext reference for testing (needs the secret key: only used in the single-process simulation) ----

// x[j][a] = value of attribute a of datapoint j, recovered from the one-hot ciphertext inputs_X[0]
inline vector<vector<int>> obl_decode_dataset(const Ciphertext& input_x, Decryptor& decryptor, BatchEncoder& batch_encoder,
                                              int data_size = data_size_glb, int attr_size = attr_size_glb, int val_size = value_size_glb) {
    Plaintext pl;
    vector<uint64_t> dec;
    decryptor.decrypt(input_x, pl);
    batch_encoder.decode(pl, dec);
    vector<vector<int>> x(data_size, vector<int>(attr_size, -1));
    for (int a = 0; a < attr_size; a++)
        for (int v = 0; v < val_size; v++)
            for (int j = 0; j < data_size; j++)
                if (dec[(size_t) a * val_size * data_size + v * data_size + j] == 1) x[j][a] = v;
    return x;
}

// Re-trains the selection vectors in the clear (root = everything; node i splits on x[.][split_attr[i]] < split_val[i]) and
// compares with the decrypted selection vectors of all nodes below the root, in every block of the packed region.
// Returns the number of wrong slots (0 = the oblivious update is correct).  Levels 0 .. depth-2 hold splits.
inline int verify_oblivious_selection_vectors(const vector<Ciphertext>& selection_vector, const vector<int>& split_attr,
                                              const vector<int>& split_val, const vector<vector<int>>& x, int depth,
                                              Decryptor& decryptor, BatchEncoder& batch_encoder, const SEALContext& context,
                                              int data_size = data_size_glb, int attr_size = attr_size_glb, int val_size = value_size_glb) {
    int num_nodes = (1 << depth) - 1;     // nodes of the first depth levels; internal ones: first 2^(depth-1) - 1
    vector<vector<int>> expected(num_nodes, vector<int>(data_size, 0));
    fill(expected[0].begin(), expected[0].end(), 1);
    Plaintext pl;
    vector<uint64_t> dec;
    int wrong = 0;
    for (int parent = 0; parent < (1 << (depth - 1)) - 1; parent++) {
        for (int j = 0; j < data_size; j++) {
            bool in_left = x[j][split_attr[parent]] < split_val[parent];
            expected[2 * parent + 1][j] = expected[parent][j] && in_left;
            expected[2 * parent + 2][j] = expected[parent][j] && !in_left;
        }
        for (int c = 2 * parent + 1; c <= 2 * parent + 2; c++) {
            decryptor.decrypt(selection_vector[c], pl);
            batch_encoder.decode(pl, dec);
            for (int blk = 0; blk < attr_size * val_size; blk++)
                for (int j = 0; j < data_size; j++)
                    if ((int) dec[(size_t) blk * data_size + j] != expected[c][j]) wrong++;
        }
    }
    return wrong;
}
