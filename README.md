# Secure Private Random Forest Training via FHE and MPC

Code and artifact of the paper *Secure Private Random Forest Training via FHE and MPC*: random forest training in which
the servers compute the Gini statistics of all candidate splits under (BGV) fully homomorphic encryption, while the
final squarings and the best-split selection (argmax) run in maliciously secure MPC (Shamir secret sharing with MAC,
MP-SPDZ), together with checks of the integrity of the inputs.

This README explains how to reproduce the runtime results of the evaluation section: **Table 4** (runtime of
our protocol), **Table 5** (communication per party vs. Bhardwaj et al.) and **Figure 5** (runtime comparison) -
either fully automatically with Docker, or step by step on a manually installed machine.

- [What is reproduced, and how](#what-is-reproduced-and-how)
- [Quick start with Docker on AWS / GCP](#quick-start-with-docker-on-aws--gcp)
- [Multi-machine WAN setup (the paper's setting)](#multi-machine-wan-setup-the-papers-setting)
- [Manual installation](#manual-installation-ubuntu-2204)
- [Reproducing the results one by one](#reproducing-the-results-one-by-one)
- [Private model](#private-model-selection-vector-update-without-opening-the-split)
- [Troubleshooting](#troubleshooting)

## Repository layout

| Path | Content |
|---|---|
| `main_integrity.cpp` | FHE part of the protocol (SEAL, BGV, t = 65537, N = 16384) incl. the input integrity check; built as `build/ppml` |
| `util.h`, `global.h`, `ring_switch.h`, `oblivious_multi.h`, `share_select.h` | FHE building blocks (one-hot packing, selection vector update, ring switching, private-model selection) |
| `test_*.cpp` | standalone tests / microbenchmarks (`build/test_share`, `build/test_omulti`, ...) |
| `main.cpp`, `main_ckks.cpp`, `main_matvec.cpp`, `main_extract_ops*.cpp`, `benchmark.cpp` | earlier prototypes, not built and not used for the paper |
| `mpc/` | our fork of [MP-SPDZ](https://github.com/data61/MP-SPDZ) 0.4.1 with the MPC programs `Programs/Source/bench_fhe.py` (MPC part of our protocol), `bench_fhe_naive.py` (MPC-only baseline), `bench_input.py` (input sharing), `bench_onehot.py` (private model); see also [`mpc/README.md`](mpc/README.md) |
| `scripts/` | reproduction scripts (all have `--help`), parameters (`datasets.csv`), baseline numbers that are not re-measured (`baselines_reported.csv`), values printed in the paper (`paper_reference.csv`) |
| `Dockerfile` | the artifact image (Ubuntu 22.04): SEAL 4.1.2, `ppml`, MP-SPDZ, the Bhardwaj et al. baseline, the scripts |
| `related-work/` | optional separate image with other related work (Hamada et al., Abspoel et al., MPyC RF, the code of Akavia et al.); not needed for the paper's results |

## What is reproduced, and how

All experiments train a random forest of **100 trees** (10 servers, 10 trees each) on four UCI datasets with
√A randomly chosen attributes per node, without and with binning into 8 bins, for tree depths 4, 5, 6.

| Dataset | `ppml` id | n | m (= A) | α (values per attribute) | t (labels) |
|---|---|---|---|---|---|
| iris | 1 | 100 | 4 | 9 | 3 |
| wine | 2 | 119 | 13 | 11 | 3 |
| cancer | 3 | 380 | 30 | 18 | 2 |
| digits | 4 | 1203 | 64 | 17 | 10 |

With 8 bins, α = 8. The scripts take these parameters from `scripts/datasets.csv`; `ppml` sets its own
(`main_integrity.cpp`, selected by the dataset id).

| Paper | Quantity | How it is obtained | Command (stage) | Output |
|---|---|---|---|---|
| Table 4, "FHE" | runtime of the FHE part | **measured**: `ppml <id> <d> <bins> 1 0 16384 0` (mode 0 = split opened, as in the paper); training + labeling + packing + integrity check | `scripts/run_fhe.sh` (`fhe`) | `results/table4.{tex,csv}` |
| Table 4, "MPC" | runtime of the MPC part | **measured**: MP-SPDZ `bench_fhe n m α t d`, 10 parties, `sy-shamir-party.x`, 128-bit prime; `Time =` of party 0 | `scripts/run_mpc.sh` (`mpc`) | `results/table4.{tex,csv}` |
| Table 5, "Ours MPC" | communication per party | **measured**: `Data sent` of party 0 in the same runs (no binning) | `scripts/run_mpc.sh` (`mpc`) | `results/table5.{tex,csv}` |
| Table 5, "Ours FHE" | communication per party | **computed**: secret sharing of the decrypted FHE results, 2Tαnm + T(2^d-1)(4α⌊√m⌋tn + nt + α⌊√m⌋t) field elements (T = 10 trees per party) sent to 9 parties, 16 bytes each (formula of `mpc/Programs/Source/bench_input.py`; GB = 2^30 bytes) | `scripts/make_results.py` | `results/table5.{tex,csv}` |
| Table 5, "[7]" | communication per party, Bhardwaj et al. (CCS'24) | **measured** for one tree with their implementation ([MP-SPDZ PR #1449](https://github.com/data61/MP-SPDZ/pull/1449)), `bench-dt n m d`, 3 parties, `ps-rep-ring` (malicious, 1 corruption), times 100 trees (the protocol is data-oblivious, every tree costs the same) | `scripts/run_baselines.sh` (`baselines`) | `results/table5.{tex,csv}` |
| Figure 5, "Ours" / "Ours (8 bins)" | runtime | **measured**: FHE + MPC of Table 4 at the figure depth | stages `fhe`, `mpc` | `results/figure5.{png,pdf,csv}` |
| Figure 5, "MPC-only" (+ 8 bins) | runtime | **measured**: MP-SPDZ `bench_fhe_naive n m α t d bins` (whole Gini computation in MPC, same setting as ours) | `scripts/run_mpc.sh --program mpconly` (`mpc-only`) | `results/figure5.*`, `results/table_mpc_only.*` |
| Figure 5, "[7]" | runtime | **measured** as above: one tree, times 100 | `scripts/run_baselines.sh` (`baselines`) | `results/figure5.*` |
| Figure 5, "[4]" (Akavia et al.), "[39]" (Shin et al.) | runtime | **not measured by this artifact**: as stated in the paper, these are microbenchmarks of their CKKS building blocks on their reported machines, scaled to our parameters; the values of the paper's figure are in `scripts/baselines_reported.csv` and are labeled as such in `figure5.csv` and in the figure | - | `results/figure5.*` |
| Private-model section | FHE runtime, opened split vs. private model | **measured**: `ppml ... 0` vs. `ppml ... 2` | `scripts/run_fhe.sh --modes "0 2"` | `results/fhe_private_model.csv` |

`results/compare_paper.csv` lists every measured value next to the value printed in the paper (`scripts/paper_reference.csv`).

Notes:

* Figure 5 shows one tree depth; `--figure-depth` selects it (default 4). The MPC-only baseline is run at that depth
  only, unless `--full` is given (the MPC-only runs at depth 6 take more than a day for digits).
* The runtime numbers of the paper were measured on 10 AWS c6i.32xlarge instances in two regions (WAN, see
  [below](#multi-machine-wan-setup-the-papers-setting)) with 48 vCPUs per server. On a single machine, the
  MPC runtimes differ: there is no network latency, but the 10 parties share the CPUs. The FHE part is a
  single-machine computation in both settings (each server runs it locally).
* `ppml` reports the integrity-check time as `Integrity Runtime for all : <x> ms.`; the value is accumulated in
  microseconds (`main_integrity.cpp`), and `make_results.py` reads it as such. `--fhe-no-integrity` reports the
  training alone.

## Quick start with Docker on AWS / GCP

The image builds everything from source (pinned versions) and runs all experiments with one command.

**1. Start a machine.** The paper used AWS **c6i.32xlarge** (Intel Ice Lake, 128 vCPUs, 256 GiB). On GCP, an
**n2-standard-128** with minimum CPU platform *Intel Ice Lake* is the closest equivalent. Use **Ubuntu 22.04 LTS** and a
**200 GB** disk (image about 6 GB, results a few MB). Smaller machines (e.g. 32 vCPUs, 64 GB) work for `--quick`
and for the FHE part, but the 10 local MPC parties then compete for the CPUs.

**2. Install Docker and git.**
```bash
sudo apt-get update
sudo apt-get install -y docker.io git
sudo usermod -aG docker $USER && newgrp docker      # use docker without sudo
docker run --rm hello-world                          # check
```

**3. Get the code and build the image** (30-45 minutes on c6i.32xlarge; builds Boost 1.83, SEAL 4.1.2 with HEXL,
`ppml`, MP-SPDZ with `sy-shamir-party.x`, the Bhardwaj et al. fork, compiles all MPC programs and runs the unit tests
of the result scripts).
```bash
git clone --branch oblivious-update-sel https://github.com/Hybrid-PPML-RF/FHE-PPML.git   # branch with the artifact
cd FHE-PPML
docker build -t fhe-ppml --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) .
```
Build options: `--build-arg WITH_HEXL=OFF` (SEAL without Intel HEXL), `--build-arg WITH_BASELINES=0` (skip the
Bhardwaj et al. baseline), `--build-arg MARCH=x86-64-v3` (MP-SPDZ for a generic CPU instead of `-march=native`;
build the image on the machine type you run it on otherwise).

**4. Smoke test** (iris, depth 4, all stages; about 5-10 minutes):
```bash
mkdir -p results
docker run --rm -v "$PWD/results:/results" fhe-ppml --quick
ls results     # table4.tex table5.tex figure5.png ... logs/
```

**5. Full run** (Table 4, Table 5, Figure 5). It runs in the background; re-running the same command later resumes
it (configurations with a complete log are skipped, `--force` re-runs them):
```bash
docker run -d --rm --name ppml-run -v "$PWD/results:/results" fhe-ppml
docker logs -f ppml-run          # progress; Ctrl-C only stops following the log
tail -n 3 results/run_info.txt   # what ran when (the console log also ends up in docker logs only)
```
Expected time on one c6i.32xlarge (estimates from the paper's per-run times): FHE about 3 h, MPC about 1-2 h,
Bhardwaj et al. about 1 h, MPC-only at depth 4 about 10 h (digits: 9 h). Useful options (`--help` lists all):

| Option | Effect |
|---|---|
| `--stages fhe,mpc,baselines,mpc-only,results` | run a subset of the stages (e.g. `--stages fhe,mpc,results` for Table 4 only) |
| `--datasets iris,wine` / `--depths 4,5` | restrict the configurations |
| `--figure-depth 6` | depth shown in Figure 5 (MPC-only stage runs this depth) |
| `--full` | MPC-only baseline at all depths (`table_mpc_only.tex`; about 3 days) |
| `--cpus 0-47` | pin the FHE runs to 48 vCPUs, as one server of the paper |
| `--fhe-modes "0 2"` | also run the private model (`fhe_private_model.csv`) |
| `--netem-delay 25ms` | emulate the WAN latency on the loopback device (needs `docker run --cap-add NET_ADMIN`); see `scripts/wan_emulation.sh --help` for the caveats |
| `--fill-missing-from-paper` | plot the paper's value (marked with `*`) for bars that have no run yet |

**6. Results** (in `results/`, owned by root: `sudo chown -R $USER results`):

| File | Content |
|---|---|
| `table4.tex`, `table4.csv` | Table 4 (LaTeX in the paper's layout; CSV with FHE training / integrity split, MPC data sent) |
| `table5.tex`, `table5.csv` | Table 5 |
| `figure5.png`, `figure5.pdf`, `figure5.csv` | Figure 5 (CSV: value and source of every bar: measured / reported / paper) |
| `table_mpc_only.tex/.csv` | MPC-only baseline per depth |
| `compare_paper.csv` | measured vs. paper, with ratio |
| `fhe_private_model.csv` | with `--fhe-modes "0 2"` |
| `run_info.txt`, `logs/` | machine and code version, raw logs (`logs/fhe/*.log`, `logs/mpc/*/party*.log`, `logs/baselines/*/party*.log`) |

Tables and figure can be regenerated at any time from the logs, e.g. for another figure depth:
`docker run --rm -v "$PWD/results:/results" fhe-ppml make_results.py --figure-depth 6`.

Other entry points of the image: `docker run ... fhe-ppml run_fhe.sh|run_mpc.sh|run_baselines.sh|make_results.py [--help]`,
and `docker run -it ... fhe-ppml bash` for a shell (repository in `/opt/FHE-PPML`).

## Multi-machine WAN setup (the paper's setting)

The paper runs the 10 MPC parties on 10 c6i.32xlarge instances, 5 in us-west-2 (Oregon) and 5 in us-east-2 (Ohio).

1. Start 10 Ubuntu 22.04 instances (5 per region), connect the two VPCs with VPC peering (or use public IPs) and
   allow TCP ports **14000-15999** between the 10 instances in the security groups (plus ssh).
2. Install Docker on all of them (step 2 above). Build the image **once** (on `vm0`) and copy it to the others, so that
   all machines have identical binaries and the same SSL certificates for the MPC channels:
   ```bash
   for h in vm1 vm2 vm3 vm4 vm5 vm6 vm7 vm8 vm9; do docker save fhe-ppml | gzip | ssh $h 'gunzip | docker load'; done
   ```
3. Write `hosts_ssh.txt` with one ssh target per line (`ubuntu@<ip>`), party 0 first, and, if the parties should
   use other (private) addresses among themselves, `hosts_mpc.txt` with one IP per line in the same order.
4. Start all parties at once from `vm0` (or any machine with password-less ssh to all of them):
   ```bash
   scripts/launch_multihost.sh --ssh-hosts hosts_ssh.txt --mpc-hosts hosts_mpc.txt -- --quick   # test
   scripts/launch_multihost.sh --ssh-hosts hosts_ssh.txt --mpc-hosts hosts_mpc.txt               # everything
   ```
   Each machine runs `docker run --network host -v ~/results:/results fhe-ppml --party-id <i> --hosts /results/hosts.txt`
   (you can also type this yourself on every machine within a minute). All machines run the MPC stages together;
   machine 0 then runs the FHE and baseline stages and writes the tables and the figure to `~/results` on `vm0`.

Without 10 machines, `--netem-delay 25ms` (round-trip time 50 ms) with all parties on one machine approximates the
latency, but not the topology (all pairs get the delay) - see `scripts/wan_emulation.sh --help`.

## Manual installation (Ubuntu 22.04)

The same steps as the Dockerfile, on the host (paths relative to the repository root).

**1. Packages**
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git curl bzip2 pkg-config clang automake autoconf libtool m4 yasm \
    libgmp-dev libntl-dev libsodium-dev libssl-dev openssl zlib1g-dev libbz2-dev \
    python3 python3-matplotlib iproute2 util-linux
```

**2. Boost ≥ 1.75** (for MP-SPDZ's libOTe; Ubuntu 22.04 ships 1.74; on Ubuntu 24.04 use `libboost-all-dev` instead).
Do not install the `libboost-*-dev` packages of 22.04 in addition.
```bash
curl -fsSLO https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.bz2
echo "6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e  boost_1_83_0.tar.bz2" | sha256sum -c -
tar xjf boost_1_83_0.tar.bz2 && cd boost_1_83_0
./bootstrap.sh --prefix=/usr/local --with-libraries=system,thread,filesystem,iostreams,regex,chrono,atomic,date_time
sudo ./b2 -j$(nproc) -d0 link=shared,static threading=multi variant=release install && sudo ldconfig
cd ..
```

**3. Microsoft SEAL 4.1** (optionally with Intel HEXL, which accelerates SEAL with AVX-512)
```bash
git clone --depth 1 --branch v4.1.2 https://github.com/microsoft/SEAL.git
cmake -S SEAL -B SEAL/build -DCMAKE_BUILD_TYPE=Release -DSEAL_USE_INTEL_HEXL=ON
cmake --build SEAL/build -j$(nproc) && sudo cmake --install SEAL/build
```

**4. The FHE benchmark** (`build/ppml` and the tests)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release     # add -DCMAKE_PREFIX_PATH=<prefix> if SEAL is not in /usr/local
cmake --build build -j$(nproc)
```

**5. MP-SPDZ** (`mpc/sy-shamir-party.x`; fetches MP-SPDZ's dependencies at pinned commits into `mpc/deps`, uses
`MOD = -DGFP_MOD_SZ=5` from `mpc/CONFIG.mine`) and SSL certificates for 10 parties (the certificates committed in
`mpc/Player-Data` have expired; this creates new ones valid for 10 years):
```bash
scripts/build_mpspdz.sh
scripts/setup_ssl.sh 10
```

**6. Optional: the Bhardwaj et al. baseline**
```bash
sudo mkdir -p /opt/baselines && sudo chown $USER /opt/baselines
scripts/build_bhardwaj.sh            # or --dir <dir>, then export BHARDWAJ_DIR=<dir>
```

**7. Run** - the same scripts as in the image; results go to `results/` (or `$RESULTS_DIR`):
```bash
scripts/reproduce_all.sh --quick
scripts/reproduce_all.sh               # everything, see --help
```

## Reproducing the results one by one

All scripts skip configurations whose log is complete; `--dry-run` prints the commands, `--help` the options.

**Table 4, FHE column** - one configuration by hand, then all:
```bash
# ./build/ppml <dataset 1-4> <depth> <is_bin> <is_sqrt> <verify> <N> <mode>
./build/ppml 1 4 0 1 0 16384 0     # iris, depth 4, no binning, sqrt(A) attributes, public model
#   ... Training + labeling + packing total runtime: <us> us.
#   ... Integrity Runtime for all : <us> ms.      (microseconds, see above)
scripts/run_fhe.sh                                   # 4 datasets x 3 depths x 2 binnings
scripts/run_fhe.sh --datasets digits --depths 6 --bins 1 --cpus 0-47
```

**Table 4, MPC column and Table 5, "Ours MPC"** - one configuration by hand (10 parties on this machine), then all:
```bash
cd mpc
./compile.py bench_fhe 100 4 9 3 4               # n m alpha t d  (8 bins: alpha = 8)
for i in $(seq 0 9); do
  ./sy-shamir-party.x -p $i -N 10 -lgp 128 -pn 14000 -h localhost bench_fhe-100-4-9-3-4 > party$i.log 2>&1 &
done; wait
grep -E "^Time|^Data sent" party0.log
cd ..
scripts/run_mpc.sh                                   # all 24 configurations
scripts/run_mpc.sh --party-id 3 --hosts hosts.txt    # multi-machine: party 3 of the parties in hosts.txt
```

**Figure 5, MPC-only baseline**
```bash
scripts/run_mpc.sh --program mpconly --depths 4      # bench_fhe_naive n m alpha t d bins
```

**Table 5 and Figure 5, Bhardwaj et al. [7]** (one tree per dataset and depth; results scaled to 100 trees)
```bash
scripts/run_baselines.sh                             # --protocol, --threads, see --help
```

**Tables and figure**
```bash
python3 scripts/make_results.py --figure-depth 4    # reads results/logs, writes results/*.tex|csv|png
python3 scripts/tests/test_make_results.py          # unit tests of the parsers
```

## Private model (selection vector update without opening the split)
The 7th argument selects the selection vector update (arguments 5 and 6: `verify` and the ring dimension):
```
# ./ppml <dataset_no> <depth> <is_bin> <is_sqrt> <verify> <N> <mode>
./ppml 1 6 1 1 0 16384 0   # original: the split is opened, plaintext-indexed extraction
./ppml 1 6 1 1 0 16384 1   # private model, oblivious update in FHE (equality test, ring switching; util.h, oblivious_multi.h)
./ppml 1 6 1 1 0 16384 2   # private model, selection in MPC (default; share_select.h)
```
In mode 2, `BestSplit` outputs the one-hot split in shares (`ml.argmax_onehot` in `mpc/Compiler/ml.py`, a drop-in variant of
MP-SPDZ's `ml.argmax` that keeps the comparison bits of the tournament and expands them top-down instead of carrying the index;
paper, Appendix D), the servers compute the shares of the left-child indicator from their
shares of the processed data and encrypt them (packed, `floor((N/2)/n)` nodes per batching row), and the FHE update is the one of
the original path with this ciphertext as threshold data (same modulus chain). The MPC part is simulated; its cost is counted with
`mpc/Programs/Source/bench_onehot.py` (`./compile.py bench_onehot K L n mode`). Further optional arguments of mode 2:
13th = 1: every server encrypts its share already tiled (one ciphertext per node), 14th: number of servers (default 10),
15th: prime size of the modulus chain (default 34; 40 leaves noise budget for the leaf labeling at depth 6, with real data).
`verify = 1` decrypts all selection vectors and compares them with plaintext training. A fast standalone check of the update
alone (all slots of all nodes, plus per-node timings): `./test_share 16384 <n> <A> <V> <depth> [M tiled prime_bits]`.

The end-to-end comparison of mode 0 and mode 2 for all configurations: `scripts/run_fhe.sh --modes "0 2"`, then
`scripts/make_results.py` writes `results/fhe_private_model.csv`. Note that the default mode of `ppml` is 2; Table 4
uses mode 0, which the scripts pass explicitly.

### Sample output
After running `./ppml 1 6 1 1 0 16384 0`, one should see logs similar to the following (times of an 8-core laptop):
```
Start training with #attr: 2 #val: 8
Modulus chain of the data ring (N=16384): 8 primes + special = 306 bits (128-bit security bound: 438)
Encoding inputs to 1 ciphertexts...
Preprocessing for all possible threshold values...
   Input X preprocessed.
   Input Y preprocessed.
Preprocess time: 3031747 us.
	Training for level 0 with 1 nodes...
	...
	Training for level 5 with 32 nodes...
Calculating the labeling for leaf nodes...
Simulate the packing and extraction...
Training + labeling + packing total runtime: 166190891 us.

=== Integrity check: Y' x C' pipeline ===
...
Integrity Runtime for all : 2560446 ms.
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `docker: permission denied` | `sudo usermod -aG docker $USER`, then log in again (or `newgrp docker`) |
| MP-SPDZ: `certificate has expired` / SSL handshake errors | `scripts/setup_ssl.sh 10` (manual installation). On several machines all parties need the same `Player-Data/P*.pem/key`: use one image everywhere, or generate once and pass `--ssl-dir` to `run_mpc.sh` / `reproduce_all.sh` |
| MP-SPDZ: `Not compiled for 128-bit primes` | `mpc/CONFIG.mine` must contain `MOD = -DGFP_MOD_SZ=5`; rebuild with `scripts/build_mpspdz.sh` |
| multi-machine: connection timeouts | open TCP 14000-15999 between the machines; start all parties within 60 s of each other (`launch_multihost.sh` does); run the same options on all machines (also `--force`), so that all skip the same configurations |
| `Illegal instruction` | the image / MP-SPDZ was built with `-march=native` on a different CPU: rebuild on the target machine type, or with `--build-arg MARCH=x86-64-v3` |
| MP-SPDZ build fails in libOTe / boost | Boost ≥ 1.75 must be installed (manual installation, step 2) |
| a stage failed | re-run the same command: only the missing configurations run; failed attempts are kept as `*.partial` in `results/logs` |
| `results/` owned by root | `sudo chown -R $USER results` |
| figure missing | needs matplotlib (`python3-matplotlib`); `figure5.csv` is written without it |
| `tc` / netem: `Operation not permitted` | `docker run --cap-add NET_ADMIN ...` |

## Dependencies (versions in the Docker image)

Ubuntu 22.04 (GCC 11, clang 14, CMake 3.22, Python 3.10, NTL 11.5, GMP 6.2, OpenSSL 3.0), Boost 1.83.0,
[Microsoft SEAL](https://github.com/microsoft/SEAL) 4.1.2 (with [Intel HEXL](https://github.com/intel/hexl) 1.2.5 by
default), MP-SPDZ 0.4.1 (fork in `mpc/`; dependencies pinned in `scripts/build_mpspdz.sh`), the MP-SPDZ fork of
Bhardwaj et al. at commit `87d1e5c` (`scripts/build_bhardwaj.sh`). Earlier versions of this code also used
[PALISADE](https://gitlab.com/palisade/palisade-release); it is not needed anymore.
