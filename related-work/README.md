# Related-Work: Private Decision Tree / Random Forest Training

Docker image that wraps the publicly available implementations of related work
cited in *Private Random Forest Training via FHE and MPC*.

## What is included

| Paper | Algorithm | Source |
|---|---|---|
| Hamada et al. PoPETs 2023 | `TreeTrainer` in MP-SPDZ | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) |
| Abspoel et al. PoPETs 2021 | `TreeClassifier` in MP-SPDZ | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) |
| Bhardwaj et al. CCS 2024 | PR #1449 on fork | [sandy9999/MP-SPDZ](https://github.com/sandy9999/MP-SPDZ), branch `PrivateDT` |
| Abspoel et al. RF variant | MPyC implementation | [philips-software/random_forest](https://github.com/philips-software/random_forest) |
| Akavia et al. TOPSEC 2022 | CKKS/SEAL FHE training | [intuit/Decision-Trees-over-FHE](https://github.com/intuit/Decision-Trees-over-FHE) |

**No public code available for:** Hashemi/Shin et al. ESORICS 2024.

## Build

```bash
docker build -t ppml-related-work .
```

The build clones and compiles MP-SPDZ from source. Expect **20–40 minutes** on a
modern machine. The Bhardwaj fork is cloned at build time; if it is unreachable
the build still succeeds and that algorithm falls back to Hamada.

## Options

| Flag | Values | Default | Description |
|---|---|---|---|
| `--algorithm` | `hamada` \| `abspoel` \| `bhardwaj` \| `mpyc-rf` \| `akavia` | `hamada` | Which protocol to run |
| `--dataset` | `iris` \| `wine` \| `cancer` \| `digits` | `iris` | UCI dataset |
| `--depth` | integer | `6` | Maximum tree depth |
| `--num-trees` | integer | `1` | Number of trees (`>1` trains a random forest) |
| `--protocol` | `ring` \| `semi2k` | `ring` | MPC protocol |
| `--threads` | integer | `1` | OMP threads inside MP-SPDZ |

**Protocols:**
- `ring` — 3-party honest-majority replicated secret sharing over a ring (matches the paper's comparison setting)
- `semi2k` — 2-party semi-honest over Z_{2^k} (faster, weaker security, good for local timing)

`--protocol` is ignored for `--algorithm akavia` (FHE-only, no MPC).

## Examples

```bash
# Single decision tree — Hamada et al., iris, depth 6, 3-party ring
docker run ppml-related-work \
  --algorithm hamada --dataset iris --depth 6

# Random forest — 10 trees, wine, depth 4
docker run ppml-related-work \
  --algorithm hamada --dataset wine --depth 4 --num-trees 10

# Abspoel et al. — cancer, depth 5
docker run ppml-related-work \
  --algorithm abspoel --dataset cancer --depth 5

# Bhardwaj et al. — digits, depth 6 (improved communication over Hamada)
docker run ppml-related-work \
  --algorithm bhardwaj --dataset digits --depth 6

# MPyC random forest — Abspoel RF variant, 5 trees
docker run ppml-related-work \
  --algorithm mpyc-rf --dataset iris --num-trees 5 --depth 4

# Fast local benchmark using semi-honest 2-party protocol
docker run ppml-related-work \
  --algorithm hamada --dataset cancer --depth 6 --protocol semi2k
```

## Datasets

Downloaded automatically via scikit-learn at container runtime. Features are
min-max scaled to integers in `[0, 255]`. An 80/20 train/test split is applied
with seed 42.

| Dataset | Samples (train) | Features | Classes |
|---|---|---|---|
| iris | 120 | 4 | 3 |
| wine | 142 | 13 | 3 |
| cancer | 455 | 30 | 2 |
| digits | 1437 | 64 | 10 |

## File structure

```
related-work/
├── Dockerfile                       # builds MP-SPDZ (main + Bhardwaj fork) and MPyC RF
├── entrypoint.sh                    # CLI dispatcher
├── prepare_data.py                  # downloads UCI datasets, writes MP-SPDZ input format
├── run_mpyc_rf.py                   # MPyC random forest wrapper
└── mpc_programs/
    ├── dt_train.mpc                 # Hamada et al. single tree
    ├── dt_train_abspoel.mpc         # Abspoel et al. single tree
    ├── dt_train_bhardwaj.mpc        # Bhardwaj et al. single tree (Bhardwaj fork only)
    └── rf_train.mpc                 # Random forest: n_trees × Hamada, ceil(√m) features/tree
```

## Notes

- Random forest feature bagging uses `ceil(√m)` features per tree, selected at
  compile time with seed 42 (not secret). Bootstrap sampling is disabled.
- The Bhardwaj et al. improvement is in the fork's `Compiler/decision_tree.py`;
  the `.mpc` program is structurally identical to `dt_train.mpc`.
- Wall-clock time is printed at the end of each run; MP-SPDZ also reports
  per-party communication cost in its own output.
