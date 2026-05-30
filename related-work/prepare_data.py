#!/usr/bin/env python3
"""
Download UCI datasets (Iris, Wine, Breast Cancer, Digits) and write them
to MP-SPDZ's party-input format:
  Player-Data/Input-P0-0   one value per line, in order:
      feat_0 ... feat_{m-1} label  (per sample, repeated for all samples)

Also supports --info-only to print "n_train m n_classes" for shell scripts.

Feature scaling: min-max to integer range [0, scale_max] (default 255).
"""

import argparse, sys, math
import numpy as np
from sklearn import datasets
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

DATASETS = {
    "iris":    {"loader": datasets.load_iris,          "n": 150,  "m": 4,  "k": 3},
    "wine":    {"loader": datasets.load_wine,          "n": 178,  "m": 13, "k": 3},
    "cancer":  {"loader": datasets.load_breast_cancer, "n": 569,  "m": 30, "k": 2},
    "digits":  {"loader": datasets.load_digits,        "n": 1797, "m": 64, "k": 10},
}

def load_and_scale(name: str, scale_max: int = 255, seed: int = 42):
    meta = DATASETS[name]
    data = meta["loader"]()
    X, y = data.data, data.target.astype(np.int64)

    # Scale features to [0, scale_max] and convert to integers
    scaler = MinMaxScaler(feature_range=(0, scale_max))
    X_scaled = np.round(scaler.fit_transform(X)).astype(np.int64)

    # 80/20 train/test split (reproducible)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y, test_size=0.2, random_state=seed, stratify=y
    )
    return X_tr, X_te, y_tr, y_te, meta["k"]


def write_mpspdz_input(X_train, y_train, output_path: str):
    """Write one value per line: features then label, repeated per sample."""
    with open(output_path, "w") as f:
        for i in range(len(X_train)):
            for v in X_train[i]:
                f.write(f"{int(v)}\n")
            f.write(f"{int(y_train[i])}\n")


def write_mpyc_input(X_train, y_train, X_test, y_test, output_dir: str):
    """Write CSV files for MPyC random forest runner."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    import pandas as pd
    train = pd.DataFrame(X_train)
    train["label"] = y_train
    test  = pd.DataFrame(X_test)
    test["label"]  = y_test
    train.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    test.to_csv(os.path.join(output_dir, "test.csv"),  index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset",     required=True, choices=DATASETS.keys())
    ap.add_argument("--output",      default=None,
                    help="Write MP-SPDZ input file here")
    ap.add_argument("--mpyc-dir",    default=None,
                    help="Write MPyC CSV inputs to this directory")
    ap.add_argument("--scale-max",   type=int, default=255)
    ap.add_argument("--seed",        type=int, default=42)
    ap.add_argument("--info-only",   action="store_true",
                    help="Print 'n_train m n_classes' and exit (for shell scripts)")
    args = ap.parse_args()

    X_tr, X_te, y_tr, y_te, n_classes = load_and_scale(
        args.dataset, args.scale_max, args.seed
    )

    if args.info_only:
        # Format: n_train m n_classes  (space-separated, one line)
        print(f"{len(X_tr)} {X_tr.shape[1]} {n_classes}")
        return

    if args.output:
        import os
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        write_mpspdz_input(X_tr, y_tr, args.output)
        print(f"[data] Wrote {len(X_tr)} train samples × {X_tr.shape[1]} features "
              f"({n_classes} classes) → {args.output}", file=sys.stderr)

    if args.mpyc_dir:
        write_mpyc_input(X_tr, y_tr, X_te, y_te, args.mpyc_dir)
        print(f"[data] Wrote MPyC CSVs to {args.mpyc_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
