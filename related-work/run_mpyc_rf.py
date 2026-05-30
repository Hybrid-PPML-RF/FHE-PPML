#!/usr/bin/env python3
"""
Run Abspoel et al. random forest training via philips-software/random_forest (MPyC).
This wraps the MPyC-based implementation for CLI parameterization.

philips-software/random_forest:
  https://github.com/philips-software/random_forest
  License: MIT
  Language: Python (MPyC)
  Supports random forests with configurable n_trees and max_depth.
"""

import argparse, sys, os, math, time
import pandas as pd
import numpy as np

sys.path.insert(0, "/opt/mpyc-rf")   # philips-software/random_forest

def run(dataset: str, n_trees: int, depth: int, data_dir: str):
    train_csv = os.path.join(data_dir, "train.csv")
    test_csv  = os.path.join(data_dir, "test.csv")

    if not os.path.exists(train_csv):
        print(f"[ERROR] {train_csv} not found. Run prepare_data.py first.", file=sys.stderr)
        sys.exit(1)

    train_df = pd.read_csv(train_csv)
    test_df  = pd.read_csv(test_csv)

    X_train = train_df.drop("label", axis=1).values
    y_train = train_df["label"].values
    X_test  = test_df.drop("label",  axis=1).values
    y_test  = test_df["label"].values

    n_feat_per_tree = max(1, int(math.ceil(math.sqrt(X_train.shape[1]))))

    print(f"[mpyc-rf] dataset={dataset}  n_trees={n_trees}  depth={depth}  "
          f"n_train={len(X_train)}  m={X_train.shape[1]}  "
          f"feat_per_tree={n_feat_per_tree}")

    # Try to import the philips-software RandomForest implementation
    try:
        # The repo provides various example files; look for a RandomForest class
        # or a compatible training function.
        # Typical structure: random_forest/random_forest.py or similar
        found = False
        for candidate in ["random_forest.random_forest", "random_forest",
                           "secure_random_forest"]:
            try:
                mod = __import__(candidate, fromlist=["RandomForest"])
                RF  = getattr(mod, "RandomForest", None)
                if RF is None:
                    RF = getattr(mod, "SecureRandomForest", None)
                if RF is not None:
                    found = True
                    break
            except ImportError:
                pass

        if not found:
            # Fallback: use sklearn as a plaintext baseline to verify data pipeline
            print("[mpyc-rf] MPyC RandomForest class not found in philips-software/random_forest. "
                  "Falling back to sklearn plaintext RF for data-pipeline verification.",
                  file=sys.stderr)
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import accuracy_score

            t0 = time.time()
            clf = RandomForestClassifier(n_estimators=n_trees, max_depth=depth,
                                         random_state=42)
            clf.fit(X_train, y_train)
            elapsed = time.time() - t0

            acc_train = accuracy_score(y_train, clf.predict(X_train))
            acc_test  = accuracy_score(y_test,  clf.predict(X_test))
            print(f"[plaintext-rf] train_acc={acc_train:.4f}  test_acc={acc_test:.4f}  "
                  f"time={elapsed:.2f}s  [PLAINTEXT ONLY — not MPC]")
            return

        # Run the MPyC random forest
        t0 = time.time()
        rf = RF(n_trees=n_trees, max_depth=depth, n_features=n_feat_per_tree)
        rf.fit(X_train, y_train)
        elapsed = time.time() - t0
        print(f"[mpyc-rf] Training done in {elapsed:.2f}s")

    except Exception as e:
        print(f"[mpyc-rf] Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--num-trees", type=int, default=10)
    ap.add_argument("--depth",     type=int, default=6)
    ap.add_argument("--data-dir",  default="/tmp/mpyc-data")
    args = ap.parse_args()
    run(args.dataset, args.num_trees, args.depth, args.data_dir)


if __name__ == "__main__":
    main()
