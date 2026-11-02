#!/usr/bin/env python3
"""Turn the logs of the reproduction runs into the tables and the figure of the evaluation.

Reads   <results>/logs/fhe/fhe_<ds>_d<d>_bin<b>_mode<m>_r<k>.log      (scripts/run_fhe.sh)
        <results>/logs/mpc/<ours|mpconly>_<ds>_d<d>_bin<b>/party0.log (scripts/run_mpc.sh)
        <results>/logs/baselines/bhardwaj_<ds>_d<d>/party0.log        (scripts/run_baselines.sh)
        scripts/baselines_reported.csv   runtimes of [4], [39] that are not re-measured
        scripts/paper_reference.csv      values printed in the paper (comparison only)
Writes  <results>/table4.{tex,csv}  Table 4: runtime of the FHE and the MPC part
        <results>/table5.{tex,csv}  Table 5: communication per party vs. Bhardwaj et al. [7]
        <results>/figure5.{png,pdf,csv}  Figure 5: runtime comparison (needs matplotlib)
        <results>/table_mpc_only.{tex,csv}, <results>/fhe_private_model.csv (if mode-2 runs exist)
        <results>/compare_paper.csv  measured vs. paper
Only the Python standard library is needed, plus matplotlib for the figure.
"""

import argparse
import csv
import glob
import math
import os
import re
import sys
from collections import defaultdict

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
DEPTHS = (4, 5, 6)
BIN_ALPHA = 8
GB = 2 ** 30            # "GB" in Table 5 = 2^30 bytes (the paper's "Ours FHE" column follows this convention)
MPSPDZ_MB = 1e6         # MP-SPDZ reports "MB" = 10^6 bytes

# ---------------------------------------------------------------------------------------------------------------------
# small helpers


def read_csv(path):
    """CSV with '#' comment lines -> list of dicts."""
    with open(path, newline="") as f:
        return list(csv.DictReader(line for line in f if line.strip() and not line.lstrip().startswith("#")))


def load_datasets(path=os.path.join(SCRIPTS_DIR, "datasets.csv")):
    out = []
    for r in read_csv(path):
        out.append({"name": r["name"], "label": r["label"], "n": int(r["n"]), "m": int(r["m"]),
                    "alpha": int(r["alpha"]), "t": int(r["t"])})
    return out


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def read(path):
    with open(path, errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------------------------------------------------------------
# log parsers

RE_FHE_TRAIN = re.compile(r"^Training \+ labeling \+ packing total runtime:\s*(\d+)\s*us", re.M)
RE_FHE_INTEGRITY = re.compile(r"^Integrity Runtime for all\s*:\s*(\d+)\s*ms", re.M)
RE_FHE_PRE = re.compile(r"^Preprocess time:\s*(\d+)\s*us", re.M)
RE_FHE_SHARES = re.compile(r"^Share ciphertexts per server:\s*(\d+),\s*(\d+)\s*KiB", re.M)


def parse_fhe_log(text):
    """Output of ./ppml (main_integrity.cpp). Returns None if the run did not finish its training phase.

    fhe_train_s     "Training + labeling + packing total runtime" (us)
    fhe_integrity_s "Integrity Runtime for all" -- main_integrity.cpp accumulates this time with
                    chrono::microseconds and multiplies it by depth + 1, but prints the unit "ms";
                    the value is in microseconds.
    """
    m = RE_FHE_TRAIN.search(text)
    if not m:
        return None
    out = {"fhe_train_s": int(m.group(1)) / 1e6, "fhe_integrity_s": None, "fhe_preprocess_s": None,
           "share_cts_per_server": None, "share_kib_per_server": None}
    m = RE_FHE_INTEGRITY.search(text)
    if m:
        out["fhe_integrity_s"] = int(m.group(1)) / 1e6
    m = RE_FHE_PRE.search(text)
    if m:
        out["fhe_preprocess_s"] = int(m.group(1)) / 1e6
    m = RE_FHE_SHARES.search(text)
    if m:
        out["share_cts_per_server"], out["share_kib_per_server"] = int(m.group(1)), int(m.group(2))
    return out


NUM = r"([0-9][0-9.]*(?:[eE][+-]?\d+)?)"
RE_MP_TIME = re.compile(r"^Time = " + NUM + r" seconds", re.M)
RE_MP_TIMER = re.compile(r"^Time(\d+) = " + NUM + r" seconds", re.M)
RE_MP_SENT = re.compile(r"^Data sent = " + NUM + r" MB in ~(\d+) rounds", re.M)
RE_MP_GLOBAL = re.compile(r"^Global data sent = " + NUM + r" MB", re.M)


def parse_mpspdz_log(text):
    """stderr of an MP-SPDZ party (Processor/BaseMachine.cpp). None if the run did not finish."""
    m = RE_MP_TIME.search(text)
    if not m:
        return None
    out = {"time_s": float(m.group(1)), "timers": {int(k): float(v) for k, v in RE_MP_TIMER.findall(text)},
           "sent_mb": None, "rounds": None, "global_mb": None}
    m = RE_MP_SENT.search(text)
    if m:
        out["sent_mb"], out["rounds"] = float(m.group(1)), int(m.group(2))
    m = RE_MP_GLOBAL.search(text)
    if m:
        out["global_mb"] = float(m.group(1))
    return out


def parse_meta(path):
    meta = {}
    if os.path.exists(path):
        for line in read(path).splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                meta[k.strip()] = v.strip()
    return meta


# ---------------------------------------------------------------------------------------------------------------------
# collecting the runs

RE_FHE_NAME = re.compile(r"fhe_([a-z]+)_d(\d+)_bin([01])_mode(\d)_r(\d+)\.log$")


def collect_fhe(results, include_integrity=True):
    """{(ds, d, bins, mode): {fhe_s, fhe_train_s, fhe_integrity_s, runs, ...}} averaged over repetitions."""
    runs = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(results, "logs", "fhe", "fhe_*.log"))):
        m = RE_FHE_NAME.search(os.path.basename(path))
        if not m:
            continue
        r = parse_fhe_log(read(path))
        if r:
            runs[(m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)))].append(r)
    out = {}
    for key, rs in runs.items():
        agg = {k: mean([r[k] for r in rs]) for k in rs[0]}
        integ = agg["fhe_integrity_s"] if include_integrity and agg["fhe_integrity_s"] is not None else 0.0
        agg["fhe_s"] = agg["fhe_train_s"] + integ
        agg["runs"] = len(rs)
        out[key] = agg
    return out


def collect_mpspdz(results, sub, prefix, with_bins=True):
    """Party-0 logs of MP-SPDZ runs: {(ds, d[, bins]): parsed + meta}."""
    pat = re.compile(prefix + r"_([a-z]+)_d(\d+)" + (r"_bin([01])" if with_bins else "") + r"$")
    out = {}
    for path in sorted(glob.glob(os.path.join(results, "logs", sub, prefix + "_*", "party0.log"))):
        d = os.path.dirname(path)
        m = pat.search(os.path.basename(d))
        if not m:
            continue
        r = parse_mpspdz_log(read(path))
        if not r:
            continue
        r["meta"] = parse_meta(os.path.join(d, "meta.txt"))
        key = (m.group(1), int(m.group(2))) + ((int(m.group(3)),) if with_bins else ())
        out[key] = r
    return out


def load_reported(path):
    out = {}
    for r in read_csv(path):
        out[(r["series"], r["dataset"])] = (float(r["runtime_s"]), r.get("source", "reported"))
    return out


def load_paper(path):
    out = {}
    for r in read_csv(path):
        depth = int(r["depth"]) if r["depth"] else None
        bins = int(r["bins"]) if r["bins"] else None
        out[(r["table"], r["dataset"], depth, bins, r["metric"])] = float(r["value"])
    return out


# ---------------------------------------------------------------------------------------------------------------------
# analytic communication of the FHE -> MPC conversion (Table 5, "Ours FHE")

def fhe_share_comm_bytes(n, m, alpha, t, d, trees_per_party=10, parties=10, elem_bytes=16):
    """Bytes sent per party to secret-share the decrypted FHE results (the shares of the inputs of the MPC part), as
    in mpc/Programs/Source/bench_input.py with T = trees per party:
        S = 2 T a n m + T (2^d - 1) (4 a floor(sqrt m) t n + n t + a floor(sqrt m) t)
    field elements, each sent to the other parties-1 parties, elem_bytes = 16 for the 128-bit prime field.
    This column is computed, not measured (the paper's Table 5 uses the same formula; GB = 2^30 bytes)."""
    sq = math.isqrt(m) if hasattr(math, "isqrt") else int(math.sqrt(m))
    nodes = 2 ** d - 1
    T = trees_per_party
    elems = 2 * T * alpha * n * m + T * nodes * (4 * alpha * sq * t * n + n * t + alpha * sq * t)
    return elems * (parties - 1) * elem_bytes


# ---------------------------------------------------------------------------------------------------------------------
# formatting

def f2(x, nd=2):
    return "--" if x is None else f"{x:.{nd}f}"


def ftex(x, nd=2):
    """number for LaTeX with {,} thousands separator"""
    if x is None:
        return "--"
    s = f"{x:,.{nd}f}"
    return s.replace(",", "{,}")


def fgb(x):
    """GB values of Table 5: 0.451, 1.72, 142.54"""
    return ftex(x, 3 if x is not None and x < 1 else 2)


def short(v):
    """bar labels of Figure 5: 43, 538, 1.4K, 52.9K, 1.9M"""
    if v >= 1e6:
        return f"{v / 1e6:.1f}M"
    if v >= 1e3:
        return f"{v / 1e3:.1f}K"
    return f"{v:.0f}"


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(["" if x is None else (f"{x:.10g}" if isinstance(x, float) else x) for x in r])


# ---------------------------------------------------------------------------------------------------------------------
# Table 4

TABLE4_HEAD = r"""\definecolor{chocolate}{RGB}{210,105,30}
\definecolor{bblue}{RGB}{98, 158, 222}

% generated by scripts/make_results.py
\begin{table}[t]
\centering
\scriptsize
\begin{tabular}{| l | c | c c | c c |}
\rowcolor{bblue!30}
\multicolumn{6}{c}{\textbf{Runtime (in sec) in the Hybrid FHE-MPC setting}} \\
\hline
\hline
\multirow{2}{*}{\textbf{Dataset}} & \multirow{2}{*}{\textbf{\makecell{Tree \\ Depth}}}
& \multicolumn{2}{c|}{\textbf{\makecell{$\sqrt{\attrs}$ attributes}} }
& \multicolumn{2}{c|}{\textbf{\makecell{$\sqrt{\attrs}$  attributes, \\ $8$ bins}}} \\
\cline{3-6}
& & \textbf{FHE} & \textbf{MPC} & \textbf{FHE} & \textbf{MPC} \\
\hline\hline
"""
TABLE4_TAIL = r"""\hline
\end{tabular}
\caption{Runtimes (sec) of our protocol for random forest training (100 trees), across different datasets and tree depths.%(note)s}
\label{tab:our_runtimes}
\end{table}
"""


def table4(datasets, depths, fhe, mpc, outdir, results):
    rows, tex = [], [TABLE4_HEAD]
    for i, ds in enumerate(datasets):
        tex.append(r"\multirow{%d}{*}{%s}" % (len(depths), ds["label"].upper()) + "\n")
        for d in depths:
            cells = []
            row = [ds["name"], d]
            for b in (0, 1):
                f = fhe.get((ds["name"], d, b, 0))
                mp = mpc.get((ds["name"], d, b))
                cells += [f2(f and f["fhe_s"]), f2(mp and mp["time_s"])]
                row += [f and f["fhe_s"], f and f["fhe_train_s"], f and f["fhe_integrity_s"], f and f["runs"],
                        mp and mp["time_s"], mp and mp["sent_mb"]]
            tex.append("&  %d & %s \\\\\n" % (d, " & ".join(cells)))
            rows.append(row)
        tex.append("\\hline\\hline\n" if i < len(datasets) - 1 else "")
    tex.append(TABLE4_TAIL % {"note": " FHE = training + integrity check (main\\_integrity.cpp); MPC = MP-SPDZ \\texttt{Time} of bench\\_fhe (party 0)."})
    with open(os.path.join(outdir, "table4.tex"), "w") as f:
        f.write("".join(tex))
    hdr = ["dataset", "depth"]
    for b in ("", "_bins"):
        hdr += ["fhe_s" + b, "fhe_train_s" + b, "fhe_integrity_s" + b, "fhe_runs" + b, "mpc_s" + b, "mpc_sent_mb" + b]
    write_csv(os.path.join(outdir, "table4.csv"), hdr, rows)
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# Table 5

TABLE5_HEAD = r"""% generated by scripts/make_results.py
\begin{table}[t]
\scriptsize
\centering
\setlength{\tabcolsep}{4pt}
\begin{tabular}{|c|c|r|r|r||r|r|}
\hline
\textbf{Dataset} &
\textbf{$d$} &
\textbf{\cite{BhardwajSCG2024}} &
\textbf{Ours} &
\textbf{IF} &
\textbf{Ours FHE} &
\textbf{Ours MPC} \\
\hline\hline
"""
TABLE5_TAIL = r"""\hline
\end{tabular}
\caption{Communication per party (GB) comparison with \cite{BhardwajSCG2024}, for 100-tree RF training.%(note)s}
\label{tab:communication-CCS24-gb}
\end{table}
"""


def table5(datasets, depths, mpc, bhardwaj, trees, outdir, results):
    rows, tex = [], [TABLE5_HEAD]
    for i, ds in enumerate(datasets):
        tex.append(r"\multirow{%d}{*}{%s}" % (len(depths), ds["label"].upper()) + "\n")
        for d in depths:
            fhe_gb = fhe_share_comm_bytes(ds["n"], ds["m"], ds["alpha"], ds["t"], d) / GB
            mp = mpc.get((ds["name"], d, 0))
            mpc_gb = mp["sent_mb"] * MPSPDZ_MB / GB if mp and mp["sent_mb"] is not None else None
            ours = fhe_gb + mpc_gb if mpc_gb is not None else None
            bw = bhardwaj.get((ds["name"], d))
            bw_trees = trees if trees else (int(bw["meta"].get("trees_total", 100)) if bw else 100)
            measured = int(bw["meta"].get("trees_measured", 1)) if bw else 1
            bw_gb = bw["sent_mb"] * MPSPDZ_MB / GB * bw_trees / measured if bw and bw["sent_mb"] is not None else None
            imp = bw_gb / ours if bw_gb is not None and ours else None
            tex.append("& %d & %s & %s & %s & %s & %s \\\\\n" % (
                d, ftex(bw_gb, 0 if bw_gb and bw_gb >= 100 else 1), fgb(ours), ftex(imp, 3), fgb(fhe_gb), fgb(mpc_gb)))
            rows.append([ds["name"], d, bw_gb, ours, imp, fhe_gb, mpc_gb,
                         bw and bw["sent_mb"], bw and bw["global_mb"], bw and bw["time_s"],
                         bw_trees / measured if bw else None, mp and mp["global_mb"]])
        tex.append("\\hline\\hline\n" if i < len(datasets) - 1 else "")
    tex.append(TABLE5_TAIL % {"note": " GB = $2^{30}$ bytes. \\cite{BhardwajSCG2024}: party 0 of one measured tree, "
                                      "times the number of trees. Ours FHE: computed (secret sharing of the decrypted FHE "
                                      "results, $T = 10$ trees per party, 10 parties, 128-bit field). Ours MPC: party 0 of bench\\_fhe."})
    with open(os.path.join(outdir, "table5.tex"), "w") as f:
        f.write("".join(tex))
    write_csv(os.path.join(outdir, "table5.csv"),
              ["dataset", "depth", "bhardwaj_gb", "ours_gb", "if", "ours_fhe_gb", "ours_mpc_gb",
               "bhardwaj_one_tree_sent_mb_party0", "bhardwaj_one_tree_global_mb", "bhardwaj_one_tree_time_s",
               "bhardwaj_scale", "ours_mpc_global_mb"], rows)
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# MPC-only table

def table_mpc_only(datasets, depths, mpconly, outdir):
    rows, tex = [], [r"""% generated by scripts/make_results.py
\begin{table}[ht]
\centering
\footnotesize
\begin{tabular}{l|l|r|r}
\rowcolor{bblue!30}
\multicolumn{4}{c}{\textbf{Cost in the full MPC setting}} \\
\hline
\textbf{Dataset} & \textbf{\makecell{Tree \\Depth}}
& \textbf{\makecell{$\sqrt{\attrs}$ \\ attributes}}
& \textbf{\makecell{$\sqrt{\attrs}$ \\ attributes, \\ $8$ bins}} \\
\hline
"""]
    for ds in datasets:
        tex.append(r"\multirow{%d}{*}{%s}" % (len(depths), ds["label"].upper()) + "\n")
        for d in depths:
            a = mpconly.get((ds["name"], d, 0))
            b = mpconly.get((ds["name"], d, 1))
            tex.append("&  %d & %s & %s \\\\\n" % (d, f2(a and a["time_s"]), f2(b and b["time_s"])))
            rows.append([ds["name"], d, a and a["time_s"], b and b["time_s"], a and a["sent_mb"], b and b["sent_mb"]])
        tex.append("\\hline\n")
    tex.append(r"""\end{tabular}
\caption{MPC runtimes (seconds) for random forest training (ensemble of 100 trees) across datasets and tree depths using malicious Shamir secret sharing (10 parties, 48 threads each).}
\label{tab:naive_mpc_runtimes_only}
\end{table}
""")
    with open(os.path.join(outdir, "table_mpc_only.tex"), "w") as f:
        f.write("".join(tex))
    write_csv(os.path.join(outdir, "table_mpc_only.csv"),
              ["dataset", "depth", "runtime_s", "runtime_s_bins", "sent_mb", "sent_mb_bins"], rows)
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# Figure 5

SERIES = [  # key, legend label (as in the paper), face color, hatch
    ("akavia", "[4]", "#c62828", "//"),
    ("shin", "[39]", "#f4a582", "\\\\"),
    ("mpconly", "MPC-only", "#ff8c00", "."),
    ("mpconly_bins", "MPC-only (8 bins)", "#ffc47e", "+"),
    ("bhardwaj", "[7]", "#d4a52c", "x"),
    ("ours", r"$\bf{Ours}$", "#1446b8", "-"),
    ("ours_bins", r"$\bf{Ours}$ (8 bins)", "#80b3e0", "*"),
]
SERIES_NAMES = {
    "akavia": "[4] Akavia et al. (CKKS)", "shin": "[39] Shin et al. (CKKS)", "mpconly": "MPC-only",
    "mpconly_bins": "MPC-only (8 bins)", "bhardwaj": "[7] Bhardwaj et al. (CCS'24)", "ours": "Ours",
    "ours_bins": "Ours (8 bins)",
}


def figure5_values(datasets, depth, fhe, mpc, mpconly, bhardwaj, reported, paper, trees, fill):
    """[(dataset, series, value or None, source)]"""
    out = []
    for ds in datasets:
        name = ds["name"]
        for key, *_ in SERIES:
            val, src = None, "missing"
            if key in ("akavia", "shin"):
                if (key, name) in reported:
                    val, src = reported[(key, name)][0], "reported/scaled (" + reported[(key, name)][1] + ")"
            elif key.startswith("mpconly"):
                r = mpconly.get((name, depth, 1 if key.endswith("bins") else 0))
                if r:
                    val, src = r["time_s"], "measured"
            elif key == "bhardwaj":
                r = bhardwaj.get((name, depth))
                if r:
                    measured = int(r["meta"].get("trees_measured", 1))
                    total = trees if trees else int(r["meta"].get("trees_total", 100))
                    val, src = r["time_s"] * total / measured, "measured (%d tree(s) x %g)" % (measured, total / measured)
            else:
                b = 1 if key.endswith("bins") else 0
                f, mp = fhe.get((name, depth, b, 0)), mpc.get((name, depth, b))
                if f and mp:
                    val, src = f["fhe_s"] + mp["time_s"], "measured (FHE + MPC)"
            if val is None and fill and ("figure5", name, None, None, key) in paper:
                val, src = paper[("figure5", name, None, None, key)], "paper"
            out.append((name, key, val, src))
    return out


def plot_figure5(datasets, values, depth, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    plt.rcParams.update({"hatch.linewidth": 0.8, "font.size": 13})
    vals = {(d, s): (v, src) for d, s, v, src in values}
    nser = len(SERIES)
    width = 0.8 / nser
    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    present = [v for _, _, v, _ in values if v]
    ymin = min([10.0] + [10 ** math.floor(math.log10(v)) for v in present])   # 10 s as in the paper, lower if needed
    any_paper = False
    for j, (key, label, color, hatch) in enumerate(SERIES):
        for i, ds in enumerate(datasets):
            x = i + (j - (nser - 1) / 2) * width
            v, src = vals.get((ds["name"], key), (None, "missing"))
            if v is None:
                ax.text(x, ymin * 1.3, "n/a", rotation=90, ha="center", va="bottom", fontsize=7, color="#666666")
                continue
            from_paper = src == "paper"
            any_paper |= from_paper
            ax.bar(x, v - ymin, bottom=ymin, width=width, color=color, hatch=hatch, edgecolor="#333333",
                   linewidth=0.6, alpha=0.45 if from_paper else 1.0)
            ax.annotate(short(v) + ("*" if from_paper else ""), (x, v), xytext=(1, 4),
                        textcoords="offset points", rotation=70, ha="left", va="center", fontsize=9,
                        rotation_mode="anchor")
    ax.set_yscale("log")
    ax.set_ylim(ymin, 1e9)
    ax.set_xlim(-0.5, len(datasets) - 0.5)
    ax.set_xticks(range(len(datasets)))
    ax.set_xticklabels(["%s\n(n=%s)" % (ds["label"], f"{ds['n']:,}") for ds in datasets])
    ax.set_ylabel("Runtime (s, log scale)")
    handles = [Patch(facecolor=c, edgecolor="#333333", hatch=h, label=l) for _, l, c, h in SERIES]
    # two columns, filled column-wise as in the paper: [4], [39], MPC-only, MPC-only (8 bins) | [7], Ours, Ours (8 bins)
    ax.legend(handles=handles, ncol=2, loc="upper left", fontsize=10, framealpha=1.0, edgecolor="#888888")
    notes = ["[4], [39]: scaled microbenchmark estimates (scripts/baselines_reported.csv), not re-measured.",
             "Tree depth %d; [7]: measured tree(s) scaled to 100 trees." % depth]
    if any_paper:
        notes.append("* value from the paper (no run of this configuration found).")
    fig.text(0.01, 0.005, "  ".join(notes), fontsize=6, color="#555555", ha="left", va="bottom", wrap=True)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(outdir, "figure5." + ext), dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------------------------------------------------------------
# comparison with the paper, private model

def compare_paper(datasets, depths, t4, t5, tmo, fig, paper, outdir):
    rows = []

    def add(what, ds, d, b, measured, key):
        p = paper.get(key)
        rows.append([what, ds, d, "" if b is None else b, measured, p,
                     measured / p if measured is not None and p else None])

    for r in t4:
        ds, d = r[0], r[1]
        add("table4 FHE (s)", ds, d, 0, r[2], ("table4", ds, d, 0, "fhe_s"))
        add("table4 MPC (s)", ds, d, 0, r[6], ("table4", ds, d, 0, "mpc_s"))
        add("table4 FHE (s)", ds, d, 1, r[8], ("table4", ds, d, 1, "fhe_s"))
        add("table4 MPC (s)", ds, d, 1, r[12], ("table4", ds, d, 1, "mpc_s"))
    for r in t5:
        ds, d = r[0], r[1]
        for i, metric in ((2, "bhardwaj_gb"), (3, "ours_gb"), (4, "if"), (5, "ours_fhe_gb"), (6, "ours_mpc_gb")):
            add("table5 " + metric, ds, d, None, r[i], ("table5", ds, d, None, metric))
    for r in tmo:
        add("mpc_only (s)", r[0], r[1], 0, r[2], ("mpc_only", r[0], r[1], 0, "runtime_s"))
        add("mpc_only (s)", r[0], r[1], 1, r[3], ("mpc_only", r[0], r[1], 1, "runtime_s"))
    for ds, key, v, src in fig:
        if src != "paper":
            add("figure5 " + key + " (s)", ds, "", None, v, ("figure5", ds, None, None, key))
    write_csv(os.path.join(outdir, "compare_paper.csv"),
              ["what", "dataset", "depth", "bins", "measured", "paper", "measured/paper"], rows)
    return rows


def private_model(datasets, depths, fhe, outdir):
    rows = []
    for ds in datasets:
        for d in depths:
            for b in (0, 1):
                a, p = fhe.get((ds["name"], d, b, 0)), fhe.get((ds["name"], d, b, 2))
                if a and p:
                    rows.append([ds["name"], d, b, a["fhe_s"], p["fhe_s"], p["fhe_s"] / a["fhe_s"] - 1,
                                 p["share_cts_per_server"], p["share_kib_per_server"]])
    if rows:
        write_csv(os.path.join(outdir, "fhe_private_model.csv"),
                  ["dataset", "depth", "bins", "public_model_s", "private_model_s", "overhead",
                   "share_cts_per_server", "share_kib_per_server"], rows)
    return rows


# ---------------------------------------------------------------------------------------------------------------------

def print_summary(datasets, depths, t4, t5, fig, fig_depth, out=None):
    p = lambda *a: print(*a, file=out or sys.stdout)  # noqa: E731
    p("Table 4 -- runtime (s), 100 trees")
    p("%-8s %2s | %10s %10s | %10s %10s" % ("dataset", "d", "FHE", "MPC", "FHE 8bins", "MPC 8bins"))
    for r in t4:
        p("%-8s %2d | %10s %10s | %10s %10s" % (r[0], r[1], f2(r[2]), f2(r[6]), f2(r[8]), f2(r[12])))
    p("\nTable 5 -- communication per party (GB = 2^30 B)")
    p("%-8s %2s | %10s %10s %8s | %10s %10s" % ("dataset", "d", "[7]", "Ours", "IF", "Ours FHE", "Ours MPC"))
    for r in t5:
        p("%-8s %2d | %10s %10s %8s | %10s %10s" % (r[0], r[1], f2(r[2]), f2(r[3]), f2(r[4], 2), f2(r[5]), f2(r[6])))
    p("\nFigure 5 -- runtime (s), depth %d" % fig_depth)
    p("%-8s " % "dataset" + " ".join("%12s" % k for k, *_ in SERIES))
    by = {(d, s): (v, src) for d, s, v, src in fig}
    for ds in datasets:
        cells = []
        for k, *_ in SERIES:
            v, src = by.get((ds["name"], k), (None, ""))
            cells.append("%12s" % ("--" if v is None else short(v) + ("*" if src == "paper" else "")))
        p("%-8s " % ds["name"] + " ".join(cells))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=os.environ.get("RESULTS_DIR", os.path.join(SCRIPTS_DIR, "..", "results")),
                    help="results directory with logs/ (default: $RESULTS_DIR or <repo>/results)")
    ap.add_argument("--out", help="output directory (default: the results directory)")
    ap.add_argument("--figure-depth", type=int, default=4, help="tree depth shown in Figure 5 (default: 4)")
    ap.add_argument("--depths", default="4,5,6", help="depths of the tables (default: 4,5,6)")
    ap.add_argument("--trees", type=int, default=0,
                    help="number of trees the Bhardwaj et al. runs are scaled to (default: 100, from meta.txt)")
    ap.add_argument("--fhe-no-integrity", action="store_true",
                    help="FHE runtime without the integrity check (default: training + integrity check)")
    ap.add_argument("--reported", default=os.path.join(SCRIPTS_DIR, "baselines_reported.csv"))
    ap.add_argument("--paper", default=os.path.join(SCRIPTS_DIR, "paper_reference.csv"))
    ap.add_argument("--fill-missing-from-paper", action="store_true",
                    help="use the paper's value (marked with *) for bars of Figure 5 without a run")
    ap.add_argument("--no-figure", action="store_true", help="skip the figure (no matplotlib needed)")
    args = ap.parse_args(argv)

    results = os.path.abspath(args.results)
    outdir = os.path.abspath(args.out or results)
    os.makedirs(outdir, exist_ok=True)
    depths = [int(x) for x in re.split(r"[ ,]+", args.depths.strip()) if x]
    datasets = load_datasets()

    fhe = collect_fhe(results, include_integrity=not args.fhe_no_integrity)
    mpc = collect_mpspdz(results, "mpc", "ours")
    mpconly = collect_mpspdz(results, "mpc", "mpconly")
    bhardwaj = collect_mpspdz(results, "baselines", "bhardwaj", with_bins=False)
    reported = load_reported(args.reported)
    paper = load_paper(args.paper)

    t4 = table4(datasets, depths, fhe, mpc, outdir, results)
    t5 = table5(datasets, depths, mpc, bhardwaj, args.trees, outdir, results)
    tmo = table_mpc_only(datasets, depths, mpconly, outdir)
    fig = figure5_values(datasets, args.figure_depth, fhe, mpc, mpconly, bhardwaj, reported, paper, args.trees,
                         args.fill_missing_from_paper)
    write_csv(os.path.join(outdir, "figure5.csv"), ["dataset", "series", "name", "runtime_s", "source"],
              [[d, s, SERIES_NAMES[s], v, src] for d, s, v, src in fig])
    compare_paper(datasets, depths, t4, t5, tmo, fig, paper, outdir)
    private_model(datasets, depths, fhe, outdir)
    if not args.no_figure:
        try:
            plot_figure5(datasets, fig, args.figure_depth, outdir)
        except ImportError:
            print("matplotlib not available: figure5.png skipped (figure5.csv written)", file=sys.stderr)

    print_summary(datasets, depths, t4, t5, fig, args.figure_depth)
    print("\nparsed runs: %d FHE, %d MPC (ours), %d MPC-only, %d Bhardwaj et al.; output in %s"
          % (len(fhe), len(mpc), len(mpconly), len(bhardwaj), outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
