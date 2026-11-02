#!/usr/bin/env python3
"""Tests of the log parsers and of the table generation of scripts/make_results.py.

    python3 scripts/tests/test_make_results.py        (matplotlib optional: the figure test is skipped without it)

fixtures/ppml_*.log are real outputs of ./ppml (main_integrity.cpp, iris, depth 6, 8 bins, on an 8-core laptop);
the MP-SPDZ logs are synthetic, in the format of Processor/BaseMachine.cpp.
"""
import contextlib
import importlib.util
import io
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
spec = importlib.util.spec_from_file_location("make_results", os.path.join(HERE, "..", "make_results.py"))
mr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mr)

MPSPDZ_LOG = """Using statistical security parameter 40
Trying to run 128-bit computation
32-bit_length
Compiled with n=100, m=4, alpha=9, t=3, d=4
The following benchmarks are including preprocessing (offline phase).
Time = 26.8612 seconds
Time1 = 3.1 seconds (151.2 MB, 4321 rounds)
Time2 = 23.7 seconds (480.3 MB, 1200 rounds)
Data sent = 633.5 MB in ~5521 rounds (party 0 only; rounds counted double due to multi-threading; use '-v' for more details)
Global data sent = 6.335e+06 MB (all parties)
"""


def read(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


class Parsers(unittest.TestCase):
    def test_fhe_public_model(self):
        r = mr.parse_fhe_log(read("ppml_iris_d6_bin1_mode0.log"))
        self.assertAlmostEqual(r["fhe_train_s"], 166.190891)
        # printed as "2560446 ms", but accumulated in microseconds
        self.assertAlmostEqual(r["fhe_integrity_s"], 2.560446)
        self.assertAlmostEqual(r["fhe_preprocess_s"], 3.031747)
        self.assertIsNone(r["share_cts_per_server"])

    def test_fhe_private_model(self):
        r = mr.parse_fhe_log(read("ppml_iris_d6_bin1_mode2.log"))
        self.assertAlmostEqual(r["fhe_train_s"], 151.354645)   # already without the parallel servers' encryptions
        self.assertEqual((r["share_cts_per_server"], r["share_kib_per_server"]), (5, 8704))

    def test_fhe_incomplete(self):
        self.assertIsNone(mr.parse_fhe_log(read("ppml_digits_d6_bin1_mode2_incomplete.log")))

    def test_mpspdz(self):
        r = mr.parse_mpspdz_log(MPSPDZ_LOG)
        self.assertAlmostEqual(r["time_s"], 26.8612)
        self.assertEqual(r["timers"], {1: 3.1, 2: 23.7})
        self.assertAlmostEqual(r["sent_mb"], 633.5)
        self.assertEqual(r["rounds"], 5521)
        self.assertAlmostEqual(r["global_mb"], 6.335e6)
        self.assertIsNone(mr.parse_mpspdz_log("Using statistical security parameter 40\n"))

    def test_fhe_comm_formula(self):
        # Table 5, "Ours FHE (GB)" of the paper
        expect = {("iris", 4): 0.451, ("wine", 4): 1.00, ("cancer", 6): 23.75, ("digits", 4): 135.43,
                  ("digits", 5): 276.14, ("digits", 6): 557.57}
        ds = {d["name"]: d for d in mr.load_datasets()}
        for (name, depth), gb in expect.items():
            d = ds[name]
            got = mr.fhe_share_comm_bytes(d["n"], d["m"], d["alpha"], d["t"], depth) / mr.GB
            self.assertAlmostEqual(got, gb, delta=0.006 * gb, msg=(name, depth))

    def test_short(self):
        self.assertEqual([mr.short(v) for v in (42.7, 538, 1449, 52900, 1.9e6)], ["43", "538", "1.4K", "52.9K", "1.9M"])


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "logs", "fhe"))
        for b in (0, 1):
            shutil.copy(os.path.join(FIX, "ppml_iris_d6_bin1_mode0.log"),
                        os.path.join(self.dir, "logs", "fhe", "fhe_iris_d4_bin%d_mode0_r1.log" % b))
        shutil.copy(os.path.join(FIX, "ppml_iris_d6_bin1_mode2.log"),
                    os.path.join(self.dir, "logs", "fhe", "fhe_iris_d4_bin1_mode2_r1.log"))
        for sub in ("mpc/ours_iris_d4_bin0", "mpc/ours_iris_d4_bin1", "mpc/mpconly_iris_d4_bin0",
                    "baselines/bhardwaj_iris_d4", "mpc/ours_wine_d4_bin0.partial"):
            os.makedirs(os.path.join(self.dir, "logs", sub))
            with open(os.path.join(self.dir, "logs", sub, "party0.log"), "w") as f:
                f.write(MPSPDZ_LOG if not sub.endswith(".partial") else "Trying to run 128-bit computation\n")
        with open(os.path.join(self.dir, "logs", "baselines/bhardwaj_iris_d4", "meta.txt"), "w") as f:
            f.write("baseline=bhardwaj\ntrees_measured=1\n")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_tables(self):
        with contextlib.redirect_stdout(io.StringIO()):
            mr.main(["--results", self.dir, "--no-figure"])
        rows = {r["dataset"] + r["depth"]: r for r in mr.read_csv(os.path.join(self.dir, "table4.csv"))}
        self.assertAlmostEqual(float(rows["iris4"]["fhe_s"]), 166.190891 + 2.560446, places=4)
        self.assertAlmostEqual(float(rows["iris4"]["mpc_s"]), 26.8612, places=4)
        self.assertEqual(rows["wine4"]["mpc_s"], "")            # .partial run ignored
        t5 = {r["dataset"] + r["depth"]: r for r in mr.read_csv(os.path.join(self.dir, "table5.csv"))}
        mpc_gb = 633.5e6 / 2 ** 30
        self.assertAlmostEqual(float(t5["iris4"]["ours_mpc_gb"]), mpc_gb, places=4)
        self.assertAlmostEqual(float(t5["iris4"]["bhardwaj_gb"]), 100 * mpc_gb, places=3)
        fig = {(r["dataset"], r["series"]): r for r in mr.read_csv(os.path.join(self.dir, "figure5.csv"))}
        self.assertAlmostEqual(float(fig[("iris", "ours")]["runtime_s"]), 166.190891 + 2.560446 + 26.8612, places=3)
        self.assertAlmostEqual(float(fig[("iris", "bhardwaj")]["runtime_s"]), 2686.12, places=2)
        self.assertEqual(fig[("iris", "mpconly_bins")]["runtime_s"], "")
        self.assertTrue(fig[("iris", "akavia")]["source"].startswith("reported"))
        with open(os.path.join(self.dir, "table4.tex")) as f:
            tex = f.read()
        self.assertIn("&  4 & 168.75 & 26.86 & 168.75 & 26.86 \\\\", tex)
        pm = mr.read_csv(os.path.join(self.dir, "fhe_private_model.csv"))
        self.assertEqual(len(pm), 1)

    def test_fill_from_paper_and_figure(self):
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            self.skipTest("matplotlib not installed")
        with contextlib.redirect_stdout(io.StringIO()):
            mr.main(["--results", self.dir, "--fill-missing-from-paper"])
        fig = {(r["dataset"], r["series"]): r for r in mr.read_csv(os.path.join(self.dir, "figure5.csv"))}
        self.assertEqual(fig[("digits", "ours")]["source"], "paper")
        self.assertEqual(float(fig[("digits", "ours")]["runtime_s"]), 1400)
        self.assertTrue(os.path.getsize(os.path.join(self.dir, "figure5.png")) > 10000)


if __name__ == "__main__":
    unittest.main()
