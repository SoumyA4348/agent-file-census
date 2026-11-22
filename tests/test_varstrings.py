"""orcmeta.var_strings must equal pyarrow's full-column read (names + type) on real directory_entry stripes.
Network test: python -I tests/test_varstrings.py [n_stripes]"""
import pathlib, random, sqlite3, sys, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import pyarrow.orc as orc
from census import s3fs
from orcmeta import OrcFile

def main(n=6):
    con = sqlite3.connect(f"file:{(ROOT / 'data/hits_v2.sqlite').as_posix()}?mode=ro", uri=True)
    files = con.execute("SELECT fid, path, nstripes FROM files").fetchall()
    rng = random.Random(20261119)
    s3, total = s3fs(), 0
    for fid, path, ns in rng.sample(files, n):
        k = rng.randrange(ns)
        f = s3.open_input_file(path)
        pf, mf = orc.ORCFile(f), OrcFile(f)
        tb = pf.read_stripe(k, columns=["name", "type"])
        names, types = tb.column(0).to_pylist(), tb.column(1).to_pylist()
        nrows, st = len(names), mf.stride
        rows = set(rng.sample(range(nrows), 300)) | {0, nrows - 1}
        for g in rng.sample(range(nrows // st), min(8, nrows // st)):
            rows |= {g * st - 1, g * st, g * st + 1, g * st + st - 1}
        rows = sorted(r for r in rows if 0 <= r < nrows)
        t = time.time()
        got_n = mf.var_strings(k, 2, rows)
        got_t = mf.var_strings(k, 3, rows)
        dt = time.time() - t
        bad = [r for r in rows if got_n[r] != names[r] or got_t[r].decode() != types[r]]
        assert not bad, (path, k, bad[:5], [(got_n[r], names[r]) for r in bad[:3]])
        total += len(rows)
        print(f"ok file {fid} stripe {k}: {len(rows)} rows ({nrows:,} in stripe) in {dt:.1f}s")
    print(f"ALL PASS: {total} rows across {n} stripes")

if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 6)
