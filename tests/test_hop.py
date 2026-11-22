"""hop.hop_stripe (range reads) must return exactly what census.hop_stripe (full columns) returns.
Network test: python -I tests/test_hop.py [n_stripes]"""
import json, pathlib, random, sqlite3, sys, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import census, hop

def main(n=10):
    con = sqlite3.connect(f"file:{(ROOT / 'data/hop.sqlite').as_posix()}?mode=ro", uri=True)
    seeds = [d.hex() for (d,) in con.execute("SELECT dir FROM seeds WHERE level=1")]
    sf = ROOT / "data" / "test_hop_seeds.json"
    sf.write_text(json.dumps(seeds))
    work = con.execute("SELECT w.seq, w.fid, w.stripe, f.path FROM work w JOIN files f ON f.fid=w.fid WHERE level=1").fetchall()
    rng, tot, t_new, t_old = random.Random(11), 0, 0.0, 0.0
    for seq, fid, k, path in rng.sample(work, n):
        t = time.time(); nn, new = hop.hop_stripe(path, k, 1); t_new += time.time() - t
        t = time.time(); no, old = census.hop_stripe(path, k, str(sf), len(seeds)); t_old += time.time() - t
        a = sorted((r, e[:5]) for r, e in new)
        b = sorted((r, e[:5]) for r, e in old)
        assert nn == no and a == b, (fid, k, len(a), len(b))
        tot += len(a)
        print(f"ok {fid}/{k}: {len(a)} rows; tools {sorted({e[6] for _, e in new})}")
    print(f"ALL PASS: {n} stripes, {tot} rows; new {t_new / n:.1f}s/stripe vs old {t_old / n:.1f}s/stripe (laptop)")
    sf.unlink()

if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 10)
