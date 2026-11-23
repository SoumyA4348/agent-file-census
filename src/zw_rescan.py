"""afscan 0.3.2 changed only zero-width decoding, so only blobs with zero-width characters can change: rescan those
(features.zw_chars > 0 under 0.3.1) and store their findings under the new version; every other blob keeps its
0.3.1 result, which 0.3.2 reproduces exactly. Run on the VM (corpus holds secrets).

    python -I src/zw_rescan.py          # -> findings rows ver 0.3.2 + a summary of what changed
"""
import gzip
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import afscan  # noqa: E402
from corpus import Corpus, db, SCAN_CAP  # noqa: E402


def main():
    con, corpus, ver = db(), Corpus(ro=True), afscan.__version__
    sev = {"symlink": -2, "clean": -1, "info": 0, "low": 1, "medium": 2, "high": 3}
    keys = [sg for sg, d in con.execute("SELECT sha1_git, data FROM features WHERE ver='0.3.1' AND data LIKE '%zw_chars%'")
            if d and json.loads(d).get("zw_chars", 0) > 0]
    print(f"{len(keys):,} blobs with zero-width characters", flush=True)
    changed, decoded, rows = 0, [], []
    for sg in keys:
        gz = corpus.get(sg)
        if gz is None:
            continue
        text, _ = afscan.decode(gzip.decompress(gz))
        res = afscan.scan_text(text[:SCAN_CAP])
        old = con.execute("SELECT verdict, rules FROM findings WHERE sha1_git=? AND ver='0.3.1'", (sg,)).fetchone()
        rules = ",".join(sorted({f["rule"] for f in res["flags"]}))
        if old and (old[0], old[1] or "") != (res["verdict"], rules):
            changed += 1
        for f in res["flags"]:
            if f["rule"] == "zero_width_run" and not f["snippet"].startswith("["):
                decoded.append((sg.hex()[:10], f["sev"], len(f["snippet"])))
        rows.append((sg, ver, res["verdict"], sev.get(res["verdict"], -1), rules,
                     json.dumps(res["flags"], ensure_ascii=False), int(len(text) > SCAN_CAP), time.time()))
    con.executemany("INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?)", rows)
    con.commit()
    print(f"rescanned {len(rows):,}; verdict/rules changed {changed:,}; decoded zero-width messages in "
          f"{len({d[0] for d in decoded}):,} blobs: {decoded[:40]}", flush=True)


if __name__ == "__main__":
    main()
