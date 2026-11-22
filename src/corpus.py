"""Full-scan pipeline (v3, 2026-11-19): map every target blob, fetch it once, verify it, keep it, scan it.

Runs on one cloud VM against a small portable DB (data/scan.sqlite), not the 22 GB census DB.

    python src/corpus.py init SRC.sqlite [--controls]   # laptop: copy targets (+ base controls) from the census DB
    python src/corpus.py map [--workers 16]             # one content-table round: sha1_git -> sha1 for unmapped targets
    python src/corpus.py newround                       # queue another round (after new targets, e.g. from hop)
    python src/corpus.py fetch [--threads 64]           # download each mapped blob once, verify, keep (gzip as served)
    python src/corpus.py scan [--workers 4]             # afscan over the kept corpus (one row per blob per afscan version)
    python src/corpus.py status                         # coverage per kind/tool: targets -> mapped -> kept -> scanned
    python src/corpus.py retry                          # re-queue transient fetch errors

Why this replaces blobs.py for the full scan:
  - the needle set is fixed for a whole round, so every content stripe is checked against the same set
    (blobs.py let early stripes miss needles found later);
  - needle lookup is a sorted uint64-prefix search (0.1 s/stripe) instead of rebuilding a 5.9M-entry
    hash set per stripe (1.2 s/stripe);
  - every blob is KEPT, so a new detector version or a recall sample needs no refetch;
  - every target ends in one state, so coverage is reportable:
      unmapped | not_visible | too_big | missing (HTTP 403/404) | error | hash_mismatch | ok
  - each kept blob is verified: sha1(data) == content key and git blob sha1 == the directory-entry target.
Corpus: data/corpus/<first hex digit>.sqlite, table c(sha1_git, gz) with the bytes exactly as Software Heritage
serves them (gzip). PRIVATE: it holds real secrets committed to public repos. Never upload or share it.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
import pathlib
import sqlite3
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from census import SYMLINK, s3fs  # noqa: E402

DATA = ROOT / "data"
DB = pathlib.Path(os.environ.get("AFC_SCAN_DB", DATA / "scan.sqlite"))
CORPUS = pathlib.Path(os.environ.get("AFC_CORPUS", DATA / "corpus"))
HOST = "softwareheritage.s3.amazonaws.com"
UA = "agent-file-census/0.3 (academic research)"
MAX_FETCH = 8_000_000          # bytes, uncompressed; larger blobs are recorded as too_big
SCAN_CAP = 2_000_000           # characters scanned per file; longer files are scanned truncated (flagged)
CONFIG_LATE = {"settings", "vscode_tasks", "devcontainer", "replit_cfg"}   # broad names: mostly not agent config


def prio(kind: str, tool: str | None) -> int:
    """Fetch order: agent instruction files (main paper) first, then agent config, broad config, controls."""
    if kind == "agent" or kind.startswith("hop"):
        return 0
    if kind == "config":
        return 2 if tool in CONFIG_LATE else 1
    return 3 if kind == "base" else 4


def db(path=None):
    DATA.mkdir(exist_ok=True)
    con = sqlite3.connect(path or DB, timeout=300)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS targets(target BLOB PRIMARY KEY, tool TEXT, kind TEXT, link INT, prio INT);
    CREATE INDEX IF NOT EXISTS t_prio ON targets(prio, target);
    CREATE TABLE IF NOT EXISTS cfiles(fid INTEGER PRIMARY KEY, path TEXT, nstripes INT);
    CREATE TABLE IF NOT EXISTS cwork(round INT, seq INT, fid INT, stripe INT, rows INT, matched INT, done_at REAL,
        PRIMARY KEY(round, seq));
    CREATE TABLE IF NOT EXISTS blobs(sha1_git BLOB PRIMARY KEY, sha1 BLOB, length INT, status TEXT, round INT);
    CREATE TABLE IF NOT EXISTS fetch(sha1_git BLOB PRIMARY KEY, state TEXT, http INT, err TEXT, at REAL);
    CREATE TABLE IF NOT EXISTS findings(sha1_git BLOB, ver TEXT, verdict TEXT, flag INT, rules TEXT, flags TEXT,
        truncated INT, at REAL, PRIMARY KEY(sha1_git, ver));
    CREATE TABLE IF NOT EXISTS features(sha1_git BLOB, ver TEXT, enc TEXT, data TEXT, PRIMARY KEY(sha1_git, ver));
    CREATE TABLE IF NOT EXISTS errors(stage TEXT, ref TEXT, err TEXT, at REAL);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    """)
    return con


def setmeta(con, k, v):
    con.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, json.dumps(v)))


def getmeta(con, k, default=None):
    r = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return json.loads(r[0]) if r else default


# ---------------------------------------------------------------- init (laptop)
def cmd_init(a):
    src = sqlite3.connect(f"file:{pathlib.Path(a.src).resolve().as_posix()}?mode=ro", uri=True)
    con = db()
    n0 = con.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    con.executemany("INSERT OR IGNORE INTO targets VALUES(?,?,?,?,?)",
                    ((t, tool, kind, int(lk or 0), prio(kind, tool))
                     for t, tool, kind, lk in src.execute("SELECT target, tool, kind, link FROM targets")))
    if a.controls:   # base control sample: manifests + README/CONTRIBUTING in 1/4096 of all directories
        q = ("SELECT target, MIN(LOWER(CAST(name AS TEXT))), MAX(perms=?) FROM entries "
             "WHERE kind='base' AND type='file' GROUP BY target")
        con.executemany("INSERT OR IGNORE INTO targets VALUES(?,?,?,?,?)",
                        ((t, nm, "base", int(lk), prio("base", nm)) for t, nm, lk in src.execute(q, (SYMLINK,))))
    if not con.execute("SELECT 1 FROM cfiles").fetchone():
        con.executemany("INSERT INTO cfiles VALUES(?,?,?)", src.execute("SELECT fid, path, nstripes FROM cfiles"))
        con.executemany("INSERT INTO cwork(round, seq, fid, stripe) VALUES(1,?,?,?)",
                        src.execute("SELECT seq, fid, stripe FROM cwork ORDER BY seq"))
    setmeta(con, "init", {"src": str(a.src), "at": time.strftime("%Y-%m-%d %H:%M"), "controls": a.controls})
    con.commit()
    n1 = con.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    print(f"targets {n0:,} -> {n1:,}; content stripes "
          f"{con.execute('SELECT COUNT(*) FROM cwork WHERE round=1').fetchone()[0]:,}")
    for row in con.execute("SELECT prio, kind, COUNT(*) FROM targets GROUP BY 1,2 ORDER BY 1,2"):
        print("  prio %d %-8s %10s" % (row[0], row[1], f"{row[2]:,}"))


# ---------------------------------------------------------------- map
_LUT = None
_nd: dict = {}
_content: dict = {}


def raw20(arr):
    """Fixed 40-char hex string column (pyarrow StringArray) -> (n, 20) uint8 matrix, vectorised."""
    import numpy as np
    global _LUT
    if _LUT is None:
        _LUT = np.zeros(256, np.uint8)
        for i, c in enumerate(b"0123456789abcdef"):
            _LUT[c] = i
        for i, c in enumerate(b"ABCDEF"):
            _LUT[c] = 10 + i
    if arr.null_count:
        raise ValueError("nulls in hash column")
    offs = np.frombuffer(arr.buffers()[1], dtype=np.int32)[arr.offset:arr.offset + len(arr) + 1]
    if len(arr) and (offs[-1] - offs[0] != 40 * len(arr) or (np.diff(offs) != 40).any()):
        raise ValueError("hash column is not fixed 40-char hex")
    d = np.frombuffer(arr.buffers()[2], dtype=np.uint8)[offs[0]:offs[-1]].reshape(-1, 40)
    nib = _LUT[d]
    return (nib[:, 0::2] << 4) | nib[:, 1::2]


def needle_arrays(raw):
    """Sorted big-endian uint64 prefixes + the full 20-byte rows in the same order."""
    import numpy as np
    pre = np.ascontiguousarray(raw[:, :8]).view(">u8").ravel().astype(np.uint64)
    order = np.argsort(pre, kind="stable")
    return pre[order], np.ascontiguousarray(raw[order])


def match_rows(raw, pre, full):
    """Row indexes of `raw` (n, 20) whose 20 bytes are in the needle set (pre, full)."""
    import numpy as np
    if not len(pre) or not len(raw):
        return []
    rp = np.ascontiguousarray(raw[:, :8]).view(">u8").ravel().astype(np.uint64)
    pos = np.searchsorted(pre, rp)
    pos[pos == len(pre)] = 0
    out = []
    for i in np.nonzero(pre[pos] == rp)[0].tolist():
        j = int(pos[i])
        while j < len(pre) and pre[j] == rp[i]:   # equal prefixes are adjacent; check all 20 bytes
            if (full[j] == raw[i]).all():
                out.append(i)
                break
            j += 1
    return out


def _needles(prefix):
    import numpy as np
    if _nd.get("p") != prefix:
        _nd.update(p=prefix, pre=np.load(f"{prefix}_pre.npy", mmap_mode="r"),
                   full=np.load(f"{prefix}_full.npy", mmap_mode="r"))
    return _nd["pre"], _nd["full"]


def map_stripe(path, k, prefix):
    import pyarrow.orc as orc
    from orcmeta import OrcFile
    pre, full = _needles(prefix)
    if path not in _content:
        raw = s3fs().open_input_file(path)
        _content[path] = (orc.ORCFile(raw), OrcFile(raw))
    pf, mf = _content[path]
    sg = pf.read_stripe(k, columns=["sha1_git"]).column(0)
    raw = raw20(sg)
    idx = match_rows(raw, pre, full)
    if not idx:
        return len(sg), []
    sha1 = mf.fixed_strings(k, 1, 40, idx)
    meta = pf.read_stripe(k, columns=["length", "status"])
    ln, st = meta.column(0), meta.column(1)
    return len(sg), [(bytes(raw[r]), bytes.fromhex(sha1[r].decode()), ln[r].as_py(), st[r].as_py()) for r in idx]


def _mjob(args):
    seq, path, k, prefix = args
    err = None
    for attempt in range(5):
        try:
            n, rows = map_stripe(path, k, prefix)
            return seq, n, rows, None
        except Exception as e:   # network hiccup: reopen and retry
            _content.pop(path, None)
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
    return seq, 0, [], err


def current_round(con):
    r = con.execute("SELECT MIN(round) FROM cwork WHERE done_at IS NULL").fetchone()[0]
    return r or con.execute("SELECT MAX(round) FROM cwork").fetchone()[0]


def build_needles(con, rnd):
    """Fixed for the whole round: every target with no blob row yet when the round starts."""
    import numpy as np
    prefix = DATA / f"needles_r{rnd}"
    if pathlib.Path(f"{prefix}_full.npy").exists():
        return prefix, getmeta(con, f"needles_r{rnd}")
    rows = [r[0] for r in con.execute("SELECT t.target FROM targets t LEFT JOIN blobs b ON b.sha1_git=t.target "
                                      "WHERE b.sha1_git IS NULL")]
    raw = np.frombuffer(b"".join(rows), np.uint8).reshape(-1, 20) if rows else np.zeros((0, 20), np.uint8)
    pre, full = needle_arrays(raw)
    for nm, arr in (("pre", pre), ("full", full)):
        tmp = pathlib.Path(f"{prefix}_{nm}.tmp.npy")
        np.save(tmp, arr)
        os.replace(tmp, f"{prefix}_{nm}.npy")
    setmeta(con, f"needles_r{rnd}", len(rows))
    con.commit()
    return prefix, len(rows)


def cmd_addhop(a):
    """Add file targets found by hop.py (entries inside agent dirs) as kind hop<level>, fetched first (prio 0).
    A blob already queued by pass 1 keeps its pass-1 kind. Run before `newround` so the round's needles hold them."""
    src = sqlite3.connect(f"file:{pathlib.Path(a.hopdb).resolve().as_posix()}?mode=ro", uri=True)
    con = db()
    n0 = con.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    rows = src.execute("SELECT target, MIN(tool), kind, MAX(perms=?) FROM entries WHERE type='file' "
                       "GROUP BY target, kind", (SYMLINK,))
    con.executemany("INSERT OR IGNORE INTO targets VALUES(?,?,?,?,?)",
                    ((t, tool, kind, int(lk), prio(kind, tool)) for t, tool, kind, lk in rows))
    con.commit()
    print(f"targets {n0:,} -> {con.execute('SELECT COUNT(*) FROM targets').fetchone()[0]:,}",
          con.execute("SELECT kind, COUNT(*) FROM targets WHERE kind LIKE 'hop%' GROUP BY 1").fetchall())


def cmd_newround(a):
    con = db()
    r = con.execute("SELECT MAX(round) FROM cwork").fetchone()[0]
    if con.execute("SELECT 1 FROM cwork WHERE round=? AND done_at IS NULL", (r,)).fetchone():
        sys.exit(f"round {r} is not finished")
    con.execute("INSERT INTO cwork(round, seq, fid, stripe) SELECT ?, seq, fid, stripe FROM cwork WHERE round=?",
                (r + 1, r))
    con.commit()
    print(f"round {r + 1} queued")


def cmd_map(a):
    con = db()
    rnd = current_round(con)
    prefix, n_need = build_needles(con, rnd)
    paths = dict(con.execute("SELECT fid, path FROM cfiles"))
    todo = con.execute("SELECT seq, fid, stripe FROM cwork WHERE round=? AND done_at IS NULL ORDER BY seq",
                       (rnd,)).fetchall()
    print(f"round {rnd}: {n_need:,} needles, {len(todo):,} content stripes to do, {a.workers} workers", flush=True)
    stop, t0, n, found, last_commit = DATA / "STOP_MAP", time.time(), 0, 0, time.time()
    with ProcessPoolExecutor(a.workers, max_tasks_per_child=40) as ex:
        pending, it = set(), iter(todo)

        def submit():
            for seq, fid, k in it:
                pending.add(ex.submit(_mjob, (seq, paths[fid], k, str(prefix))))
                return
        for _ in range(a.workers * 2):
            submit()
        while pending:
            fu = next(as_completed(pending))
            pending.discard(fu)
            seq, nrows, rows, err = fu.result()
            if err:
                con.execute("INSERT INTO errors VALUES(?,?,?,?)", ("map", f"r{rnd}/{seq}", err, time.time()))
            else:
                con.executemany("INSERT OR IGNORE INTO blobs VALUES(?,?,?,?,?)", [r + (rnd,) for r in rows])
                con.execute("UPDATE cwork SET rows=?, matched=?, done_at=? WHERE round=? AND seq=?",
                            (nrows, len(rows), time.time(), rnd, seq))
                n, found = n + 1, found + len(rows)
            if time.time() - last_commit > 5:
                con.commit()
                last_commit = time.time()
            if n and n % 500 == 0:
                rate = n / (time.time() - t0) * 3600
                print(f"{time.strftime('%H:%M:%S')} {n:,}/{len(todo):,} stripes, {found:,} mapped, {rate:,.0f}/h, "
                      f"ETA {(len(todo) - n) / max(rate, 1):.1f} h", flush=True)
            if not stop.exists():
                submit()
    con.commit()
    left = con.execute("SELECT COUNT(*) FROM cwork WHERE round=? AND done_at IS NULL", (rnd,)).fetchone()[0]
    print(f"map round {rnd} {'finished' if not left else f'stopped, {left:,} stripes left'}; {found:,} mapped",
          flush=True)


# ---------------------------------------------------------------- fetch
_tls = threading.local()


def http_get(path):
    """GET over a per-thread keep-alive HTTPS connection. -> (status or None, body or None, err or None)."""
    err = None
    for attempt in range(6):
        conn = getattr(_tls, "c", None)
        if conn is None:
            conn = _tls.c = http.client.HTTPSConnection(HOST, timeout=60)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status == 200:
                return 200, body, None
            if resp.status in (403, 404):
                return resp.status, None, f"HTTP {resp.status}"
            err = f"HTTP {resp.status}"   # 500/503 SlowDown: back off and retry
        except (OSError, http.client.HTTPException) as e:
            err = f"{type(e).__name__}: {e}"
            try:
                conn.close()
            except Exception:
                pass
            _tls.c = None
        time.sleep(min(30, 2 ** attempt))
    return None, None, err


def verify(data: bytes, sha1: bytes, sha1_git: bytes) -> bool:
    return (hashlib.sha1(data).digest() == sha1
            and hashlib.sha1(b"blob %d\x00" % len(data) + data).digest() == sha1_git)


def fetch_one(sha1_git, sha1):
    """-> (sha1_git, state, http status, err, gz bytes to keep or None)"""
    code, body, err = http_get(f"/content/{sha1.hex()}")
    if code != 200:
        return sha1_git, ("missing" if code in (403, 404) else "error"), code, err, None
    try:
        data = gzip.decompress(body)
    except Exception as e:
        return sha1_git, "error", code, f"gunzip {type(e).__name__}: {e}", None
    if verify(data, sha1, sha1_git):
        return sha1_git, "ok", code, None, body
    return sha1_git, "hash_mismatch", code, f"{len(data)} bytes", body


class Corpus:
    """16 SQLite shards by the first hex digit of sha1_git. Writes from one thread only."""

    def __init__(self, ro=False):
        self.ro, self.c = ro, {}
        if not ro:
            CORPUS.mkdir(parents=True, exist_ok=True)

    def con(self, h):
        if h not in self.c:
            p = CORPUS / f"{h:x}.sqlite"
            if self.ro:
                c = sqlite3.connect(f"file:{p.resolve().as_posix()}?mode=ro", uri=True, timeout=300)
            else:
                c = sqlite3.connect(p, timeout=300)
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA synchronous=NORMAL")
                c.execute("CREATE TABLE IF NOT EXISTS c(sha1_git BLOB PRIMARY KEY, gz BLOB)")
            self.c[h] = c
        return self.c[h]

    def put(self, sg, gz):
        self.con(sg[0] >> 4).execute("INSERT OR REPLACE INTO c VALUES(?,?)", (sg, gz))

    def get(self, sg):
        r = self.con(sg[0] >> 4).execute("SELECT gz FROM c WHERE sha1_git=?", (sg,)).fetchone()
        return r[0] if r else None

    def commit(self):
        for c in self.c.values():
            c.commit()


def part_range(part: str):
    """'i/n' -> [lo, hi) slice of the sha1_git space; n | 16 keeps each corpus shard in one process."""
    i, n = (int(x) for x in part.split("/"))
    lo = bytes([256 * i // n]) if i else b""
    hi = bytes([256 * (i + 1) // n]) if i + 1 < n else b"\xff" * 21
    return lo, hi


def fetch_queue(con, max_prio, part="0/1", batch=2000):
    """Keyset walk over mapped, visible, not-too-big targets with no fetch row yet: prio 0 first, then by target."""
    lo, hi = part_range(part)
    q = ("SELECT t.target, b.sha1 FROM targets t JOIN blobs b ON b.sha1_git=t.target "
         "WHERE t.prio = ? AND t.target {} ? AND t.target < ? AND b.status='visible' AND b.length <= ? "
         "AND NOT EXISTS (SELECT 1 FROM fetch f WHERE f.sha1_git=t.target) ORDER BY t.target LIMIT ?")
    for p in range(max_prio + 1):
        last, op = lo, ">="
        while True:
            rows = con.execute(q.format(op), (p, last, hi, MAX_FETCH, batch)).fetchall()
            if not rows:
                break
            last, op = rows[-1][0], ">"
            yield from rows


def mark_unfetchable(con):
    now = time.time()
    a = con.execute("INSERT OR IGNORE INTO fetch(sha1_git, state, at) SELECT sha1_git, 'not_visible', ? FROM blobs "
                    "WHERE status != 'visible'", (now,)).rowcount
    b = con.execute("INSERT OR IGNORE INTO fetch(sha1_git, state, at) SELECT sha1_git, 'too_big', ? FROM blobs "
                    "WHERE status = 'visible' AND length > ?", (now, MAX_FETCH)).rowcount
    con.commit()
    return a, b


def cmd_fetch(a):
    con, corpus = db(), Corpus()
    stop = DATA / "STOP_FETCH"
    t0, n, last_commit, counts = time.time(), 0, time.time(), {}
    with ThreadPoolExecutor(a.threads) as ex:
        while not stop.exists():
            nv, nb = mark_unfetchable(con)
            map_busy = con.execute("SELECT 1 FROM cwork WHERE done_at IS NULL").fetchone() is not None
            got, pending, it = 0, set(), fetch_queue(con, a.max_prio, a.part)

            def submit():
                for sg, s1 in it:
                    pending.add(ex.submit(fetch_one, sg, s1))
                    return True
                return False
            for _ in range(a.threads * 4):
                if not submit():
                    break
            out = []
            while pending:
                fu = next(as_completed(pending))
                pending.discard(fu)
                out.append(fu.result())
                if len(out) >= 1000 or time.time() - last_commit > 5 or not pending:
                    for sg, state, code, err, gz in out:
                        if gz is not None:
                            corpus.put(sg, gz)
                        counts[state] = counts.get(state, 0) + 1
                    corpus.commit()   # blob first, then its state: a crash can only cause a refetch
                    con.executemany("INSERT OR REPLACE INTO fetch VALUES(?,?,?,?,?)",
                                    [(sg, state, code, err, time.time()) for sg, state, code, err, _ in out])
                    con.commit()
                    got, n, out, last_commit = got + len(out), n + len(out), [], time.time()
                    if n % 20000 < 1000:
                        rate = n / (time.time() - t0)
                        print(f"{time.strftime('%H:%M:%S')} {n:,} fetched ({rate:,.0f}/s) {counts}", flush=True)
                if not stop.exists():
                    submit()
            if not got and not map_busy:
                break
            if not got:
                time.sleep(120)   # map still running: wait for new blobs
    print(f"fetch {'stopped' if stop.exists() else 'finished'}: {n:,} this run {counts}", flush=True)


def cmd_retry(a):
    con = db()
    n = con.execute("DELETE FROM fetch WHERE state='error'").rowcount
    con.commit()
    print(f"{n:,} errored blobs re-queued")


# ---------------------------------------------------------------- scan
def link_info(data: bytes):
    """A symlink blob is the link path. Outside the repo = absolute or home-relative; '../' may or may not leave it."""
    to = data.decode("utf-8", "replace")
    outside = to.startswith(("/", "~", "\\")) or (len(to) > 1 and to[1] == ":")
    rule = "link_outside" if outside else "link_up" if to.startswith("../") else "link"
    return {"verdict": "symlink", "flags": [{"rule": rule, "to": to[:500]}]}


def _scan_chunk(keys):
    """-> [(sha1_git, scan result or None, truncated, err, encoding, features)]"""
    import afscan
    corpus, out = Corpus(ro=True), []
    for sg, link in keys:
        gz = corpus.get(sg)
        if gz is None:
            out.append((sg, None, 0, "not in corpus", None, None))
            continue
        data = gzip.decompress(gz)
        if link:
            out.append((sg, link_info(data), 0, None, "link", None))
            continue
        text, enc = afscan.decode(data)
        trunc = int(len(text) > SCAN_CAP)
        text = text[:SCAN_CAP]
        out.append((sg, afscan.scan_text(text), trunc, None, enc, afscan.features(text)))
    return out


def cmd_scan(a):
    import afscan
    ver = afscan.__version__
    con = db()
    sev = {"symlink": -2, "clean": -1, "info": 0, "low": 1, "medium": 2, "high": 3}
    q = ("SELECT f.sha1_git, t.link FROM fetch f JOIN targets t ON t.target=f.sha1_git WHERE f.state='ok' "
         "AND f.sha1_git >= ? AND f.sha1_git < ? AND t.prio <= ? "
         "AND NOT EXISTS (SELECT 1 FROM findings x WHERE x.sha1_git=f.sha1_git AND x.ver=?)")
    t0, n = time.time(), 0
    with ProcessPoolExecutor(a.workers) as ex:
        for h in range(16):
            lo, hi = bytes([h << 4]), (bytes([(h + 1) << 4]) if h < 15 else b"\xff" * 21)
            keys = con.execute(q, (lo, hi, a.max_prio, ver)).fetchall()
            futs = [ex.submit(_scan_chunk, keys[i:i + 500]) for i in range(0, len(keys), 500)]
            for fu in as_completed(futs):
                rows, feats = [], []
                for sg, res, trunc, err, enc, feat in fu.result():
                    if res is None:
                        con.execute("INSERT INTO errors VALUES(?,?,?,?)", ("scan", sg.hex(), err, time.time()))
                        continue
                    rules = ",".join(sorted({f["rule"] for f in res["flags"]}))
                    rows.append((sg, ver, res["verdict"], sev.get(res["verdict"], -1), rules,
                                 json.dumps(res["flags"], ensure_ascii=False), trunc, time.time()))
                    feats.append((sg, ver, enc, json.dumps(feat, separators=(",", ":")) if feat else None))
                con.executemany("INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?)", rows)
                con.executemany("INSERT OR REPLACE INTO features VALUES(?,?,?,?)", feats)
                con.commit()
                n += len(rows)
            print(f"{time.strftime('%H:%M:%S')} shard {h:x} done, {n:,} scanned "
                  f"({n / max(time.time() - t0, 1):,.0f}/s)", flush=True)
    print(f"scan finished: {n:,} blobs, afscan {ver}", flush=True)


# ---------------------------------------------------------------- status
def cmd_status(a):
    con = db()
    for rnd, tot, done, matched in con.execute("SELECT round, COUNT(*), COUNT(done_at), SUM(matched) FROM cwork "
                                               "GROUP BY round"):
        print(f"map round {rnd}: {done:,}/{tot:,} content stripes, {matched or 0:,} mapped, "
              f"{getmeta(con, f'needles_r{rnd}', '?')} needles")
    ver = a.ver
    if not ver:
        r = con.execute("SELECT ver FROM findings ORDER BY at DESC LIMIT 1").fetchone()
        ver = r[0] if r else ""
    q = """SELECT t.kind, t.tool, COUNT(*), COUNT(b.sha1_git),
        SUM(f.state='not_visible'), SUM(f.state='too_big'), SUM(f.state='missing'), SUM(f.state='error'),
        SUM(f.state='hash_mismatch'), SUM(f.state='ok'), COUNT(x.sha1_git), SUM(x.flag >= 2)
        FROM targets t LEFT JOIN blobs b ON b.sha1_git=t.target LEFT JOIN fetch f ON f.sha1_git=t.target
        LEFT JOIN findings x ON x.sha1_git=t.target AND x.ver=? GROUP BY 1,2 ORDER BY 1, 3 DESC"""
    hdr = ("kind", "tool", "targets", "mapped", "not_vis", "too_big", "missing", "error", "bad_hash", "kept",
           f"scanned {ver}", ">=medium")
    print(("%-7s %-22s" + " %10s" * 10) % hdr)
    tot = [0] * 10
    for row in con.execute(q, (ver,)):
        vals = [v or 0 for v in row[2:]]
        tot = [x + y for x, y in zip(tot, vals)]
        print(("%-7s %-22s" + " %10s" * 10) % (row[0], (row[1] or "")[:22], *[f"{v:,}" for v in vals]))
    print(("%-7s %-22s" + " %10s" * 10) % ("ALL", "", *[f"{v:,}" for v in tot]))
    print("errors:", con.execute("SELECT stage, COUNT(*) FROM errors GROUP BY stage").fetchall())


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("src")
    i.add_argument("--controls", action="store_true")
    m = sub.add_parser("map")
    m.add_argument("--workers", type=int, default=16)
    sub.add_parser("newround")
    ah = sub.add_parser("addhop")
    ah.add_argument("hopdb")
    f = sub.add_parser("fetch")
    f.add_argument("--threads", type=int, default=64)
    f.add_argument("--max-prio", type=int, default=3)
    f.add_argument("--part", default="0/1", help="i/n: this process fetches slice i of n of the sha1_git space")
    s = sub.add_parser("scan")
    s.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    s.add_argument("--max-prio", type=int, default=3)
    st = sub.add_parser("status")
    st.add_argument("--ver", default="")
    sub.add_parser("retry")
    a = p.parse_args()
    {"init": cmd_init, "map": cmd_map, "newround": cmd_newround, "addhop": cmd_addhop, "fetch": cmd_fetch,
     "scan": cmd_scan, "status": cmd_status, "retry": cmd_retry}[a.cmd](a)
