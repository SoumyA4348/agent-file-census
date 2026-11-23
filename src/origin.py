"""Pass 5 (origin), 2026-11-22: which hosting platform (GitHub, GitLab, ...) each agent file came from.

    python -I src/origin.py needles                 # laptop: parent dirs of census entries -> data/origin/dir_*.npy
    python -I src/origin.py scan STAGE [--workers N] # VM: STAGE in revision release snapshot_branch ovs (in order)
    python -I src/origin.py status
    python -I src/origin.py join [--mem 10GB]       # VM, after ovs (DuckDB): blob -> origins, dates -> join.duckdb
    python -I src/origin.py report [--labels CSV] [--blobs HEX,..]   # -> results/origin_*.csv (aggregates)

Chain (2026-06-04 export): file entry (dir) -> revision.directory -> revision.id [-> release.target]
-> snapshot_branch.target -> snapshot_id -> origin_visit_status.snapshot -> origin (URL).
Only directories that are a commit's root reach a revision, so a file links when its parent dir (or, for hop
files, its agent dir's parent) is a root, and only commits that were a branch head or tag at some visit reach a
snapshot. Coverage is reported, not assumed. Each stage keeps the rows whose key is in the previous stage's
output; stages are resumable per stripe.
"""
import argparse
import os
import pathlib
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
DATA = ROOT / "data"
OUT = DATA / "origin"
DB = OUT / "origin.sqlite"
BASE = "softwareheritage/graph/2026-06-04/orc/"

# stage: (table, key column, key col id, value column, value col id, needles from, value is fixed 40-hex)
STAGES = {
    "revision": ("revision", "directory", 11, "id", 1, "dir", True),
    "revdate": ("revision", "directory", 11, "date", None, "dir", False),   # adoption timeline
    "release": ("release", "target", 4, "id", 1, "rev", True),
    "snapshot_branch": ("snapshot_branch", "target", 3, "snapshot_id", 1, "revrel", True),
    "ovs": ("origin_visit_status", "snapshot", 5, "origin", 1, "snp", False),   # origin = URL
}
NEXT = {"revdate": None, "revision": "rev", "release": None, "snapshot_branch": "snp", "ovs": None}


def s3fs():
    import pyarrow.fs as fs
    return fs.S3FileSystem(anonymous=True, region="us-east-1", request_timeout=60, connect_timeout=20)


def db():
    OUT.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=120)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE IF NOT EXISTS work(stage TEXT, path TEXT, stripe INT, rows INT, kept INT, done_at REAL,"
                " PRIMARY KEY(stage, path, stripe))")
    con.execute("CREATE TABLE IF NOT EXISTS hits(stage TEXT, k BLOB, v BLOB)")
    return con


def save_needles(name, raw):
    import numpy as np
    from corpus import needle_arrays
    if len(raw):   # dedupe: sort by full 20 bytes via lexsort on 3 big-endian words
        w = [np.ascontiguousarray(raw[:, i:j]).view(">u8" if j - i == 8 else ">u4").ravel() for i, j in ((0, 8), (8, 16), (16, 20))]
        o = np.lexsort((w[2], w[1], w[0]))
        raw = raw[o]
        keep = np.ones(len(raw), bool)
        keep[1:] = (raw[1:] != raw[:-1]).any(1)
        raw = raw[keep]
    pre, full = needle_arrays(raw)
    np.save(OUT / f"{name}_pre.npy", pre)
    np.save(OUT / f"{name}_full.npy", full)
    print(f"needles {name}: {len(pre):,}", flush=True)


def cmd_needles(a):
    """Distinct parent dirs of every census entry (agent files and agent dirs)."""
    import numpy as np
    OUT.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{(DATA / 'hits_v2.sqlite').as_posix()}?mode=ro", uri=True)
    src.execute("PRAGMA temp_store=FILE")
    chunks, n, t0 = [], 0, time.time()
    cur = src.execute("SELECT DISTINCT dir FROM entries WHERE kind <> 'base'")   # README/manifest controls skipped
    while True:
        rows = cur.fetchmany(2_000_000)
        if not rows:
            break
        chunks.append(np.frombuffer(b"".join(r[0] for r in rows), np.uint8).reshape(-1, 20))
        n += len(rows)
        print(f"{n:,} distinct dirs, {time.time() - t0:.0f}s", flush=True)
    save_needles("dir", np.concatenate(chunks) if chunks else np.zeros((0, 20), np.uint8))


def _load(name):
    import numpy as np
    return np.load(OUT / f"{name}_pre.npy", mmap_mode="r"), np.load(OUT / f"{name}_full.npy", mmap_mode="r")


_cache: dict = {}


def hexcol(col):
    """40-hex string column with possible nulls -> (n, 20) uint8 (nulls and non-hash values such as alias-branch
    targets -> zero hash, which never matches)."""
    import pyarrow.compute as pc
    from corpus import raw20
    if col.null_count:
        col = pc.fill_null(col, "0" * 40)
    ok = pc.equal(pc.binary_length(col), 40)
    if not pc.all(ok).as_py():
        col = pc.if_else(ok, col, "0" * 40)
    return raw20(col)


def pyorc_dates(path, k, col, idx):
    """Fallback when pyarrow refuses a stripe (timestamps beyond the ns range): pyorc, seconds only."""
    import pyorc
    from pyorc.converters import ORCConverter

    class Sec(ORCConverter):
        @staticmethod
        def from_orc(seconds, *_):
            return seconds

        @staticmethod
        def to_orc(*_):
            raise NotImplementedError

    r = pyorc.Reader(s3fs().open_input_file(path), column_names=(col,),
                     converters={pyorc.TypeKind.TIMESTAMP: Sec})
    st, out = r.read_stripe(k), {}
    for i in sorted(idx):
        st.seek(i)
        v = next(st)[0]
        if v is not None:
            out[i] = v
    return out


def scan_stripe(stage, path, k):
    import pyarrow.orc as orc
    from corpus import match_rows
    from orcmeta import OrcFile
    table, key, kid, val, vid, src, fixed = STAGES[stage]
    if "nd" not in _cache:
        _cache["nd"] = _load(src)
    pre, full = _cache["nd"]
    if _cache.get("path") != path:
        raw = s3fs().open_input_file(path)
        _cache.update(path=path, pf=orc.ORCFile(raw), mf=OrcFile(raw))
    pf, mf = _cache["pf"], _cache["mf"]
    kc = pf.read_stripe(k, columns=[key]).column(0)
    raw = hexcol(kc)
    idx = match_rows(raw, pre, full)
    if not idx:
        return len(kc), []
    vals = None
    if vid is not None and fixed:
        try:
            got = mf.fixed_strings(k, vid, 40, idx)
            vals = {r: bytes.fromhex(got[r].decode()) for r in idx}
        except Exception:
            vals = None
    if vals is None:
        try:
            vc = pf.read_stripe(k, columns=[val]).column(0)
        except Exception as e:
            if val != "date" or "out of range" not in str(e):
                raise
            return len(kc), [(bytes(raw[r]), v) for r, v in pyorc_dates(path, k, val, idx).items()]
        if val == "date":   # timestamp[ns] -> int ns (bogus dates would overflow datetime)
            import pyarrow as pa
            vc = vc.cast(pa.int64())
        vals = {}
        for r in idx:
            v = vc[r].as_py()
            if v is None:
                continue
            if val == "date":   # epoch seconds
                vals[r] = v // 1_000_000_000
            else:
                vals[r] = bytes.fromhex(v) if fixed else (v.encode() if isinstance(v, str) else v)
    return len(kc), [(bytes(raw[r]), vals[r]) for r in idx if r in vals]


def _job(args):
    stage, path, k = args
    err = None
    for attempt in range(5):
        try:
            n, rows = scan_stripe(stage, path, k)
            return path, k, n, rows, None
        except Exception as e:
            _cache.pop("path", None)
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
    return path, k, 0, [], err


def build_next(con, stage):
    """Needles for the next stage from this stage's distinct values (snapshot_branch also gets release ids)."""
    import numpy as np
    nxt = NEXT[stage]
    if stage == "release":   # revrel = matched revisions + releases pointing to them
        vals = [r[0] for r in con.execute("SELECT DISTINCT v FROM hits WHERE stage='revision'")]
        vals += [r[0] for r in con.execute("SELECT DISTINCT v FROM hits WHERE stage='release'")]
        nxt = "revrel"
    else:
        if nxt is None:
            return
        vals = [r[0] for r in con.execute("SELECT DISTINCT v FROM hits WHERE stage=?", (stage,))]
    raw = np.frombuffer(b"".join(vals), np.uint8).reshape(-1, 20) if vals else np.zeros((0, 20), np.uint8)
    save_needles(nxt, raw)


def cmd_scan(a):
    import pyarrow.fs as fs
    import pyarrow.orc as orc
    con = db()
    stage = a.stage
    table = STAGES[stage][0]
    if not con.execute("SELECT 1 FROM work WHERE stage=? LIMIT 1", (stage,)).fetchone():
        s = s3fs()
        files = sorted(i.path for i in s.get_file_info(fs.FileSelector(BASE + table)) if i.type == fs.FileType.File)
        rows = []
        for p in files:
            rows += [(stage, p, k) for k in range(orc.ORCFile(s.open_input_file(p)).nstripes)]
        con.executemany("INSERT OR IGNORE INTO work(stage, path, stripe) VALUES(?,?,?)", rows)
        con.commit()
    todo = con.execute("SELECT path, stripe FROM work WHERE stage=? AND done_at IS NULL ORDER BY path, stripe",
                       (stage,)).fetchall()
    print(f"{stage}: {len(todo):,} stripes to do, {a.workers} workers", flush=True)
    t0, n, kept, last = time.time(), 0, 0, time.time()
    with ProcessPoolExecutor(a.workers) as ex:
        futs = {ex.submit(_job, (stage, p, k)) for p, k in todo}
        for fu in as_completed(futs):
            path, k, nrows, rows, err = fu.result()
            futs.discard(fu)   # drop the finished future: held results OOM-killed the scan at ~45M rows
            if err:
                print("ERR", path, k, err, flush=True)
                continue
            con.executemany("INSERT INTO hits VALUES(?,?,?)", [(stage, kk, v) for kk, v in rows])
            con.execute("UPDATE work SET rows=?, kept=?, done_at=? WHERE stage=? AND path=? AND stripe=?",
                        (nrows, len(rows), time.time(), stage, path, k))
            n, kept = n + 1, kept + len(rows)
            if time.time() - last > 10:
                con.commit()
                last = time.time()
                rate = n / (time.time() - t0) * 3600
                print(f"{time.strftime('%H:%M:%S')} {n:,}/{len(todo):,} stripes, {kept:,} kept, {rate:,.0f}/h, "
                      f"ETA {(len(todo) - n) / max(rate, 1):.1f} h", flush=True)
    con.commit()
    left = con.execute("SELECT COUNT(*) FROM work WHERE stage=? AND done_at IS NULL", (stage,)).fetchone()[0]
    print(f"{stage} {'finished' if not left else f'stopped, {left} stripes left (rerun)'}; {kept:,} kept", flush=True)
    if not left:
        build_next(con, stage)


def cmd_status(a):
    con = db()
    for st, tot, done, kept in con.execute("SELECT stage, COUNT(*), COUNT(done_at), SUM(kept) FROM work GROUP BY 1"):
        print(f"{st}: {done:,}/{tot:,} stripes, {kept or 0:,} kept")


def host_of(url: str) -> str:
    u = url.split("://", 1)[-1].split("/", 1)[0].lower()
    return u.split("@")[-1].split(":")[0]


MAXPAR = 50   # parents kept per dir per level (popular subtrees sit in thousands of parents)
HOSTSQL = r"lower(regexp_extract(url, '^(?:[A-Za-z0-9+.-]+://)?(?:[^@/]*@)?([^/:]+)', 1))"


def duck(a):
    import duckdb
    c = duckdb.connect((OUT / "join.duckdb").as_posix())
    c.execute(f"SET memory_limit='{a.mem}'; SET temp_directory='{(OUT / 'duck_tmp').as_posix()}';"
              " SET preserve_insertion_order=false; SET enable_progress_bar=false")
    return c


def cmd_join(a):
    """VM, after ovs: blob -> origins (repos) and first commit date, walking up to --levels (default 4) directory levels to a commit root.
    DuckDB, spills to disk. Inputs: data/origin/origin.sqlite (revision/release/snapshot_branch/ovs hits) and
    data/origin/pq/{files,edges,root_date}.parquet (laptop exports: census agent/config file entries + hop file
    entries (dir, blob, kind, tool); dir edges (child, parent); revdate min commit time per root dir).
    Output: data/origin/join.duckdb (url, fdir, fblob, files, anc, dir_u, dir_date, blob_u)."""
    c = duck(a)
    c.execute("INSTALL sqlite; LOAD sqlite")
    c.execute(f"ATTACH '{DB.as_posix()}' AS o (TYPE sqlite, READ_ONLY)")
    P = (OUT / "pq").as_posix()
    t0 = time.time()
    steps = [
        ("ovs", "SELECT DISTINCT k AS snp, CAST(v AS VARCHAR) AS url FROM o.hits WHERE stage='ovs'"),
        ("url", f"SELECT row_number() OVER ()::INT AS uid, url, {HOSTSQL} AS host FROM (SELECT DISTINCT url FROM ovs)"),
        ("snp_u", "SELECT DISTINCT snp, uid FROM ovs JOIN url USING (url)"),
        ("rel", "SELECT k AS rev, v AS rel FROM o.hits WHERE stage='release'"),
        ("rev_u", "SELECT DISTINCT coalesce(r.rev, b.k) AS rev, s.uid FROM (SELECT k, v FROM o.hits"
                  " WHERE stage='snapshot_branch') b JOIN snp_u s ON b.v = s.snp LEFT JOIN rel r ON b.k = r.rel"),
        ("roots", "SELECT k AS d, v AS rev FROM o.hits WHERE stage='revision'"),
        ("root_u", "SELECT DISTINCT h.d, u.uid FROM roots h JOIN rev_u u ON h.rev = u.rev"),
        ("root_date", f"SELECT * FROM '{P}/root_date.parquet'"),
        ("edges", f"SELECT * FROM '{P}/edges.parquet'"),
        ("fdir", f"SELECT row_number() OVER ()::INT AS did, d FROM (SELECT DISTINCT dir AS d FROM '{P}/files.parquet')"),
        ("fblob", f"SELECT row_number() OVER ()::INT AS bid, b AS sha1 FROM (SELECT DISTINCT blob AS b FROM '{P}/files.parquet')"),
        ("files", f"SELECT DISTINCT fd.did, fb.bid, p.kind, p.tool FROM '{P}/files.parquet' p"
                  " JOIN fdir fd ON p.dir = fd.d JOIN fblob fb ON p.blob = fb.sha1"),
        ("anc0", "SELECT did, d AS a FROM fdir"),
    ]
    L = a.levels
    for lvl in range(1, L + 1):
        steps.append((f"anc{lvl}", f"SELECT did, a FROM (SELECT DISTINCT x.did, e.parent AS a FROM anc{lvl - 1} x"
                                   f" JOIN edges e ON x.a = e.child) QUALIFY row_number() OVER (PARTITION BY did) <= {MAXPAR}"))
    steps += [
        ("anc", " UNION ALL ".join(f"SELECT did, a, {i}::TINYINT AS lvl FROM anc{i}" for i in range(L + 1))),
        ("dir_u", "SELECT DISTINCT x.did, r.uid FROM anc x JOIN root_u r ON x.a = r.d"),
        ("dir_date", "SELECT x.did, min(r.ts) AS ts FROM anc x JOIN root_date r ON x.a = r.d GROUP BY 1"),
        ("blob_u", "SELECT DISTINCT f.bid, u.uid FROM files f JOIN dir_u u USING (did)"),
    ]
    for name, sql in steps:
        if a.only and name not in a.only.split(","):
            continue
        c.execute(f"CREATE OR REPLACE TABLE {name} AS {sql}")
        n = c.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        print(f"{time.time() - t0:7.0f}s {name}: {n:,}", flush=True)
    for t in ["ovs"] + [f"anc{i}" for i in range(L + 1)]:
        c.execute(f"DROP TABLE IF EXISTS {t}")
    print("join done", flush=True)


PLATFORMS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com", "sourceforge.net")


def cmd_report(a):
    """Aggregates from join.duckdb -> results/origin_*.csv (no URLs or hashes), plus notes/origin_blobs.md for
    named blobs (URLs, local only)."""
    import csv
    c = duck(a)
    res = ROOT / "results"
    res.mkdir(exist_ok=True)
    plat = "CASE " + " ".join(f"WHEN host = '{p}' OR host LIKE '%.{p}' THEN '{p}'" for p in PLATFORMS) + \
           " WHEN host LIKE '%gitlab%' THEN 'self-hosted gitlab' ELSE 'other' END"
    c.execute(f"CREATE OR REPLACE TEMP TABLE up AS SELECT uid, {plat} AS platform FROM url")
    c.execute("CREATE OR REPLACE TEMP TABLE bk AS SELECT DISTINCT bid, kind, tool FROM files")
    c.execute("CREATE OR REPLACE TEMP TABLE bdate AS SELECT f.bid, min(d.ts) AS ts FROM files f JOIN dir_date d USING (did) GROUP BY 1")

    def out(name, sql):
        cur = c.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        with open(res / name, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
        print(f"{name}: {len(rows)} rows", flush=True)

    out("origin_coverage.csv", """
        SELECT bk.kind, count(DISTINCT bk.bid) AS blobs,
               count(DISTINCT CASE WHEN o.bid IS NOT NULL THEN bk.bid END) AS blobs_with_origin,
               count(DISTINCT CASE WHEN d.bid IS NOT NULL THEN bk.bid END) AS blobs_with_date
        FROM bk LEFT JOIN (SELECT DISTINCT bid FROM blob_u) o USING (bid) LEFT JOIN bdate d USING (bid)
        GROUP BY 1 ORDER BY 1""")
    out("origin_platforms.csv", """
        SELECT bk.kind, up.platform, count(DISTINCT bk.bid) AS blobs, count(DISTINCT bu.uid) AS origins
        FROM bk JOIN blob_u bu USING (bid) JOIN up USING (uid) GROUP BY 1, 2 ORDER BY 1, 3 DESC""")
    out("origin_platforms_by_tool.csv", """
        SELECT bk.kind, bk.tool, up.platform, count(DISTINCT bk.bid) AS blobs, count(DISTINCT bu.uid) AS origins
        FROM bk JOIN blob_u bu USING (bid) JOIN up USING (uid) GROUP BY 1, 2, 3 ORDER BY 1, 2, 4 DESC""")
    out("origin_spread.csv", """
        WITH n AS (SELECT bid, count(*) AS n FROM blob_u GROUP BY 1)
        SELECT bk.kind, count(DISTINCT bk.bid) AS blobs_with_origin, median(n.n) AS median_origins,
               quantile_cont(n.n, 0.9) AS p90_origins, max(n.n) AS max_origins,
               count(DISTINCT CASE WHEN n.n >= 10 THEN bk.bid END) AS blobs_in_10plus_origins
        FROM bk JOIN n USING (bid) GROUP BY 1 ORDER BY 1""")
    out("origin_timeline_blobs.csv", """
        SELECT bk.kind, bk.tool, strftime(to_timestamp(d.ts), '%Y-%m') AS month, count(DISTINCT bk.bid) AS new_blobs
        FROM bk JOIN bdate d USING (bid) GROUP BY 1, 2, 3 ORDER BY 1, 2, 3""")
    out("origin_timeline_repos.csv", """
        WITH f AS (SELECT u.uid, fl.kind, fl.tool, min(d.ts) AS ts FROM files fl JOIN dir_u u USING (did)
                   JOIN dir_date d USING (did) GROUP BY 1, 2, 3)
        SELECT kind, tool, strftime(to_timestamp(ts), '%Y-%m') AS month, count(*) AS repos_first_file
        FROM f GROUP BY 1, 2, 3 ORDER BY 1, 2, 3""")
    if a.labels:   # spread of labelled blobs (aggregates by label)
        lab = pathlib.Path(a.labels).resolve().as_posix()
        out("origin_spread_by_label.csv", f"""
            WITH l AS (SELECT from_hex(sha1_git) AS sha1, label FROM read_csv('{lab}', all_varchar=true)),
                 n AS (SELECT bid, count(*) AS n FROM blob_u GROUP BY 1)
            SELECT l.label, count(*) AS labelled, count(n.bid) AS with_origin, median(n.n) AS median_origins,
                   max(n.n) AS max_origins, min(strftime(to_timestamp(d.ts), '%Y-%m')) AS earliest
            FROM l LEFT JOIN fblob b USING (sha1) LEFT JOIN n USING (bid) LEFT JOIN bdate d USING (bid)
            GROUP BY 1 ORDER BY 1""")
    if a.blobs:   # named blobs by hex prefix: hosts, counts, sample URLs (local notes only)
        lines = ["# Origins of named blobs (local only: contains URLs)", ""]
        for pre in a.blobs.split(","):
            for bid, sha in c.execute("SELECT bid, hex(sha1) FROM fblob WHERE starts_with(lower(hex(sha1)), ?)",
                                      (pre.lower(),)).fetchall():
                n, first = c.execute("SELECT (SELECT count(*) FROM blob_u WHERE bid=?),"
                                     " (SELECT strftime(to_timestamp(ts), '%Y-%m-%d') FROM bdate WHERE bid=?)",
                                     (bid, bid)).fetchone()
                kinds = c.execute("SELECT string_agg(DISTINCT kind || '/' || tool, ', ') FROM files WHERE bid=?",
                                  (bid,)).fetchone()[0]
                lines.append(f"## {sha.lower()} ({kinds}): {n} origins, first commit {first}")
                for host, k in c.execute("SELECT u.host, count(*) FROM blob_u b JOIN url u USING (uid) WHERE b.bid=?"
                                         " GROUP BY 1 ORDER BY 2 DESC LIMIT 10", (bid,)).fetchall():
                    lines.append(f"- {host}: {k}")
                lines += [f"  - {r[0]}" for r in c.execute(
                    "SELECT u.url FROM blob_u b JOIN url u USING (uid) WHERE b.bid=? ORDER BY u.url LIMIT 25",
                    (bid,)).fetchall()]
                lines.append("")
        (ROOT / "notes" / "origin_blobs.md").write_text("\n".join(lines), encoding="utf-8")
        print("notes/origin_blobs.md written", flush=True)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("needles").set_defaults(f=cmd_needles)
    s = sp.add_parser("scan")
    s.add_argument("stage", choices=list(STAGES))
    s.add_argument("--workers", type=int, default=16)
    s.set_defaults(f=cmd_scan)
    sp.add_parser("status").set_defaults(f=cmd_status)
    for name, f in (("join", cmd_join), ("report", cmd_report)):
        j = sp.add_parser(name)
        j.add_argument("--mem", default="10GB")
        j.set_defaults(f=f)
        if name == "join":
            j.add_argument("--only", help="comma-separated steps to (re)build")
            j.add_argument("--levels", type=int, default=4, help="directory levels to walk up to a commit root")
        else:
            j.add_argument("--labels", help="CSV with sha1_git,label (aggregates by label)")
            j.add_argument("--blobs", help="comma-separated sha1_git hex prefixes -> notes/origin_blobs.md")
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
