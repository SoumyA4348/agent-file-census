"""Pass 3 (hop), v3 2026-11-19: entries inside agent/tool directories, reading only what matches.

    python src/hop.py seeds SRC.sqlite --level 1      # laptop: seed dirs from the census DB -> data/hop.sqlite
    python src/hop.py run --level 1 [--workers 24] [--from-seq A --to-seq B] [--reverse]   # cloud VM
    python src/hop.py merge OTHER_hop.sqlite          # fold another machine's hop DB into this one
    python src/hop.py status

Level 1 seeds = every directory that pass 1 kept as an agent/tool dir (.claude, .cursor, .kiro, .clinerules/, ...).
Level 2 seeds = their rule/command/agent subdirs found by level 1 (.claude/commands, .kiro/steering, .roo/rules-code).
Names like `commands/deploy.md` or `.kiro/steering/tech.md` can only be identified through the parent directory.

Why not census.py hop: almost every stripe holds some seed dir, so it read the whole `name` column (13-23% of
each stripe) everywhere. Here a stripe costs its directory_id column (2-4%) + type/perms (<1%): unique dirs are
matched against the sorted seed prefixes, and name/target are range-read for the matching rows only
(orcmeta.var_strings / fixed_strings, both checked against pyarrow).
The DB is portable (seeds + work + entries); entries use the census schema with kind 'hop<level>'.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from census import RULES_VERSION, _file, _open  # noqa: E402
from corpus import needle_arrays, raw20  # noqa: E402

DATA = ROOT / "data"
DB = pathlib.Path(os.environ.get("AFC_HOP_DB", DATA / "hop.sqlite"))
# level-2 seeds: subdirs of agent dirs that hold rule/command/agent files
HOP_SUBDIRS = {"steering", "rules", "commands", "command", "agents", "agent", "hooks", "prompts", "modes",
               "workflows", "memories", "memory", "instructions", "chatmodes", "specs", "skills", "output-styles"}
HOP_PREFIX = ("rules-",)   # Roo: .roo/rules-code, .roo/rules-architect, ...


def db(path=None):
    con = sqlite3.connect(path or DB, timeout=300)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS files(fid INTEGER PRIMARY KEY, path TEXT, nstripes INT, nrows INT);
    CREATE TABLE IF NOT EXISTS work(level INT, seq INT, fid INT, stripe INT, rows INT, kept INT, done_at REAL,
        PRIMARY KEY(level, seq));
    CREATE TABLE IF NOT EXISTS seeds(level INT, dir BLOB, tool TEXT, PRIMARY KEY(level, dir));
    CREATE TABLE IF NOT EXISTS entries(dir BLOB, name BLOB, type TEXT, target BLOB, perms INT,
        kind TEXT, tool TEXT, fid INT, stripe INT, row INT, v INT);
    CREATE TABLE IF NOT EXISTS errors(level INT, seq INT, err TEXT, at REAL);
    """)
    return con


def cmd_seeds(a):
    """Level 1 from the census DB; level >= 2 from this hop DB's level-(n-1) entries."""
    con = db()
    if a.level == 1:
        src = sqlite3.connect(f"file:{pathlib.Path(a.src).resolve().as_posix()}?mode=ro", uri=True)
        if not con.execute("SELECT 1 FROM files").fetchone():
            con.executemany("INSERT INTO files VALUES(?,?,?,?)", src.execute("SELECT fid, path, nstripes, nrows FROM files"))
        seeds = src.execute("SELECT target, MIN(tool) FROM entries WHERE type='dir' AND kind IN ('agent','config') "
                            "GROUP BY target")
        con.executemany("INSERT OR IGNORE INTO seeds VALUES(1,?,?)", seeds)
        con.executemany("INSERT OR IGNORE INTO work(level, seq, fid, stripe) VALUES(1,?,?,?)",
                        src.execute("SELECT seq, fid, stripe FROM work ORDER BY seq"))
    else:
        rows = con.execute("SELECT DISTINCT target, name, tool FROM entries WHERE type='dir' AND kind=?",
                           (f"hop{a.level - 1}",)).fetchall()
        keep = [(t, tool) for t, nm, tool in rows
                if (n := bytes(nm).decode("utf-8", "replace").lower()) in HOP_SUBDIRS or n.startswith(HOP_PREFIX)]
        con.executemany("INSERT OR IGNORE INTO seeds VALUES(?,?,?)", [(a.level, t, tool) for t, tool in keep])
        con.execute("INSERT OR IGNORE INTO work(level, seq, fid, stripe) SELECT ?, seq, fid, stripe FROM work "
                    "WHERE level=1", (a.level,))
    con.commit()
    write_seed_arrays(con, a.level)
    n = con.execute("SELECT COUNT(*) FROM seeds WHERE level=?", (a.level,)).fetchone()[0]
    print(f"level {a.level}: {n:,} seed dirs; top tools:",
          con.execute("SELECT tool, COUNT(*) FROM seeds WHERE level=? GROUP BY 1 ORDER BY 2 DESC LIMIT 12",
                      (a.level,)).fetchall())


def write_seed_arrays(con, level):
    """data/hop<level>_{pre,full,tool}.npy: sorted prefixes, full 20 bytes, tool code (index into hop<level>_tools)."""
    import json
    import numpy as np
    rows = con.execute("SELECT dir, tool FROM seeds WHERE level=?", (level,)).fetchall()
    tools = sorted({t or "" for _, t in rows})
    code = {t: i for i, t in enumerate(tools)}
    raw = np.frombuffer(b"".join(d for d, _ in rows), np.uint8).reshape(-1, 20)
    tc = np.array([code[t or ""] for _, t in rows], np.uint16)
    pre = np.ascontiguousarray(raw[:, :8]).view(">u8").ravel().astype(np.uint64)
    order = np.argsort(pre, kind="stable")
    for nm, arr in (("pre", pre[order]), ("full", np.ascontiguousarray(raw[order])), ("tool", tc[order])):
        np.save(DATA / f"hop{level}_{nm}.npy", arr)
    (DATA / f"hop{level}_tools.json").write_text(json.dumps(tools))


_seed: dict = {}


def _seeds(level):
    import json
    import numpy as np
    if _seed.get("level") != level:
        _seed.update(level=level, pre=np.load(DATA / f"hop{level}_pre.npy", mmap_mode="r"),
                     full=np.load(DATA / f"hop{level}_full.npy", mmap_mode="r"),
                     tool=np.load(DATA / f"hop{level}_tool.npy", mmap_mode="r"),
                     tools=json.loads((DATA / f"hop{level}_tools.json").read_text()))
    return _seed


def match_pos(raw, pre, full):
    """[(row in raw, seed index)] for rows of raw (n, 20) that are seeds."""
    import numpy as np
    if not len(pre) or not len(raw):
        return []
    rp = np.ascontiguousarray(raw[:, :8]).view(">u8").ravel().astype(np.uint64)
    pos = np.searchsorted(pre, rp)
    pos[pos == len(pre)] = 0
    out = []
    for i in np.nonzero(pre[pos] == rp)[0].tolist():
        j = int(pos[i])
        while j < len(pre) and pre[j] == rp[i]:
            if (full[j] == raw[i]).all():
                out.append((i, j))
                break
            j += 1
    return out


def hop_stripe(path, k, level):
    """-> (rows in stripe, [(row, (dir, name, type, target, perms, kind, tool))])"""
    import pyarrow as pa
    import pyarrow.compute as pc
    s = _seeds(level)
    raw_f, pf, mf = _file(path)
    dirs = pf.read_stripe(k, columns=["directory_id"]).column(0)
    uniq = pc.unique(dirs)                       # ~90k dirs per 2.5M-row stripe
    hits = match_pos(raw20(uniq), s["pre"], s["full"])
    if not hits:
        return len(dirs), []
    tool_of = {uniq[i].as_py(): s["tools"][int(s["tool"][j])] for i, j in hits}
    idx = pc.indices_nonzero(pc.is_in(dirs, value_set=pa.array(list(tool_of), pa.string()))).to_pylist()
    tp = pf.read_stripe(k, columns=["type", "perms"])
    types, perms = tp.column(0), tp.column(1)
    names = mf.var_strings(k, 2, idx)
    tgt = mf.fixed_strings(k, 4, 40, idx)
    kind = f"hop{level}"
    out = []
    for r in idx:
        d = dirs[r].as_py()
        out.append((r, (bytes.fromhex(d), names[r], types[r].as_py(), bytes.fromhex(tgt[r].decode()),
                        perms[r].as_py(), kind, tool_of[d])))
    return len(dirs), out


def _job(args):
    seq, fid, path, k, level = args
    err = None
    for attempt in range(5):
        try:
            n, rows = hop_stripe(path, k, level)
            return seq, fid, k, n, rows, None
        except Exception as e:
            _open.pop(path, None)
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
    return seq, fid, k, 0, [], err


def cmd_run(a):
    con = db()
    paths = dict(con.execute("SELECT fid, path FROM files"))
    order = "DESC" if a.reverse else "ASC"
    todo = con.execute(f"SELECT seq, fid, stripe FROM work WHERE level=? AND done_at IS NULL AND seq >= ? AND seq < ? "
                       f"ORDER BY seq {order}", (a.level, a.from_seq, a.to_seq)).fetchall()
    nseed = con.execute("SELECT COUNT(*) FROM seeds WHERE level=?", (a.level,)).fetchone()[0]
    print(f"hop level {a.level}: {nseed:,} seeds, {len(todo):,} stripes to do, {a.workers} workers", flush=True)
    stop, t0, n, kept, last_commit = DATA / "STOP_HOP", time.time(), 0, 0, time.time()
    with ProcessPoolExecutor(a.workers, max_tasks_per_child=50) as ex:
        pending, it = set(), iter(todo)

        def submit():
            for seq, fid, k in it:
                pending.add(ex.submit(_job, (seq, fid, paths[fid], k, a.level)))
                return
        for _ in range(a.workers * 2):
            submit()
        while pending:
            fu = next(as_completed(pending))
            pending.discard(fu)
            seq, fid, k, nrows, rows, err = fu.result()
            if err:
                con.execute("INSERT INTO errors VALUES(?,?,?,?)", (a.level, seq, err, time.time()))
            elif con.execute("SELECT done_at FROM work WHERE level=? AND seq=?", (a.level, seq)).fetchone()[0] is None:
                con.executemany("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                [e + (fid, k, r, RULES_VERSION) for r, e in rows])
                con.execute("UPDATE work SET rows=?, kept=?, done_at=? WHERE level=? AND seq=?",
                            (nrows, len(rows), time.time(), a.level, seq))
                n, kept = n + 1, kept + len(rows)
            if time.time() - last_commit > 5:
                con.commit()
                last_commit = time.time()
            if n and n % 1000 == 0:
                rate = n / (time.time() - t0) * 3600
                print(f"{time.strftime('%H:%M:%S')} {n:,}/{len(todo):,} stripes, {kept:,} entries, {rate:,.0f}/h, "
                      f"ETA {(len(todo) - n) / max(rate, 1):.1f} h", flush=True)
            if not stop.exists():
                submit()
    con.commit()
    print(f"hop level {a.level} {'stopped' if stop.exists() else 'finished'}: {n:,} stripes, {kept:,} entries",
          flush=True)


def cmd_merge(a):
    con = db()
    con.execute("ATTACH ? AS o", (a.other,))
    con.execute("CREATE TEMP TABLE m AS SELECT w.level, w.seq, w.fid, w.stripe FROM o.work w JOIN main.work x "
                "ON x.level=w.level AND x.seq=w.seq WHERE w.done_at IS NOT NULL AND x.done_at IS NULL")
    n = con.execute("SELECT COUNT(*) FROM m").fetchone()[0]
    con.execute("INSERT INTO main.entries SELECT e.* FROM o.entries e JOIN m ON m.fid=e.fid AND m.stripe=e.stripe "
                "AND e.kind='hop' || m.level")
    con.execute("UPDATE main.work SET (rows, kept, done_at) = (SELECT rows, kept, done_at FROM o.work w "
                "WHERE w.level=main.work.level AND w.seq=main.work.seq) "
                "WHERE (level, seq) IN (SELECT level, seq FROM m)")
    con.commit()
    print(f"merged {n:,} stripes from {a.other}")


def cmd_status(a):
    con = db()
    for lv, tot, done, kept in con.execute("SELECT level, COUNT(*), COUNT(done_at), SUM(kept) FROM work GROUP BY 1"):
        print(f"level {lv}: {done:,}/{tot:,} stripes, {kept or 0:,} entries")
    print("errors:", con.execute("SELECT COUNT(*) FROM errors").fetchone()[0])


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seeds")
    s.add_argument("src", nargs="?")
    s.add_argument("--level", type=int, default=1)
    r = sub.add_parser("run")
    r.add_argument("--level", type=int, default=1)
    r.add_argument("--workers", type=int, default=24)
    r.add_argument("--reverse", action="store_true")
    r.add_argument("--from-seq", type=int, default=0)
    r.add_argument("--to-seq", type=int, default=1 << 62)
    m = sub.add_parser("merge")
    m.add_argument("other")
    sub.add_parser("status")
    a = p.parse_args()
    {"seeds": cmd_seeds, "run": cmd_run, "merge": cmd_merge, "status": cmd_status}[a.cmd](a)
