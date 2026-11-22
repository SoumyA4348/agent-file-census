"""Agent-file census, pass 1: scan Software Heritage directory entries for AI-agent files.

    python src/census.py init                 # list the 128 ORC files + stripe counts, shuffle the work
    python src/census.py run [--workers 16] [--reverse]   # stripes in random order until done or data/STOP
    python src/census.py merge other.sqlite   # fold another machine's DB into this one (laptop + codespace)
    python src/census.py hop --level 1        # pass 3: children of agent dirs (.claude, .kiro, ...); level 2 = grandchildren
    python src/census.py finish               # build indexes once the scan is done
    python src/census.py status

Stripes are processed in a fixed random order, so at any moment the finished part is a uniform
random sample of the archive (estimates come with sampling error, not coverage bias). One machine
runs the order forwards, another with --reverse; they meet in the middle and `merge` joins them.
Per stripe we read only `name` + `directory_id` (+ `type`, `perms`), then range-read `target` for kept rows.
Names match case-insensitively; `name` keeps the original bytes.
  agent   - agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, ...)
  config  - auto-run / agent config candidates (settings.json, tasks.json, .mcp.json, agent dirs, ...)
  sibling - selected entries in a directory that holds an agent file: manifests, lockfiles, licence,
            README, auto-run dotfiles and CI files that hint the host (the rest of the listing is
            dropped: it was 87% of rows in v1 and would not fit on disk)
  base    - manifests + README/CONTRIBUTING in a 1/4096 random subset of directories (control)
  hopN    - pass 3: entries of the child dirs of agent dirs (level 1), and of their rule/command subdirs (level 2)
Symlinks (perms 40960) are kept; the blob is the link path, so reports count them apart from files.
Everything goes to the DB after each stripe (data/hits_v2.sqlite, or $AFC_DB).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
DATA = ROOT / "data"
DB = pathlib.Path(os.environ.get("AFC_DB", DATA / "hits_v2.sqlite"))
EXPORT = "softwareheritage/graph/2026-06-04/orc/directory_entry"
RULES_VERSION = 2
AGG_VERSION = 1
EXT_RE = r"^.+\.(?P<e>[a-z0-9_+-]{1,10})$"
SYMLINK = 0o120000

# lower-case file name -> agent platform
AGENT = {
    "claude.md": "claude", "claude.local.md": "claude",
    "agents.md": "agents_md", "agent.md": "agents_md",
    "gemini.md": "gemini",
    ".cursorrules": "cursor",
    "copilot-instructions.md": "copilot",
    ".windsurfrules": "windsurf",
    ".clinerules": "cline",
    ".roorules": "roo", ".roomodes": "roo",
    ".augment-guidelines": "augment",
    "conventions.md": "aider",
    "warp.md": "warp",
    ".goosehints": "goose",
    "replit.md": "replit",
    "skill.md": "skill",
    "llms.txt": "llms_txt",
}
AGENT_SUFFIX = {".mdc": "cursor", ".instructions.md": "copilot", ".prompt.md": "copilot",
                ".chatmode.md": "copilot"}
CONFIG = {
    "settings.json": "settings", "settings.local.json": "claude_settings_local",
    ".mcp.json": "mcp", "mcp.json": "mcp", "mcp_config.json": "mcp",
    "tasks.json": "vscode_tasks", "devcontainer.json": "devcontainer",
    ".devcontainer.json": "devcontainer",
    "copilot-setup-steps.yml": "copilot_setup", "copilot-setup-steps.yaml": "copilot_setup",
    ".replit": "replit_cfg",
}
# agent / tool directories: counted and their child-dir id kept for pass 3 (hop)
AGENT_DIRS = {".claude", ".cursor", ".windsurf", ".roo", ".kiro", ".junie", ".amazonq",
              ".continue", ".gemini", ".codex", ".clinerules", ".agents", ".opencode",
              ".aider.conf.yml"}   # .github/.vscode/.devcontainer: too common, kept only as siblings
MANIFEST = {"package.json", "requirements.txt", "pyproject.toml", "pipfile", "cargo.toml",
            "go.mod", "gemfile", "composer.json", "pom.xml", "build.gradle", "setup.py",
            "requirements-dev.txt", "environment.yml"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "cargo.lock",
             "go.sum", "gemfile.lock", "composer.lock", "pipfile.lock", "bun.lock", "bun.lockb"}
SIBLING = MANIFEST | LOCKFILES | {
    "readme.md", "contributing.md", "security.md",
    # auto-run, kept as siblings only
    ".envrc", ".yarnrc.yml", ".gitpod.yml", "conftest.py", ".npmrc", ".pre-commit-config.yaml", ".husky",
    # host hints (exact host comes from the origin join later)
    ".github", ".gitlab-ci.yml", ".gitlab", ".gitea", ".forgejo", "bitbucket-pipelines.yml", ".travis.yml",
    ".circleci", "azure-pipelines.yml", ".woodpecker.yml", ".woodpecker", ".drone.yml", "jenkinsfile",
    ".vscode", ".devcontainer", "skills"}
LICENCE_PREFIX = ("licen", "copying", "unlicense")
CONTROL = MANIFEST | {"readme.md", "contributing.md"}
CONTROL_PREFIX = "000"   # 1/4096 of directories
# pass 3 level 2: subdirs of agent dirs that hold rule/command files (.kiro/steering, .claude/commands, ...)
HOP_SUBDIRS = {"steering", "rules", "commands", "agents", "hooks", "prompts", "modes", "workflows",
               "memories", "memory", "instructions", "chatmodes", "specs"}


def s3fs():
    import pyarrow.fs as fs
    return fs.S3FileSystem(anonymous=True, region="us-east-1", request_timeout=60, connect_timeout=20)


def connect(path=None):
    DATA.mkdir(exist_ok=True)
    con = sqlite3.connect(path or DB, timeout=120)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS files(fid INTEGER PRIMARY KEY, path TEXT, nstripes INT, nrows INT);
    CREATE TABLE IF NOT EXISTS work(seq INTEGER PRIMARY KEY, fid INT, stripe INT,
        rows INT, kept INT, secs REAL, done_at REAL, UNIQUE(fid, stripe));
    CREATE TABLE IF NOT EXISTS entries(dir BLOB, name BLOB, type TEXT, target BLOB, perms INT,
        kind TEXT, tool TEXT, fid INT, stripe INT, row INT, v INT);
    CREATE TABLE IF NOT EXISTS targets(target BLOB PRIMARY KEY, tool TEXT, kind TEXT, link INT);
    CREATE TABLE IF NOT EXISTS hwork(level INT, seq INT, fid INT, stripe INT, seeds INT, kept INT,
        done_at REAL, PRIMARY KEY(level, seq));
    CREATE TABLE IF NOT EXISTS errors(fid INT, stripe INT, err TEXT, at REAL);
    CREATE TABLE IF NOT EXISTS aggs(fid INT, stripe INT, v INT, data BLOB, PRIMARY KEY(fid, stripe));
    """)
    return con


def add_rows(con, rows, fid, k, kind=None, tool_by=None):
    """Insert scan output [(row, entry)]; file targets of agent/config/hop rows also go to `targets`
    (the blob queue). kind/tool_by relabel hop rows (tool = the seed dir's tool)."""
    if kind:
        rows = [(r, e[:5] + (kind, tool_by.get(e[0].hex()))) for r, e in rows]
    con.executemany("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    [e + (fid, k, r, RULES_VERSION) for r, e in rows])
    con.executemany("INSERT OR IGNORE INTO targets VALUES(?,?,?,?)",
                    [(e[3], e[6], e[5], int(e[4] == SYMLINK)) for _, e in rows
                     if e[2] == "file" and (e[5] in ("agent", "config") or e[5].startswith("hop"))])
    return len(rows)


def cmd_init(a):
    import pyarrow.fs as fs
    from orcmeta import OrcFile
    s3 = s3fs()
    paths = sorted(i.path for i in s3.get_file_info(fs.FileSelector(EXPORT)) if i.path.endswith(".orc"))
    con = connect()
    if con.execute("SELECT COUNT(*) FROM work").fetchone()[0]:
        sys.exit("already initialised")

    def meta(p):
        o = OrcFile(s3.open_input_file(p))
        return len(o.stripes), sum(s["rows"] for s in o.stripes)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(16) as ex:
        metas = list(ex.map(meta, paths))
    work = []
    for fid, (p, (ns, nr)) in enumerate(zip(paths, metas)):
        con.execute("INSERT INTO files VALUES(?,?,?,?)", (fid, p, ns, nr))
        work += [(fid, k) for k in range(ns)]
    random.Random(20261117).shuffle(work)
    con.executemany("INSERT INTO work(seq, fid, stripe) VALUES(?,?,?)",
                    [(i, f, k) for i, (f, k) in enumerate(work)])
    con.commit()
    print(f"{len(paths)} files, {len(work)} stripes, {sum(m[1] for m in metas):,} rows")


_open: dict[str, object] = {}
_sets: dict = {}


def _vs(name, keys):
    import pyarrow as pa
    if name not in _sets:
        _sets[name] = pa.array(sorted(keys), pa.string())
    return _sets[name]


def _file(path):
    import pyarrow.orc as orc
    from orcmeta import OrcFile
    if path not in _open:
        raw = s3fs().open_input_file(path)
        _open[path] = (raw, orc.ORCFile(raw), OrcFile(raw))
    return _open[path]


def _lower(names):
    import pyarrow as pa
    import pyarrow.compute as pc
    return pc.ascii_lower(names.view(pa.string()))   # byte-wise; no UTF-8 validation


def tool_of(low):
    return AGENT.get(low) or next((t for s, t in AGENT_SUFFIX.items() if low.endswith(s)), None)


def _rows(tb, idx, k, mf, label):
    """Kept rows as [(row, (dir, name, type, target, perms, kind, tool))]; label(i, lower name) -> (kind, tool)."""
    import pyarrow as pa
    take = pa.array(idx, pa.int64())
    sub = tb.take(take)
    dirs, names = sub.column("directory_id").to_pylist(), sub.column("name").to_pylist()
    types, perms = sub.column("type").to_pylist(), sub.column("perms").to_pylist()
    low = _lower(sub.column("name")).to_pylist()
    tgt = mf.fixed_strings(k, 4, 40, idx)
    return [(r, (bytes.fromhex(dirs[i]), names[i], types[i], bytes.fromhex(tgt[r].decode()), perms[i])
             + label(i, low[i])) for i, r in enumerate(idx)]


def stripe_agg(tb, low):
    """Whole-stripe counts, no rows kept: (type, perms) pairs, all file extensions, top file and dir names.
    zstd JSON, one `aggs` row per stripe, so merges stay exact and stripes give error bars.
    Never raises: a failure is stored as {"err": ...} so it cannot fail the census stripe."""
    import pyarrow as pa
    import pyarrow.compute as pc
    import zstandard

    def counts(arr, n=None):
        vc = pc.value_counts(arr)
        vals, cnts = vc.field("values"), vc.field("counts")
        if n:
            top = pc.array_sort_indices(cnts, order="descending")[:n]
            vals, cnts = vals.take(top), cnts.take(top)
        vals = [v.decode("utf-8", "replace") for v in vals.view(pa.binary()).to_pylist()]
        return [[v, c] for v, c in zip(vals, cnts.to_pylist())]
    try:
        typ, perms = tb.column("type"), tb.column("perms")
        tp = pa.table({"t": pc.dictionary_encode(typ), "p": perms}).group_by(["t", "p"]).aggregate([([], "count_all")])
        is_file = pc.and_(pc.equal(typ, "file"), pc.not_equal(perms, SYMLINK))
        files = pc.filter(low, is_file)
        # raw extension = text after the last dot (<= 10 bytes, something before the dot); EXT_RE cleans it at report time
        fb = (pa.chunked_array([c.view(pa.binary()) for c in files.chunks]) if isinstance(files, pa.ChunkedArray)
              else files.view(pa.binary()))
        rv = pc.binary_reverse(fb)
        parts = pc.split_pattern(rv, pattern=".", max_splits=1)
        head = pc.list_element(parts, 0)
        before_dot = pc.subtract(pc.subtract(pc.binary_length(rv), pc.binary_length(head)), 1)
        ok = pc.and_(pc.equal(pc.list_value_length(parts), 2),
                     pc.and_(pc.less_equal(pc.binary_length(head), 10), pc.greater(before_dot, 0)))
        ext = pc.if_else(ok, pc.binary_reverse(head), pa.scalar(b"", pa.binary()))
        data = {"v": AGG_VERSION, "rows": tb.num_rows,
                "tp": [[r["t"], r["p"], r["count_all"]] for r in tp.to_pylist()],
                "ext": counts(ext),
                "fn": counts(files, 300),
                "dn": counts(pc.filter(low, pc.equal(typ, "dir")), 150)}
    except Exception as e:
        data = {"v": AGG_VERSION, "err": f"{type(e).__name__}: {e}"}
    return zstandard.ZstdCompressor(level=6).compress(json.dumps(data, separators=(",", ":")).encode())


def scan_stripe(path: str, k: int, agg_only: bool = False):
    """Return (rows, kept, agg) for one stripe; kept = [(row, entry tuple)], agg = stripe_agg blob."""
    import pyarrow as pa
    import pyarrow.compute as pc
    raw, pf, mf = _file(path)
    tb = pf.read_stripe(k, columns=(["name", "type", "perms"] if agg_only
                                    else ["directory_id", "name", "type", "perms"]))
    low = _lower(tb.column("name"))
    agg = stripe_agg(tb, low)
    if agg_only:
        return tb.num_rows, [], agg
    dirs = tb.column("directory_id")
    agent_m = pc.is_in(low, value_set=_vs("agent", AGENT))
    for suf in AGENT_SUFFIX:
        agent_m = pc.or_(agent_m, pc.ends_with(low, pattern=suf))
    cfg_m = pc.is_in(low, value_set=_vs("cfg", set(CONFIG) | AGENT_DIRS))
    agent_dirs = pc.unique(pc.filter(dirs, agent_m))
    sib_name = pc.is_in(low, value_set=_vs("sib", SIBLING))
    for pre in LICENCE_PREFIX:
        sib_name = pc.or_(sib_name, pc.starts_with(low, pattern=pre))
    sib_m = pc.and_(pc.is_in(dirs, value_set=agent_dirs), sib_name)
    base_m = pc.and_(pc.starts_with(dirs, pattern=CONTROL_PREFIX), pc.is_in(low, value_set=_vs("ctl", CONTROL)))
    keep = pc.or_(pc.or_(agent_m, cfg_m), pc.or_(sib_m, base_m))
    idx = pc.indices_nonzero(keep).to_pylist()
    if not idx:
        return tb.num_rows, [], agg
    take = pa.array(idx, pa.int64())
    am, cm, sm = (m.take(take).to_pylist() for m in (agent_m, cfg_m, sib_m))

    def label(i, nm):
        if am[i]:
            return "agent", tool_of(nm)
        if cm[i]:
            return "config", CONFIG.get(nm) or nm
        return ("sibling", None) if sm[i] else ("base", None)
    return tb.num_rows, _rows(tb, idx, k, mf, label), agg


def hop_stripe(path: str, k: int, seeds_file: str, n_seeds: int):
    """Pass 3: rows whose directory_id is a seed dir. Reads directory_id only unless something matches."""
    import pyarrow as pa
    import pyarrow.compute as pc
    if _sets.get("seeds_n") != n_seeds:
        _sets["seeds"] = pa.array(json.loads(pathlib.Path(seeds_file).read_text()), pa.string())
        _sets["seeds_n"] = n_seeds
    raw, pf, mf = _file(path)
    dirs = pf.read_stripe(k, columns=["directory_id"]).column("directory_id")
    idx = pc.indices_nonzero(pc.is_in(dirs, value_set=_sets["seeds"])).to_pylist()
    if not idx:
        return len(dirs), []
    tb = pf.read_stripe(k, columns=["directory_id", "name", "type", "perms"])
    return tb.num_rows, _rows(tb, idx, k, mf, lambda i, nm: ("hop", None))


def _job(args):
    seq, fid, path, k, agg_only = args
    t0 = time.time()
    for attempt in range(4):
        try:
            rows, kept, agg = scan_stripe(path, k, agg_only)
            return seq, fid, k, rows, kept, agg, time.time() - t0, None
        except Exception as e:  # network hiccup: reopen and retry
            _open.pop(path, None)
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
    return seq, fid, k, 0, [], None, time.time() - t0, err


def cmd_run(a):
    con = connect()
    paths = dict(con.execute("SELECT fid, path FROM files"))
    order = "DESC" if a.reverse else "ASC"
    if a.agg_only:   # backfill aggs for stripes finished before aggs existed
        todo = con.execute(f"SELECT seq, fid, stripe FROM work w WHERE done_at IS NOT NULL AND seq >= ? AND seq < ? "
                           f"AND NOT EXISTS (SELECT 1 FROM aggs g WHERE g.fid=w.fid AND g.stripe=w.stripe) "
                           f"ORDER BY seq {order}", (a.from_seq, a.to_seq)).fetchall()
    else:
        todo = con.execute(f"SELECT seq, fid, stripe FROM work WHERE done_at IS NULL AND seq >= ? AND seq < ? "
                           f"ORDER BY seq {order}", (a.from_seq, a.to_seq)).fetchall()
    if a.limit:
        todo = todo[:a.limit]
    print(f"{len(todo)} stripes to do{' (agg backfill)' if a.agg_only else ''}, {a.workers} workers, "
          f"rules v{RULES_VERSION}, db {DB}", flush=True)
    t_start, n_done, last_report = time.time(), 0, 0.0
    stop = DATA / "STOP"
    with ProcessPoolExecutor(a.workers, max_tasks_per_child=6) as ex:
        pending, it = set(), iter(todo)

        def submit():
            for seq, fid, k in it:
                pending.add(ex.submit(_job, (seq, fid, paths[fid], k, a.agg_only)))
                return True
            return False
        for _ in range(a.workers * 2):
            submit()
        while pending:
            done = next(as_completed(pending))
            pending.discard(done)
            seq, fid, k, rows, kept, agg, secs, err = done.result()
            if err:
                con.execute("INSERT INTO errors VALUES(?,?,?,?)", (fid, k, err, time.time()))
            elif a.agg_only:
                con.execute("INSERT OR IGNORE INTO aggs VALUES(?,?,?,?)", (fid, k, AGG_VERSION, agg))
                n_done += 1
            else:
                con.execute("INSERT OR IGNORE INTO aggs VALUES(?,?,?,?)", (fid, k, AGG_VERSION, agg))
                if con.execute("SELECT done_at FROM work WHERE seq=?", (seq,)).fetchone()[0] is None:
                    add_rows(con, kept, fid, k)   # a merge may have filled this stripe already
                con.execute("UPDATE work SET rows=?, kept=?, secs=?, done_at=? WHERE seq=?",
                            (rows, len(kept), secs, time.time(), seq))
                n_done += 1
            con.commit()
            if n_done % 50 == 0 and n_done:
                el = time.time() - t_start
                print(f"{time.strftime('%H:%M:%S')} {n_done} stripes, {n_done / el * 3600:.0f}/h", flush=True)
            if time.time() - last_report > a.report_every and not a.agg_only:
                last_report = time.time()
                try:
                    import report
                    report.main()
                except Exception as e:
                    print("report failed:", e, flush=True)
            if not stop.exists():
                submit()
    if a.agg_only:   # not "finished": cs_keepalive.py stops the codespace on that word
        print("agg backfill done" if not stop.exists() else "agg backfill halted (data/STOP)", flush=True)
        return
    import report
    report.main()
    print("finished" if not stop.exists() else "stopped (data/STOP)", flush=True)


def cmd_merge(a):
    """Copy finished stripes from another DB (same init) that this one has not done yet."""
    con = connect()
    con.execute("ATTACH ? AS o", (a.other,))
    con.execute("CREATE TEMP TABLE m AS SELECT w.seq, w.fid, w.stripe FROM o.work w JOIN main.work x "
                "ON x.seq=w.seq WHERE w.done_at IS NOT NULL AND x.done_at IS NULL")
    n = con.execute("SELECT COUNT(*) FROM m").fetchone()[0]
    con.execute("INSERT INTO main.entries SELECT e.* FROM o.entries e JOIN m ON m.fid=e.fid AND m.stripe=e.stripe "
                "WHERE e.kind NOT LIKE 'hop%'")
    con.execute("UPDATE main.work SET (rows, kept, secs, done_at) = (SELECT rows, kept, secs, done_at FROM o.work w "
                "WHERE w.seq=main.work.seq) WHERE seq IN (SELECT seq FROM m)")
    con.execute("INSERT OR IGNORE INTO main.targets SELECT * FROM o.targets")
    if con.execute("SELECT 1 FROM o.sqlite_master WHERE name='aggs'").fetchone():
        con.execute("INSERT OR IGNORE INTO main.aggs SELECT * FROM o.aggs")   # keyed by stripe: exact
    con.commit()
    print(f"merged {n} stripes from {a.other}")


def _hjob(args):
    seq, path, k, sf, ns = args
    for attempt in range(4):
        try:
            return hop_stripe(path, k, sf, ns)[1], None
        except Exception as e:
            _open.pop(path, None)
            err = f"{type(e).__name__}: {e}"
            time.sleep(5 * (attempt + 1))
    return [], err


def cmd_hop(a):
    """Pass 3 at one level: every stripe, directory_id only, looking for the seed dirs."""
    con = connect()
    if a.level == 1:
        seeds = con.execute("SELECT DISTINCT target, tool FROM entries WHERE type='dir' "
                            "AND kind IN ('agent','config')").fetchall()
    else:
        seeds = [(t, tool) for t, nm, tool in con.execute(
            "SELECT DISTINCT target, name, tool FROM entries WHERE type='dir' AND kind=?", (f"hop{a.level - 1}",))
            if nm.decode("latin-1").lower() in HOP_SUBDIRS]
    tool_by = {t.hex(): tool for t, tool in seeds}
    sf = DATA / f"hop{a.level}_seeds.json"
    sf.write_text(json.dumps(sorted(tool_by)))
    paths = dict(con.execute("SELECT fid, path FROM files"))
    if not con.execute("SELECT 1 FROM hwork WHERE level=?", (a.level,)).fetchone():
        con.execute("INSERT INTO hwork(level, seq, fid, stripe) SELECT ?, seq, fid, stripe FROM work", (a.level,))
        con.commit()
    todo = con.execute("SELECT seq, fid, stripe FROM hwork WHERE level=? AND done_at IS NULL ORDER BY seq",
                       (a.level,)).fetchall()
    print(f"hop level {a.level}: {len(tool_by):,} seed dirs, {len(todo)} stripes", flush=True)
    stop, t0, n = DATA / "STOP_HOP", time.time(), 0
    with ProcessPoolExecutor(a.workers) as ex:
        futs, it = {}, iter(todo)

        def submit():
            for seq, fid, k in it:
                futs[ex.submit(_hjob, (seq, paths[fid], k, str(sf), len(tool_by)))] = (seq, fid, k)
                return
        for _ in range(a.workers * 2):
            submit()
        while futs:
            fu = next(as_completed(futs))
            seq, fid, k = futs.pop(fu)
            kept, err = fu.result()
            if err:
                con.execute("INSERT INTO errors VALUES(?,?,?,?)", (fid, k, "hop " + err, time.time()))
            else:
                nk = add_rows(con, kept, fid, k, kind=f"hop{a.level}", tool_by=tool_by)
                con.execute("UPDATE hwork SET seeds=?, kept=?, done_at=? WHERE level=? AND seq=?",
                            (len(tool_by), nk, time.time(), a.level, seq))
                n += 1
            con.commit()
            if n and n % 200 == 0:
                print(f"{time.strftime('%H:%M:%S')} hop{a.level} {n} stripes, {n / (time.time() - t0) * 3600:.0f}/h",
                      flush=True)
            if not stop.exists():
                submit()
    print("hop finished" if not stop.exists() else "hop stopped (data/STOP_HOP)", flush=True)


def cmd_finish(a):
    con = connect()
    con.executescript("""
    CREATE INDEX IF NOT EXISTS e_kind ON entries(kind, tool);
    CREATE INDEX IF NOT EXISTS e_dir ON entries(dir);
    CREATE INDEX IF NOT EXISTS e_target ON entries(target);
    """)
    print("indexes built")


def cmd_status(a):
    con = connect()
    tot, done, rows = con.execute("SELECT COUNT(*), COUNT(done_at), SUM(rows) FROM work").fetchone()
    print(f"{done}/{tot} stripes ({done / tot:.2%}), {rows or 0:,} rows")
    for kind, tool, n in con.execute("SELECT kind, tool, COUNT(*) FROM entries WHERE kind IN ('agent','config') "
                                     "GROUP BY 1,2 ORDER BY 3 DESC"):
        print(f"  {kind:7} {tool:28} {n:,}")
    print("errors:", con.execute("SELECT COUNT(*) FROM errors").fetchone()[0])


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    r = sub.add_parser("run")
    r.add_argument("--workers", type=int, default=16)
    r.add_argument("--limit", type=int, default=0)
    r.add_argument("--report-every", type=int, default=1800)
    r.add_argument("--reverse", action="store_true", help="walk the random order from the end")
    r.add_argument("--from-seq", type=int, default=0, help="only stripes with seq >= this (split work across machines)")
    r.add_argument("--to-seq", type=int, default=1 << 62, help="only stripes with seq < this")
    r.add_argument("--agg-only", action="store_true", help="only backfill aggs for finished stripes")
    m = sub.add_parser("merge")
    m.add_argument("other")
    h = sub.add_parser("hop")
    h.add_argument("--level", type=int, default=1)
    h.add_argument("--workers", type=int, default=16)
    sub.add_parser("finish")
    sub.add_parser("status")
    a = p.parse_args()
    {"init": cmd_init, "run": cmd_run, "merge": cmd_merge, "hop": cmd_hop, "finish": cmd_finish,
     "status": cmd_status}[a.cmd](a)
