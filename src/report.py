"""Write LIVE.md + data/live/*.csv from the census DB (and findings, when present).

    python src/report.py
"""
from __future__ import annotations

import csv
import math
import pathlib
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from census import DB, SYMLINK  # noqa: E402

DATA = ROOT / "data"
LIVE = DATA / "live"
TOTAL_ROWS = 1_066_000_000_000  # refined from files table when available
CSV_ROWS = 100_000              # newest rows per kind in the live CSVs


def wilson(k, n, z=1.96):
    if not n:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), c + h


def main():
    LIVE.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=120)
    tot_rows = con.execute("SELECT SUM(nrows) FROM files").fetchone()[0] or TOTAL_ROWS
    tot, done, rows = con.execute("SELECT COUNT(*), COUNT(done_at), COALESCE(SUM(rows),0) FROM work").fetchone()
    t0, t1 = con.execute("SELECT MIN(done_at), MAX(done_at) FROM work").fetchone()
    rate = done / ((t1 - t0) / 3600) if t0 and t1 and t1 > t0 else 0
    scale = tot_rows / rows if rows else 0
    lines = [f"# Agent-file census: live ({time.strftime('%Y-%m-%d %H:%M')}, {DB.name})", "",
             f"- Stripes: {done:,}/{tot:,} ({done / max(tot, 1):.2%}), {rows:,} of {tot_rows:,} directory entries",
             f"- Rate: {rate:,.0f} stripes/h; full pass ETA at this rate: "
             f"{(tot - done) / rate / 24:,.1f} days" if rate else "- Rate: n/a", "",
             "## Agent files by platform", "",
             "Counts are directory entries across all archived tree versions (one file kept over 50 commits "
             "that touch its directory = 50 entries), not files. Unique blobs = distinct contents. "
             "Symlinks are counted apart (their blob is the link path). est. = entries scaled to the archive.", "",
             "| kind | platform | entries (tree versions) | unique blobs | symlink entries | unique dirs | "
             "est. entries (archive) |",
             "|---|---|---:|---:|---:|---:|---:|"]
    q = ("SELECT kind, tool, SUM(perms!=?), COUNT(DISTINCT CASE WHEN perms!=? THEN target END), SUM(perms=?), "
         "COUNT(DISTINCT dir) FROM entries WHERE kind IN ('agent','config') OR kind LIKE 'hop%' "
         "GROUP BY 1,2 ORDER BY 1, 3 DESC")
    for kind, tool, n, ub, nl, ud in con.execute(q, (SYMLINK, SYMLINK, SYMLINK)):
        est = f"{n * scale:,.0f}" if not kind.startswith("hop") else "n/a"
        lines.append(f"| {kind} | {tool} | {n:,} | {ub:,} | {nl:,} | {ud:,} | {est} |")
    have_f = con.execute("SELECT 1 FROM sqlite_master WHERE name='findings'").fetchone()
    if have_f:
        lines += ["", "## Detector findings (unique blobs scanned; symlinks excluded)", "",
                  "| platform | scanned | flagged | rate | 95% CI |", "|---|---:|---:|---:|---|"]
        for tool, n, k in con.execute("SELECT tool, COUNT(*), SUM(flag>0) FROM findings "
                                      "WHERE COALESCE(verdict,'')!='symlink' GROUP BY 1 ORDER BY 2 DESC"):
            lo, hi = wilson(k or 0, n)
            lines.append(f"| {tool} | {n:,} | {k or 0:,} | {(k or 0) / n:.3%} | {lo:.3%}–{hi:.3%} |")
        links = con.execute("SELECT tool, COUNT(*), SUM(rules='link_outside'), SUM(rules='link_up') FROM findings "
                            "WHERE verdict='symlink' GROUP BY 1 ORDER BY 2 DESC").fetchall()
        if links:
            lines += ["", "## Symlink blobs", "", "| platform | links | outside repo | climbs with ../ |",
                      "|---|---:|---:|---:|"]
            lines += [f"| {t} | {n:,} | {o or 0:,} | {u or 0:,} |" for t, n, o, u in links]
    (ROOT / "LIVE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for kind in ("agent", "config", "base"):
        with open(LIVE / f"hits_{kind}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["dir", "name", "type", "target", "perms", "tool", "fid", "stripe", "row"])
            for d, nm, ty, tg, pm, tool, fid, k, r in con.execute(
                    "SELECT dir, name, type, target, perms, tool, fid, stripe, row FROM entries WHERE kind=? "
                    "ORDER BY rowid DESC LIMIT ?", (kind, CSV_ROWS)):
                w.writerow([d.hex(), nm.decode("utf-8", "replace"), ty, tg.hex(), pm, tool, fid, k, r])
    con.close()


if __name__ == "__main__":
    main()
