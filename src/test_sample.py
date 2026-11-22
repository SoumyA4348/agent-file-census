"""TEST set for the precision/recall claims (protocol pre-registered in notes/study_design.md, 2026-11-19).

    python -I src/test_sample.py draw --ver 0.3.1          # strata below, seed 20261120 -> notes/test_<ver>.csv + sheets
    python -I src/test_sample.py score LABELS.csv [RATER2.csv]   # precision per stratum (Wilson CI) + Cohen's kappa

Strata (agent instruction files only: kinds agent, hop1, hop2; symlinks excluded):
  high      all high flags if <= 200, else 200 random
  med:<rule> 50 random per rule that produced a medium flag
  hidden    200 random files with >= 1 hidden channel and no flag >= medium (misses inside hidden-channel files)
  random    400 random files below medium, stratified by platform (recall upper bound)
A blob drawn by an earlier stratum is not drawn again. Labels: malicious | suspicious | benign_hidden |
not_instruction | fp. The rater-2 sheet is a blind, stratified 120-item subset (same seed).
Run `draw` only after the detector version used for reporting is frozen; never tune rules on these items.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import html
import json
import math
import pathlib
import random
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import afscan  # noqa: E402
from corpus import DB, Corpus  # noqa: E402
from label_sheet import contexts  # noqa: E402

SEED = 20261120
LABELS = ["malicious", "suspicious", "benign_hidden", "not_instruction", "fp"]
KINDS = ("agent", "hop1", "hop2")


def wilson(k, n, z=1.96):
    if not n:
        return 0.0, 0.0
    p, d = k / n, 1 + z * z / n
    c, h = (p + z * z / (2 * n)) / d, z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def draw(a):
    con = sqlite3.connect(f"file:{pathlib.Path(a.db).resolve().as_posix()}?mode=ro", uri=True)
    rng = random.Random(SEED)
    rows = con.execute(
        f"SELECT x.sha1_git, t.tool, x.verdict, x.rules, x.flags, ft.data FROM findings x "
        f"JOIN targets t ON t.target=x.sha1_git LEFT JOIN features ft ON ft.sha1_git=x.sha1_git AND ft.ver=x.ver "
        f"WHERE x.ver=? AND t.link=0 AND t.kind IN ({','.join('?' * len(KINDS))}) ORDER BY x.sha1_git",
        (a.ver, *KINDS)).fetchall()
    taken, picks = set(), []

    def take(stratum, pool, n):
        pool = [r for r in pool if r[0] not in taken]
        for r in (pool if len(pool) <= n else rng.sample(pool, n)):
            taken.add(r[0])
            picks.append((stratum, r))
    take("high", [r for r in rows if r[2] == "high"], 200)
    med_rules = sorted({f["rule"] for r in rows if r[2] in ("medium", "high")
                        for f in json.loads(r[4] or "[]") if f["sev"] == "medium"})
    for rule in med_rules:
        take(f"med:{rule}", [r for r in rows if r[2] == "medium" and rule in (r[3] or "").split(",")], 50)

    def hidden(r):
        f = json.loads(r[5] or "{}")
        return bool(f.get("hidden")) or f.get("tag_chars", 0) or f.get("zw_runs", 0) or f.get("bidi", 0)
    below = [r for r in rows if r[2] in ("clean", "info", "low")]
    take("hidden", [r for r in below if hidden(r)], 200)
    by_tool = {}
    for r in below:
        by_tool.setdefault(r[1], []).append(r)
    for tool, pool in sorted(by_tool.items()):   # proportional, at least 5 per platform
        take("random", pool, max(5, round(400 * len(pool) / max(len(below), 1))))
    out = ROOT / "notes" / f"test_{a.ver}.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stratum", "sha1_git", "tool", "verdict", "rules"])
        for s, r in picks:
            w.writerow([s, r[0].hex(), r[1], r[2], r[3]])
    corpus = Corpus(ro=True)
    items = [item(s, r, corpus) for s, r in picks]
    sheet(items, f"TEST set afscan {a.ver} ({len(items)})", f"afc-test-{a.ver}", ROOT / "notes" / f"label_test_{a.ver}.html")
    by_s = {}
    for it in items:
        by_s.setdefault(it["stratum"].split(":")[0], []).append(it)
    sub = []
    for s, its in sorted(by_s.items()):   # blind rater-2 subset, stratified, 120 items
        sub += random.Random(SEED + 1).sample(its, min(len(its), max(1, round(120 * len(its) / len(items)))))
    for it in sub:
        it["stratum"] = ""   # blind: rater 2 sees no stratum
    sheet(sub, f"Rater 2 blind ({len(sub)})", f"afc-rater2-{a.ver}", ROOT / "notes" / f"label_rater2_{a.ver}.html")
    print(f"{len(items)} TEST items ({ {s: len(v) for s, v in by_s.items()} }) -> {out}; rater-2 subset {len(sub)}")


def item(stratum, r, corpus):
    sg, tool, verdict, rules, flags, _ = r
    gz = corpus.get(sg)
    text = afscan.decode(gzip.decompress(gz))[0] if gz else ""
    hid = [{"rule": c, "body": afscan.defang(b, 600)} for c, b in afscan.hidden_channels(text)][:20]
    return {"id": sg.hex(), "stratum": stratum, "tool": tool, "verdict": verdict, "rules": rules or "",
            "length": len(text), "hits": contexts(text, json.loads(flags or "[]")), "hidden": hid,
            "head": text[:1500]}


def sheet(items, title, key, out):
    page = TEMPLATE.replace("__TITLE__", html.escape(title)).replace("__KEY__", key) \
                   .replace("__LABELS__", json.dumps(LABELS)).replace("__DATA__", json.dumps(items).replace("</", "<\\/"))
    out.write_text(page, encoding="utf-8")


def score(a):
    def load(p):
        with open(p, encoding="utf-8") as fh:
            return {r["sha1_git"]: r for r in csv.DictReader(fh) if r.get("label")}
    plan = {r["sha1_git"]: r for r in csv.DictReader(open(ROOT / "notes" / f"test_{a.ver}.csv", encoding="utf-8"))}
    lab = load(a.labels)
    print(f"labelled {len(lab)}/{len(plan)}")
    strata = {}
    for sg, p in plan.items():
        if sg in lab:
            strata.setdefault(p["stratum"].split(":")[0] if not p["stratum"].startswith("med:") else p["stratum"],
                              []).append(lab[sg]["label"])
    print(f"{'stratum':28} {'n':>4} {'malicious':>10} {'+suspicious':>12}  {'hidden instr (any)':>18}")
    for s, ls in sorted(strata.items()):
        n, m = len(ls), ls.count("malicious")
        ms, hi = m + ls.count("suspicious"), m + ls.count("suspicious") + ls.count("benign_hidden")
        lo, up = wilson(m, n)
        print(f"{s:28} {n:4} {m:4} [{lo:.1%}-{up:.1%}] {ms:5}  {hi:5}")
    if a.rater2:
        r2 = load(a.rater2)
        both = [sg for sg in r2 if sg in lab]
        po = sum(lab[s]["label"] == r2[s]["label"] for s in both) / max(len(both), 1)
        pe = sum((sum(lab[s]["label"] == c for s in both) / len(both)) * (sum(r2[s]["label"] == c for s in both) / len(both))
                 for c in LABELS) if both else 0
        print(f"Cohen's kappa on {len(both)} items: {(po - pe) / (1 - pe) if pe < 1 else 1:.3f} (agreement {po:.1%})")
        m1 = [lab[s]["label"] == "malicious" for s in both]
        m2 = [r2[s]["label"] == "malicious" for s in both]
        if both:
            bo = sum(a == b for a, b in zip(m1, m2)) / len(both)
            p1, p2 = sum(m1) / len(both), sum(m2) / len(both)
            be = p1 * p2 + (1 - p1) * (1 - p2)
            print(f"malicious vs not: kappa {(bo - be) / (1 - be) if be < 1 else 1:.3f} (agreement {bo:.1%}, "
                  f"rater1 {sum(m1)}, rater2 {sum(m2)})")
        for s in both:
            if lab[s]["label"] != r2[s]["label"]:
                print(f"  disagree {s[:12]} {lab[s]['label']} vs {r2[s]['label']}")


TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title><style>
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8a8f98;--card:#171a21;--line:#2a2f3a;--hl:#ffd54a33}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;z-index:2}
main{max-width:980px;margin:0 auto;padding:16px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.meta{color:var(--mut);font-size:13px;margin-bottom:8px;word-break:break-all}.sec{border-top:1px solid var(--line);padding:10px 0}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0d10;border-radius:8px;padding:10px;max-height:320px;overflow:auto;font:12px/1.45 ui-monospace,monospace}
button{border:1px solid var(--line);background:#20242d;color:var(--fg);border-radius:999px;padding:6px 14px;cursor:pointer;font:inherit}
button.on{outline:2px solid #ffd54a}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
input{flex:1;min-width:200px;background:#0b0d10;border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:6px 10px}.mut{color:var(--mut)}
</style></head><body><header><b>__TITLE__</b><span id="prog" class="mut"></span><button id="prev">◀ k</button><button id="next">j ▶</button>
<button id="skip">next unlabelled (n)</button><button id="exp">export CSV</button></header>
<main><div class="card" id="card"></div><p class="mut">Keys 1-5 = label, j/k move, n next unlabelled. malicious: tries to exfiltrate,
run untrusted code, weaken security, hide things from the user, or inject a dependency/backdoor · suspicious: risky, intent unclear ·
benign_hidden: hidden text that steers the agent harmlessly · not_instruction: hidden/flagged text that is not an instruction
(template comment, TODO, licence) · fp: nothing hidden or risky. Labels save in this browser.</p></main><script>
const D=__DATA__,KEY="__KEY__",LB=__LABELS__;let L={};try{L=JSON.parse(localStorage.getItem(KEY)||"{}")}catch(e){}let i=0;
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(L))}catch(e){}};const esc=s=>String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
function draw(){const d=D[i],l=L[d.id]||{},n=Object.values(L).filter(x=>x.label).length;document.getElementById("prog").textContent=`${i+1}/${D.length} · labelled ${n}`;
const c=document.getElementById("card");c.innerHTML=`<div class="meta"><b>${esc(d.tool)}</b> · ${d.length} chars · ${d.stratum?"stratum "+esc(d.stratum)+" · ":""}verdict ${esc(d.verdict)} · rules ${esc(d.rules)} · ${d.id}</div>`+
(d.hidden.length?`<div class="sec"><b>Hidden channels (decoded, defanged)</b>${d.hidden.map(h=>`<div class="mut">${esc(h.rule)}</div><pre>${esc(h.body)}</pre>`).join("")}</div>`:"")+
d.hits.map(h=>`<div class="sec"><b>${esc(h.rule)}</b> <span class="mut">${esc(h.sev)} · ${esc(h.snippet)}</span>${h.found?`<pre>${esc(h.ctx)}</pre>`:""}</div>`).join("")+
`<div class="sec"><b>File start</b><pre>${esc(d.head)}</pre></div><div class="row">${LB.map((b,k)=>`<button class="${l.label==b?"on":""}" data-l="${b}">${k+1} ${b}</button>`).join("")}
<input id="note" placeholder="note" value="${esc(l.note||"")}"></div>`;c.querySelectorAll("[data-l]").forEach(b=>b.onclick=()=>setL(b.dataset.l));
document.getElementById("note").oninput=e=>{L[d.id]={...(L[d.id]||{}),note:e.target.value};save()}}
function setL(v){L[D[i].id]={...(L[D[i].id]||{}),label:v};save();if(i<D.length-1)i++;draw()}function go(k){i=Math.max(0,Math.min(D.length-1,k));draw();scrollTo(0,0)}
function nextUn(){for(let k=1;k<=D.length;k++){const j=(i+k)%D.length;if(!(L[D[j].id]||{}).label)return go(j)}}
document.getElementById("prev").onclick=()=>go(i-1);document.getElementById("next").onclick=()=>go(i+1);document.getElementById("skip").onclick=nextUn;
document.getElementById("exp").onclick=()=>{const q=s=>'"'+String(s??"").replace(/"/g,'""')+'"';const rows=[["sha1_git","tool","label","note"],...D.map(d=>[d.id,d.tool,(L[d.id]||{}).label,(L[d.id]||{}).note])];
const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(r=>r.map(q).join(",")).join("\n")],{type:"text/csv"}));a.download=KEY+".csv";a.click()};
addEventListener("keydown",e=>{if(e.target.tagName=="INPUT")return;const k=+e.key;if(k>=1&&k<=LB.length)return setL(LB[k-1]);({j:()=>go(i+1),k:()=>go(i-1),n:nextUn}[e.key]||(()=>{}))()});draw();
</script></body></html>"""

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draw")
    d.add_argument("--ver", required=True)
    d.add_argument("--db", default=str(DB))
    s = sub.add_parser("score")
    s.add_argument("labels")
    s.add_argument("rater2", nargs="?")
    s.add_argument("--ver", required=True)
    a = p.parse_args()
    {"draw": draw, "score": score}[a.cmd](a)
