"""Build a local HTML sheet for hand-labelling detector flags (precision check).

    python -I src/label_sheet.py [--verdict high] [--db data/hits_v2.sqlite] [--out notes/label_high.html]

Each flag shows its rules and the text around every matched snippet. Labels live in the browser
(localStorage) and export to CSV; load that CSV back with `--labels` later if needed.
"""
import argparse, gzip, html, json, re, sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CTX = 500


def contexts(text, flags):
    out = []
    low = text.lower()
    for f in flags:
        snip = f.get("snippet", "")
        probe = re.sub(r"hxxp", "http", snip, flags=re.I).strip()
        i = -1
        for n in (len(probe), 80, 40, 20):
            if n and (i := low.find(probe[:n].lower())) >= 0:
                break
        if i < 0:   # snippets are whitespace-collapsed: match word tokens across any separators
            toks = re.findall(r"\w+", probe)[:8]
            for k in (len(toks), 4, 2, 1):
                if k and (m := re.search(r"\W+".join(map(re.escape, toks[:k])), text, re.I)):
                    i = m.start()
                    break
        ctx = text[max(0, i - CTX): i + len(probe) + CTX] if i >= 0 else ""
        out.append({"rule": f.get("rule"), "sev": f.get("sev"), "snippet": snip, "ctx": ctx, "found": i >= 0})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdict", default="high")
    ap.add_argument("--db", default=str(ROOT / "data/hits_v2.sqlite"))
    ap.add_argument("--out")
    a = ap.parse_args()
    out = Path(a.out or ROOT / f"notes/label_{a.verdict}.html")
    con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    items = []
    for sg, tool, length, rules, flags, ver in con.execute(
            "SELECT sha1_git, tool, length, rules, flags, ver FROM findings WHERE verdict=? ORDER BY tool, sha1_git",
            (a.verdict,)):
        p = ROOT / "data/flagged" / f"{sg.hex()}.txt.gz"
        text = gzip.decompress(p.read_bytes()).decode("utf-8", "replace") if p.exists() else ""
        items.append({"id": sg.hex(), "tool": tool, "length": length, "rules": rules, "ver": ver,
                      "missing": not p.exists(), "hits": contexts(text, json.loads(flags or "[]"))})
    page = TEMPLATE.replace("__TITLE__", html.escape(f"Label {a.verdict} flags ({len(items)})")) \
                   .replace("__KEY__", f"afc-label-{a.verdict}") \
                   .replace("__DATA__", json.dumps(items).replace("</", "<\\/"))
    out.write_text(page, encoding="utf-8")
    print(f"{len(items)} items -> {out}")


TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title><style>
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#8a8f98;--card:#171a21;--line:#2a2f3a;--hl:#ffd54a33;--tp:#e5484d;--sus:#f5a524;--fp:#30a46c}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;gap:12px;flex-wrap:wrap;align-items:center;z-index:2}
main{max-width:980px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.meta{color:var(--mut);font-size:13px;margin-bottom:8px;word-break:break-all}
.hit{border-top:1px solid var(--line);padding:10px 0}.rule{font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0d10;border-radius:8px;padding:10px;max-height:340px;overflow:auto;font:12px/1.45 ui-monospace,monospace}
mark{background:var(--hl);color:inherit}
button{border:1px solid var(--line);background:#20242d;color:var(--fg);border-radius:999px;padding:6px 14px;cursor:pointer;font:inherit}
button.on{outline:2px solid currentColor}.tp{color:var(--tp)}.sus{color:var(--sus)}.fp{color:var(--fp)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
input{flex:1;min-width:200px;background:#0b0d10;border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:6px 10px}
.mut{color:var(--mut)}</style></head><body>
<header><b>__TITLE__</b><span id="prog" class="mut"></span>
<button id="prev">◀ prev (k)</button><button id="next">next (j) ▶</button><button id="skip">next unlabelled (n)</button>
<button id="exp">export CSV</button></header>
<main><div class="card" id="card"></div>
<p class="mut">Keys: <b>1</b> malicious / real attack · <b>2</b> suspicious (risky but likely benign intent) · <b>3</b> false positive · j/k move · n next unlabelled. Labels save in this browser.</p></main>
<script>
const D=__DATA__, KEY="__KEY__";
let L={}; try{L=JSON.parse(localStorage.getItem(KEY)||"{}")}catch(e){}
let i=0;
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(L))}catch(e){}};
const esc=s=>s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
function hl(ctx,snip){const p=snip.replace(/hxxp/ig,"http").slice(0,40).toLowerCase();const k=ctx.toLowerCase().indexOf(p);
 if(k<0)return esc(ctx);return esc(ctx.slice(0,k))+"<mark>"+esc(ctx.slice(k,k+snip.length))+"</mark>"+esc(ctx.slice(k+snip.length))}
function draw(){const d=D[i],l=L[d.id]||{};const n=Object.values(L).filter(x=>x.label).length;
 document.getElementById("prog").textContent=`${i+1}/${D.length} · labelled ${n}`;
 const c=document.getElementById("card");
 c.innerHTML=`<div class="meta"><b>${esc(d.tool||"?")}</b> · ${d.length} bytes · rules: ${esc(d.rules||"")} · sha1_git ${d.id}${d.missing?" · <b>blob file missing</b>":""}</div>`+
 d.hits.map(h=>`<div class="hit"><span class="rule">${esc(h.rule||"")}</span> <span class="mut">${h.sev||""}</span>
 <div class="mut">snippet: ${esc(h.snippet)}</div>${h.found?`<pre>${hl(h.ctx,h.snippet)}</pre>`:`<div class="mut">(snippet not located in text)</div>`}</div>`).join("")+
 `<div class="row"><button class="tp ${l.label=="malicious"?"on":""}" data-l="malicious">1 malicious</button>
 <button class="sus ${l.label=="suspicious"?"on":""}" data-l="suspicious">2 suspicious</button>
 <button class="fp ${l.label=="fp"?"on":""}" data-l="fp">3 false positive</button>
 <input id="note" placeholder="note (optional)" value="${esc(l.note||"")}"></div>`;
 c.querySelectorAll("[data-l]").forEach(b=>b.onclick=()=>setL(b.dataset.l));
 document.getElementById("note").oninput=e=>{L[d.id]={...(L[d.id]||{}),note:e.target.value};save()};}
function setL(v){const d=D[i];L[d.id]={...(L[d.id]||{}),label:v};save();if(i<D.length-1)i++;draw()}
function go(k){i=Math.max(0,Math.min(D.length-1,k));draw();scrollTo(0,0)}
function nextUn(){for(let k=1;k<=D.length;k++){const j=(i+k)%D.length;if(!(L[D[j].id]||{}).label)return go(j)}}
document.getElementById("prev").onclick=()=>go(i-1);document.getElementById("next").onclick=()=>go(i+1);
document.getElementById("skip").onclick=nextUn;
document.getElementById("exp").onclick=()=>{const q=s=>'"'+String(s??"").replace(/"/g,'""')+'"';
 const rows=[["sha1_git","tool","rules","label","note"],...D.map(d=>[d.id,d.tool,d.rules,(L[d.id]||{}).label,(L[d.id]||{}).note])];
 const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([rows.map(r=>r.map(q).join(",")).join("\n")],{type:"text/csv"}));
 a.download=KEY+".csv";a.click()};
addEventListener("keydown",e=>{if(e.target.tagName=="INPUT")return;
 ({"1":()=>setL("malicious"),"2":()=>setL("suspicious"),"3":()=>setL("fp"),j:()=>go(i+1),k:()=>go(i-1),n:nextUn}[e.key]||(()=>{}))()});
draw();
</script></body></html>"""

if __name__ == "__main__":
    main()
