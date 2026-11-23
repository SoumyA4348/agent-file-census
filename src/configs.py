"""Pass 6 (configs + secrets), 2026-11-22: exact, parser-based checks on the kept corpus (run on the VM; the corpus
holds real secrets and never leaves it). Writes per-blob flags to data/configs.sqlite (no secret values, ever).

    python -I src/configs.py run [--workers 4]
    python -I src/configs.py report          # aggregate counts (unique blobs) -> stdout

Config checks parse the JSON (comments and trailing commas allowed), so a keyword in prose does not count:
  claude settings  permissions.allow has unrestricted Bash / WebFetch, defaultMode bypassPermissions,
                   enableAllProjectMcpServers, hooks (any / SessionStart)
  vscode settings  task.allowAutomaticTasks "on", chat.tools.autoApprove true
  tasks.json       a task with runOptions.runOn "folderOpen"
  MCP config       servers started with npx/bunx/uvx/pnpm dlx and no pinned version (or @latest); remote URL servers
Secrets (agent instruction files only): access-granting token formats; placeholders skipped; only the type is stored.
"""
import argparse
import gzip
import json
import re
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from corpus import Corpus, db as scan_db   # noqa: E402

OUT = ROOT / "data" / "configs.sqlite"
CFG_TOOLS = {"settings", "claude_settings_local", "mcp", "vscode_tasks", "devcontainer", "copilot_setup"}
AGENT_KINDS = {"agent", "hop1", "hop2"}

_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.S)
_TRAIL = re.compile(r",(\s*[}\]])")


def loads_jsonc(text):
    t = _COMMENT.sub(lambda m: m.group(1) or "", text)
    return json.loads(_TRAIL.sub(r"\1", t))


RUNNERS = {"npx", "bunx", "uvx", "pnpx"}
PIN = re.compile(r"@\d|==\d|@v\d")


def mcp_flags(servers):
    f = set()
    if not isinstance(servers, dict):
        return f
    for s in servers.values():
        if not isinstance(s, dict):
            continue
        if s.get("url") or s.get("serverUrl") or s.get("httpUrl"):
            f.add("mcp_remote")
        cmd = str(s.get("command", "")).strip()
        args = [str(a) for a in s.get("args", []) if isinstance(a, (str, int))] if isinstance(s.get("args"), list) else []
        base = cmd.replace("\\", "/").split("/")[-1].removesuffix(".cmd").removesuffix(".exe")
        if base == "pnpm" and args[:1] == ["dlx"]:
            base, args = "pnpx", args[1:]
        if base in RUNNERS:
            f.add("mcp_runner")
            pkgs = [a for a in args if not a.startswith("-")]
            if base == "uvx" and "--from" in args:
                i = args.index("--from")
                pkgs = [args[i + 1]] if i + 1 < len(args) else pkgs
            pkg = pkgs[0] if pkgs else ""
            if not pkg or not PIN.search(pkg) or pkg.endswith("@latest"):
                f.add("mcp_unpinned")
            if "-y" in args or "--yes" in args:
                f.add("mcp_autoinstall")
    return f


def bash_any(entry):
    e = str(entry).replace(" ", "")
    return e in ("Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)", "Bash(**)")


def config_flags(text):
    try:
        o = loads_jsonc(text)
    except Exception:
        return "unparsed", set()
    if not isinstance(o, dict):
        return "other", set()
    f, cls = set(), "other"
    perms = o.get("permissions")
    hooks = o.get("hooks")
    claude_events = {"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "Stop", "Notification",
                     "SubagentStop", "PreCompact", "SessionEnd"}
    if isinstance(perms, dict) and any(k in perms for k in ("allow", "deny", "ask", "defaultMode")) or (
            isinstance(hooks, dict) and claude_events & set(hooks)) or "enableAllProjectMcpServers" in o:
        cls = "claude_settings"
        allow = perms.get("allow", []) if isinstance(perms, dict) else []
        allow = allow if isinstance(allow, list) else []
        if any(bash_any(a) for a in allow):
            f.add("claude_allow_bash_any")
        if any(str(a).replace(" ", "") in ("WebFetch", "WebFetch(*)") for a in allow):
            f.add("claude_allow_webfetch_any")
        if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
            f.add("claude_bypass")
        if o.get("enableAllProjectMcpServers") is True:
            f.add("claude_mcp_all")
        if isinstance(hooks, dict) and hooks:
            f.add("claude_hooks")
            if "SessionStart" in hooks:
                f.add("claude_hook_sessionstart")
    if "tasks" in o and isinstance(o.get("tasks"), list):
        cls = "vscode_tasks"
        for t in o["tasks"]:
            if isinstance(t, dict) and isinstance(t.get("runOptions"), dict) and t["runOptions"].get("runOn") == "folderOpen":
                f.add("tasks_folder_open")
    if any(isinstance(k, str) and "." in k for k in o) and cls == "other":
        cls = "vscode_settings"
    if o.get("task.allowAutomaticTasks") == "on":
        f.add("vscode_auto_tasks")
    if o.get("chat.tools.autoApprove") is True or o.get("chat.tools.global.autoApprove") is True:
        f.add("vscode_chat_autoapprove")
    servers = o.get("mcpServers", o.get("servers") if isinstance(o.get("servers"), dict) else None)
    if isinstance(servers, dict):
        if cls == "other":
            cls = "mcp"
        f |= mcp_flags(servers)
        f.add("has_mcp_servers")
    return cls, f


PLACEHOLDER = re.compile(r"x{4,}|your|example|placeholder|dummy|test|fake|sample|<|\*{3}|\.\.\.|0{8,}|1234", re.I)
SECRETS = {   # access-granting token formats (no generic "key=" guesses)
    "discord_webhook": re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,20}/[\w-]{60,70}"),
    "slack_webhook": re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,90}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "stripe_live": re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{100,}"),
    "telegram_bot": re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b"),
}


def secret_flags(text):
    f = set()
    for name, rx in SECRETS.items():
        for m in rx.finditer(text):
            if not PLACEHOLDER.search(m.group(0)):
                f.add(name)
                break
    return f


def sk_type(tok):
    """Split the sk- family (the openai_key pattern also matches other vendors' sk- tokens)."""
    for pre, t in (("sk-or-", "openrouter_key"), ("sk-ant-oat", "anthropic_oauth"), ("sk-ant-ort", "anthropic_oauth"),
                   ("sk-ant-", "anthropic_key"), ("sk-proj-", "openai_key"), ("sk-svcacct-", "openai_key")):
        if tok.startswith(pre):
            return t
    return "openai_key" if re.fullmatch(r"sk-[A-Za-z0-9]{48}", tok) or "T3BlbkFJ" in tok else "other_sk_key"


def looks_fake(tok):
    """Low-entropy or sequential bodies (ABCDEF..., 0123456...) and doc examples; real tokens are random."""
    import math
    body = re.sub(r"^(?:https?://\S+/|[a-z]+[-_](?:[a-z]+[-_])?)", "", tok) or tok
    cnt = {c: body.count(c) for c in set(body)}
    ent = -sum(v / len(body) * math.log2(v / len(body)) for v in cnt.values())
    seq = re.search(r"(?i)abcdefgh|bcdefghi|01234567|12345678|qwerty|(.)\1{5}", body)
    return ent < 3.5 or bool(seq) or "EXAMPLE" in tok.upper()


def _secret_chunk(args):
    """-> rows (sha1_git, type, salted hash, fake, masked context) for every token match; never the value."""
    import afscan
    import hashlib
    keys, salt = args
    corpus, out = Corpus(ro=True), []
    for sg in keys:
        gz = corpus.get(sg)
        if gz is None:
            continue
        text, _ = afscan.decode(gzip.decompress(gz))
        for name, rx in SECRETS.items():
            for m in rx.finditer(text[:2_000_000]):
                tok = m.group(0)
                if PLACEHOLDER.search(tok):
                    continue
                typ = sk_type(tok) if name in ("openai_key", "anthropic_key") else name
                a, b = m.span()
                ctx = re.sub(r"\s+", " ", text[max(0, a - 90):a] + f"<{typ}:{len(tok)}>" + text[b:b + 50])
                h = hashlib.sha256(salt + tok.encode()).hexdigest()[:16]
                out.append((sg, typ, h, int(looks_fake(tok)), ctx))
    return out


def cmd_secrets(a):
    """Re-scan only blobs already flagged with a secret: split types, flag fakes, count distinct tokens."""
    import os
    out = sqlite3.connect(OUT)
    salt_f = OUT.with_name("secrets.salt")   # VM-only; hashes are for distinct counts, not lookup
    if not salt_f.exists():
        salt_f.write_bytes(os.urandom(32))
    salt = salt_f.read_bytes()
    keys = [r[0] for r in out.execute("SELECT sha1_git FROM cfg WHERE flags LIKE '%secret_%'")]
    out.execute("DROP TABLE IF EXISTS secret")
    out.execute("CREATE TABLE secret(sha1_git BLOB, type TEXT, h TEXT, fake INT, ctx TEXT)")
    rows = _secret_chunk((keys, salt))
    out.executemany("INSERT INTO secret VALUES(?,?,?,?,?)", rows)
    out.commit()
    print(f"{len(keys):,} flagged blobs -> {len(rows):,} token matches")
    print(f"{'type':18s} {'blobs':>6s} {'distinct':>8s} {'non-fake blobs':>15s} {'non-fake distinct':>18s}")
    for typ, nb, nd, rb, rd in out.execute(
            "SELECT type, COUNT(DISTINCT sha1_git), COUNT(DISTINCT h), COUNT(DISTINCT CASE WHEN fake=0 THEN sha1_git END),"
            " COUNT(DISTINCT CASE WHEN fake=0 THEN h END) FROM secret GROUP BY type ORDER BY 3 DESC"):
        print(f"{typ:18s} {nb:6,} {nd:8,} {rb:15,} {rd:18,}")
    if a.review:   # one masked context per distinct token, for manual real/example labelling
        for typ, h, fake, ctx, n in out.execute(
                "SELECT type, h, MAX(fake), MIN(ctx), COUNT(DISTINCT sha1_git) FROM secret GROUP BY h ORDER BY type"):
            print(f"{h} {typ} fake={fake} blobs={n} | {ctx}")


def _chunk(keys):
    import afscan
    corpus, out = Corpus(ro=True), []
    for sg, tool, kind in keys:
        gz = corpus.get(sg)
        if gz is None:
            continue
        text, _ = afscan.decode(gzip.decompress(gz))
        text = text[:2_000_000]
        cls, f = ("", set())
        if tool in CFG_TOOLS or (kind in ("hop1", "hop2") and text.lstrip()[:1] in ("{", "/")):
            cls, f = config_flags(text)
        if kind in AGENT_KINDS:
            f |= {"secret_" + s for s in secret_flags(text)}
        out.append((sg, tool, kind, cls, ",".join(sorted(f))))
    return out


def cmd_run(a):
    src = scan_db()
    out = sqlite3.connect(OUT)
    out.execute("CREATE TABLE IF NOT EXISTS cfg(sha1_git BLOB PRIMARY KEY, tool TEXT, kind TEXT, cls TEXT, flags TEXT)")
    done = {r[0] for r in out.execute("SELECT sha1_git FROM cfg")}
    keys = [(sg, tool, kind) for sg, tool, kind in src.execute(
        "SELECT f.sha1_git, t.tool, t.kind FROM fetch f JOIN targets t ON t.target=f.sha1_git "
        "WHERE f.state='ok' AND t.link=0 AND (t.tool IN (%s) OR t.kind IN ('agent','hop1','hop2'))"
        % ",".join("?" * len(CFG_TOOLS)), sorted(CFG_TOOLS)) if sg not in done]
    keys.sort()   # corpus shard locality
    print(f"{len(keys):,} blobs to check", flush=True)
    t0, n = time.time(), 0
    with ProcessPoolExecutor(a.workers) as ex:
        futs = [ex.submit(_chunk, keys[i:i + 2000]) for i in range(0, len(keys), 2000)]
        for fu in as_completed(futs):
            rows = fu.result()
            out.executemany("INSERT OR REPLACE INTO cfg VALUES(?,?,?,?,?)", rows)
            out.commit()
            n += len(rows)
            if n % 100000 < 2000:
                print(f"{time.strftime('%H:%M:%S')} {n:,} ({n / (time.time() - t0):,.0f}/s)", flush=True)
    print(f"configs finished: {n:,}", flush=True)


def cmd_report(a):
    import collections
    out = sqlite3.connect(f"file:{OUT.as_posix()}?mode=ro", uri=True)
    den, cnt = collections.Counter(), collections.Counter()
    for tool, kind, cls, flags in out.execute("SELECT tool, kind, cls, flags FROM cfg"):
        g = cls or ("agent:" + tool)
        den[g] += 1
        for fl in filter(None, (flags or "").split(",")):
            cnt[(g, fl)] += 1
    for g in sorted(den, key=lambda x: -den[x]):
        print(f"{g}: {den[g]:,}")
        for (gg, fl), v in sorted(cnt.items(), key=lambda x: -x[1]):
            if gg == g:
                print(f"    {fl:28s} {v:8,}  {100 * v / den[g]:.2f}%")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    r = sp.add_parser("run")
    r.add_argument("--workers", type=int, default=4)
    r.set_defaults(f=cmd_run)
    sp.add_parser("report").set_defaults(f=cmd_report)
    s = sp.add_parser("secrets")
    s.add_argument("--review", action="store_true")
    s.set_defaults(f=cmd_secrets)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
