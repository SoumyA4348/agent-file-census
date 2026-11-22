"""afscan: find hidden or suspicious instructions in AI-agent files (CLAUDE.md, AGENTS.md,
.cursorrules, copilot-instructions.md, .mdc rules, SKILL.md, MCP/settings JSON, ...).

    python src/afscan.py FILE [FILE ...]        # one summary line per file
    python src/afscan.py --json FILE            # JSON lines
    python src/afscan.py --strip IN [OUT]       # copy without hidden text (comments, tag chars, ...)

Layer 1 (deterministic channels): Unicode tag smuggling, bidi controls, zero-width runs,
variation-selector smuggling, mixed-script words, HTML comments / hidden HTML, invisible
markdown, base64 blobs, exfil endpoints, pipe-to-shell, secret paths, auto-run config.
Layer 2 (intent lexicon, multilingual): override, concealment, exfiltration, execution,
security weakening, AI-addressing. Hidden text is decoded and run through Layer 2 too.

Severity: high = intent inside a hidden channel, or exfiltration of secrets;
medium = visible malicious intent or hidden channel with an imperative; low = hidden
channel alone; info = risky-but-common patterns (pipe-to-shell, auto-run config).
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import sys
import unicodedata

__version__ = "0.3.1"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}

# ---------------- Layer 1: hidden channels ----------------
TAG = re.compile("[\U000E0000-\U000E007F]+")
BIDI = re.compile("[‪-‮⁦-⁩؜]")
ZW = re.compile("[​‌‍⁠⁡⁢⁣⁤᠎﻿]")
ZW_RUN = re.compile("[​‌‍⁠-⁤᠎﻿]{4,}")
VS_RUN = re.compile("[︀-️\U000E0100-\U000E01EF]{4,}")
EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_HTML = re.compile(
    r"<(\w+)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
    r"|opacity\s*:\s*0(?:\.0+)?\b|color\s*:\s*(?:#fff(?:fff)?|white|transparent))[^\"']*[\"'][^>]*>(.*?)</\1>",
    re.S | re.I)
HIDDEN_ATTR = re.compile(r"<(\w+)[^>]*\bhidden\b[^>]*>(.*?)</\1>", re.S | re.I)
MD_COMMENT = re.compile(r"^\s*\[(?://|comment|_)\]:\s*#\s*[\(\"'](.+?)[\)\"']\s*$", re.M | re.I)
EMPTY_LINK = re.compile(r"(?<!!)\[\s*\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)")
IMG_ALT = re.compile(r"!\[([^\]]{40,})\]\(")
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
URL = re.compile(r"https?://[^\s)\"'<>\]]+", re.I)
EXFIL_HOST = re.compile(
    r"(?:webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator|oast\.|"
    r"interact\.sh|interactsh|canarytokens|beeceptor|hookbin|pastebin\.com/raw|transfer\.sh|"
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|trycloudflare\.com|serveo\.net|"
    r"localhost\.run|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.I)
PIPE_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b"
    r"[^\n|]{0,200}\|\s*iex\b|\bpowershell(?:\.exe)?\s+[^\n]{0,40}-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
    r"bash\s+-c\s+[\"']?\$\((?:curl|wget)|/dev/tcp/\d|\bnc\s+(?:-\w+\s+)*-e\s", re.I)
SECRET_PATH = re.compile(
    r"(?:~|\$HOME|%USERPROFILE%)?/?\.ssh/(?:id_\w+|authorized_keys|config)|\bid_(?:rsa|ed25519|ecdsa)\b|"
    r"\.aws/credentials|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker/config\.json|/etc/(?:passwd|shadow)|"
    r"\bkeychain\b|\bAWS_SECRET_ACCESS_KEY\b|\b(?:GITHUB|GH|OPENAI|ANTHROPIC|NPM)_(?:API_)?(?:TOKEN|KEY)\b|"
    r"(?<![\w/])\.env(?:\.local|\.production)?\b", re.I)

IP_HOST = re.compile(r"^https?://(\d{1,3}(?:\.\d{1,3}){3})(?:[:/]|$)", re.I)


def exfil_url(u: str) -> bool:
    if not EXFIL_HOST.search(u):
        return False
    m = IP_HOST.match(u)
    if m:
        try:
            return ipaddress.ip_address(m.group(1)).is_global
        except ValueError:
            return False
    host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0]
    if re.fullmatch(r"[\w.-]*?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", host):
        return False   # an IP inside a longer host name (version strings etc.)
    return True


# auto-run / permission config (JSON-ish text)
AUTORUN = [
    ("vscode_folder_open", re.compile(r"\"runOn\"\s*:\s*\"folderOpen\"")),
    ("claude_hooks", re.compile(r"\"hooks\"\s*:\s*\{[^{}]{0,400}\"(?:PreToolUse|PostToolUse|SessionStart|"
                                r"UserPromptSubmit|Stop|Notification|SubagentStop|PreCompact)\"", re.S)),
    ("allow_all_bash", re.compile(r"\"Bash(?:\(\*\)|\(\*\*\))?\"\s*[,\]]|\"Bash\(\s*\*\s*\)\"")),
    ("skip_permissions", re.compile(r"dangerously[-_]skip[-_]permissions|bypassPermissions|\"yolo\"\s*:\s*true|"
                                    r"autoApprove\"\s*:\s*\[\s*\"\*\"|\"alwaysAllow\"\s*:\s*\[", re.I)),
    ("mcp_unpinned_npx", re.compile(r"\"command\"\s*:\s*\"(?:npx|uvx|bunx|pnpm\s+dlx)\"[^}]{0,300}?"
                                    r"\"(?:-y|--yes)?\"?,?\s*\"(?:@?[\w.-]+/)?[\w.-]+(?:@latest)?\"", re.S)),
    ("devcontainer_cmd", re.compile(r"\"(?:postCreateCommand|postStartCommand|postAttachCommand|"
                                    r"initializeCommand|onCreateCommand|updateContentCommand)\"\s*:")),
    ("auto_approve_tools", re.compile(r"\"chat\.tools\.autoApprove\"\s*:\s*true|\"enableAllProjectMcpServers\"\s*:\s*true"
                                      r"|\"task\.allowAutomaticTasks\"\s*:\s*\"on\"", re.I)),
]

# ---------------- Layer 2: intent lexicon ----------------
_AI = r"(?:ai|llm|agent|assistant|model|claude|copilot|cursor|gemini|chatgpt|gpt|codex|bot)"
LEX = [
    ("override", "override",
     r"\b(?:ignore|disregard|forget|override|bypass)\b(?: all| any)?(?: of)?(?: the| your)?(?: previous| prior| above|"
     r" preceding| earlier| other| original| system| safety| developer)? (?:instructions?|prompts?|directions?|"
     r"guidelines?|rules?|guardrails?|policies)\b"),
    ("new_instructions", "override", r"\b(?:new|updated|real|actual|true) (?:system )?instructions?\s*(?:are|:)"),
    ("conceal_user", "conceal",
     r"\b(?:do not|don't|never|must not|avoid)\b (?:tell|inform|mention|notify|reveal|show|disclose|alert|report|"
     r"let)\b(?: this| it| that| these| them)?(?: to)? (?:the |any )?(?:user|human|developer|operator|reviewer|owner|anyone)"),
    ("conceal_silent", "conceal",
     r"\bwithout (?:telling|informing|notifying|alerting|asking|showing|letting) (?:the )?(?:user|human|developer|anyone)\b"
     r".{0,60}\b(?:send|upload|post|run|execute|install|curl|download|delete|push|exfiltrat)"
     r"|\b(?:secretly|covertly|silently|quietly|stealthily)\s+(?:[\w-]+\s+){0,2}?(?:send|upload|post|exfiltrat|run|"
     r"execute|install|curl|download|add|insert|modify|delete|copy)"),
    ("conceal_output", "conceal",
     r"\b(?:do not|don't|never)\b (?:log|print|echo|output|display|include|mention) (?:this|these|the following)"
     r"(?: instructions?| commands?| steps?| text)? (?:in|to) (?:the )?(?:output|response|logs?|chat|summary|commit)"),
    ("exfil_secrets", "exfiltrate",
     r"\b(?:send|upload|post|transmit|exfiltrate|forward|copy|leak|share|report|pipe|beacon)\w*\b.{0,80}"
     r"\b(?:secrets?|credentials?|tokens?|api[ _-]?keys?|private keys?|ssh keys?|passwords?|env(?:ironment)? "
     r"(?:vars?|variables?)|\.env|cookies?|session)\b.{0,80}\b(?:to|at|via|using)\b.{0,40}(?:https?://|webhook|"
     r"server|endpoint|url|curl|wget|fetch)"),
    ("read_secrets", "exfiltrate",
     r"\b(?:read|cat|print|collect|gather|dump|grab|extract|include)\b.{0,30}\b(?:~/\.ssh|id_rsa|\.aws/credentials|"
     r"(?<!\w)\.env\b|all (?:secrets|credentials|tokens|env(?:ironment)? variables))"),
    ("exec_hidden", "execute",
     r"\b(?:always|first|before (?:anything|any task|responding|starting)|immediately|automatically)\b.{0,40}"
     r"\b(?:run|execute|eval)\b.{0,60}(?:curl|wget|iwr|powershell|bash -c|sh -c|base64 -d|\| ?sh)"),
    ("weaken_security", "weaken",
     r"\b(?:disable|turn off|skip|bypass|remove)\b.{0,20}\b(?:ssl|tls|certificate|cert) (?:verification|validation|checks?)"
     r"|\b(?:disable|turn off|bypass)\b.{0,20}\b(?:security|sandbox|antivirus|firewall|2fa|mfa|auth(?:entication)?)\b"
     r"|\bchmod\s+(?:-R\s+)?777\b|\bset\s+-x\b.{0,20}secret|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
    ("add_dependency", "inject",
     r"\b(?:always|must)\b (?:install|add|include|require)\b (?:the )?(?:package|library|module|dependency)\b"
     r"\s+[`\"']?@?[a-z0-9][\w.@/-]*"),
    ("backdoor_code", "inject",
     r"\b(?:insert|add|inject|include|hide)\b.{0,30}\b(?:backdoor|reverse shell|keylogger|crypto ?miner|telemetry beacon|"
     r"hidden (?:user|admin|account|endpoint))\b"),
    ("ai_address", "address",
     rf"\bif you are an? {_AI}\b|\b(?:note|instructions?|message|attention) (?:to|for) (?:the |any |all )?{_AI}s?\b"
     rf"|\b(?:dear|hey|hello) {_AI}\b"),
    # multilingual (ZH, JA, KO, RU, ES, PT, HI)
    ("override_i18n", "override",
     r"(?:忽略|无视|無視|忘记|忘記|무시).{0,8}(?:指令|指示|提示|命令|规则|規則|지시)|"
     r"игнорир\w*.{0,20}(?:инструкц|указани|правил)|ignora(?:r)?\b.{0,20}\b(?:instrucciones|instruções|reglas|regras)|"
     r"(?:निर्देशों|निर्देश)\s*(?:को)?\s*(?:अनदेखा|नज़रअंदाज़)"),
    ("conceal_i18n", "conceal",
     r"(?:不要|别|勿|不得)(?:告诉|通知|告知|透露)(?:用户|使用者)|ユーザーに(?:伝えない|知らせない|言わない)|"
     r"사용자에게\s*(?:알리지|말하지)|не (?:говори|сообщай)\w* пользовател|no (?:le )?(?:digas|informes|menciones) al usuario|"
     r"não (?:conte|informe|diga) ao usuário|उपयोगकर्ता को (?:न|मत) (?:बताएं|बताओ)"),
    ("exfil_i18n", "exfiltrate",
     # v0.3: imperative forms only (feature names like 기밀 전송 / "enviar tokens máximos" are not orders)
     r"(?:把|将).{0,20}(?:密钥|令牌|凭证|密码|秘密).{0,20}(?:发送|上传|发给)|(?:请|立即|然后)(?:发送|上传).{0,20}"
     r"(?:密钥|令牌|凭证|密码|秘密)|(?:キー|トークン|パスワード|秘密鍵|認証情報).{0,60}(?:送信して|送って|アップロードして)|"
     r"(?:토큰|비밀번호|키|자격 ?증명).{0,60}(?:전송하(?:세요|십시오|라)|보내(?:세요|십시오|라))|"
     r"\b(?:отправь|отправьте|загрузи|загрузите|перешли|перешлите)\b.{0,30}(?:ключ|токен|парол|секрет)|"
     r"\b(?:envía|envíe|envie|sube|suba|manda|mande)\b.{0,30}\b(?:claves?|tokens?|contraseñas?|senhas?|secretos?|"
     r"segredos?|credenciales|credenciais)"),
]
LEX = [(i, intent, re.compile(p, re.I | re.S)) for i, intent, p in LEX]
NO_VERIFY = re.compile(r"--no-verify\b")
STRONG = {"override", "conceal", "exfiltrate", "execute", "weaken", "inject"}
IMPERATIVE = re.compile(r"\b(?:you must|always|never|do not|don't|ignore|run|execute|send|upload|install|delete|"
                        r"you are|your task|from now on|instead)\b", re.I)


def norm(t: str) -> str:
    t = unicodedata.normalize("NFKC", t)
    t = ZW.sub("", t)
    return re.sub(r"\s+", " ", t)


def lex(text: str):
    t = norm(text)
    out = []
    for rid, intent, rx in LEX:
        m = rx.search(t)
        if m:
            out.append((rid, intent, m.group(0)[:160]))
    return out


# v0.3: exfil rules on visible text must fire inside ONE sentence/line, not across a whole file
SEG_RULES = {"exfil_secrets", "read_secrets", "exfil_i18n"}
SEG_SPLIT = re.compile(r"\n|(?<=[.!?。！？])\s+")
NEGATION = re.compile(
    r"\b(?:never|not|no|don't|dont|doesn't|won't|cannot|can't|shouldn't|avoid|refuse|prevent|block|forbid\w*|"
    r"prohibit\w*|deny|disallow\w*|without)\b|❌|🚫|"
    r"不要|不得|不会|禁止|勿|别|絶対に|しない|しません|禁止|않|금지|\bне\b|\bнельзя\b|\bnunca\b|\bnão\b", re.I)
PERM_LIST = re.compile(r"\"(?:deny|ask)\"\s*:\s*\[[^\]]*\]", re.S)
LIST_ITEM = re.compile(r"^(?:[-*+•]|\d+[.)])\s")
ENDPOINT = re.compile(r"https?://|\bwebhook\b|\bendpoint\b|\bcurl\b|\bwget\b", re.I)
# an order to the agent, not a description ("the frontend sends the token…", "Postmark…", "uploads")
EXFIL_VERBS = {"send", "upload", "post", "transmit", "exfiltrate", "forward", "copy", "leak", "share", "report",
               "pipe", "beacon"}
_ADV = (r"then|also|please|now|always|first|finally|next|immediately|silently|quietly|secretly|covertly|and|"
        r"you (?:must|should|need to|will|have to)|make sure to|be sure to|remember to")
IMPER_PREFIX = re.compile(rf"^[\W\d]*(?:(?:{_ADV})\W+)*$|(?:[,;:]|\b(?:{_ADV}))\s*$", re.I)


def imperative(s: str, m) -> bool:
    verb = re.match(r"\w+", m.group(0)).group(0).lower()
    return verb in EXFIL_VERBS and bool(IMPER_PREFIX.search(s[:m.start()]))


def lex_segments(text: str):
    """Sentence-scoped exfil rules: skip negated sentences and permission deny/ask lists."""
    out, seen, neg_ctx = [], set(), False
    for seg in SEG_SPLIT.split(PERM_LIST.sub(" ", text)):
        s = norm(seg).strip()
        item = bool(LIST_ITEM.match(s))
        if s.startswith("#") or s.endswith(":"):   # "### Never do these" / "Red flags:" governs the list below
            neg_ctx = bool(NEGATION.search(s))
        elif s and not item:
            neg_ctx = False
        if len(s) < 8:
            continue
        for rid, intent, rx in LEX:
            if rid not in SEG_RULES or rid in seen:
                continue
            m = rx.search(s)
            if not m or NEGATION.search(s[:m.start() + 12]) or (item and neg_ctx):   # "never send…"
                continue
            if rid == "exfil_secrets" and not imperative(s, m):
                continue
            if rid == "exfil_i18n" and not ENDPOINT.search(s):
                continue   # locale strings ("enviar tokens máximos") have no target
            seen.add(rid)
            out.append((rid, intent, m.group(0)[:160]))
    return out


def defang(s: str, n=200) -> str:
    s = s.replace("http", "hxxp").replace("\n", " ")
    s = "".join(c if c.isprintable() else f"<U+{ord(c):04X}>" for c in s)
    return s[:n]


def mixed_script_words(text: str, limit=5):
    """Latin words with Cyrillic/Greek letters inside (homoglyph tricks)."""
    hits = []
    for w in re.findall(r"\b\w{4,}\b", text):
        scripts = set()
        for c in w:
            if c.isascii():
                if c.isalpha():
                    scripts.add("L")
            else:
                n = unicodedata.name(c, "")
                if n.startswith("CYRILLIC"):
                    scripts.add("C")
                elif n.startswith("GREEK"):
                    scripts.add("G")
                elif c.isalpha():
                    scripts.add("O")
        if "L" in scripts and scripts & {"C", "G"} and "O" not in scripts:
            hits.append(w)
            if len(hits) >= limit:
                break
    return hits


def hidden_channels(text: str) -> list:
    """[(channel, body)] for text a rendered markdown view does not show (decoded where possible)."""
    hidden = []
    # Unicode tag smuggling: decode to ASCII
    for m in TAG.finditer(text):
        dec = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E)
        if len(dec) >= 3:
            hidden.append(("unicode_tags", dec))
    # zero-width runs: try binary decoding (ZWSP/ZWNJ as bits) as well
    for m in ZW_RUN.finditer(text):
        run = m.group(0)
        if len(run) >= 8 and set(run) <= {"​", "‌", "‍", "⁠", "﻿"}:
            bits = "".join("0" if c == "​" else "1" for c in run if c in "​‌")
            dec = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))
            dec = dec if dec.isprintable() and len(dec) >= 3 else ""
            hidden.append(("zero_width_run", dec or f"[{len(run)} zero-width chars]"))
        elif not EMOJI.search(text[max(0, m.start() - 2):m.end() + 2]):
            hidden.append(("zero_width_run", f"[{len(run)} zero-width chars]"))
    for m in VS_RUN.finditer(text):
        hidden.append(("variation_selector_run", f"[{len(m.group(0))} variation selectors]"))
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if len(body) >= 12:
            hidden.append(("html_comment", body))
    for rx, rule in ((HIDDEN_HTML, "hidden_html"), (HIDDEN_ATTR, "hidden_html")):
        for m in rx.finditer(text):
            hidden.append((rule, re.sub(r"<[^>]+>", " ", m.group(2))))
    for m in MD_COMMENT.finditer(text):
        hidden.append(("md_comment", m.group(1)))
    for m in EMPTY_LINK.finditer(text):
        hidden.append(("empty_link", (m.group(2) or "") + " " + m.group(1)))
    for m in IMG_ALT.finditer(text):
        hidden.append(("image_alt", m.group(1)))
    for m in B64.finditer(text):
        s = m.group(0)
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() or c in "\n\t" for c in dec) / max(len(dec), 1) > 0.95 and re.search(r"[a-z]{3,} [a-z]{2,}", dec):
            hidden.append(("base64_text", dec))
    return hidden


def scan_text(text: str, name: str = "") -> dict:
    flags = []

    def flag(rule, layer, sev, snippet="", intent=None):
        flags.append(dict(rule=rule, layer=layer, sev=sev, intent=intent, snippet=defang(snippet)))

    hidden = hidden_channels(text)
    n_bidi = len(BIDI.findall(text))
    if n_bidi:
        flag("bidi_control", 1, "low", f"{n_bidi} bidi control chars")
    mw = mixed_script_words(text)
    if mw:
        flag("mixed_script", 1, "low", " ".join(mw))

    # hidden text: classify by its intent
    for rule, body in hidden:
        hits = lex(body)
        strong = [h for h in hits if h[1] in STRONG]
        ext = [u for u in URL.findall(body) if exfil_url(u)] + PIPE_SHELL.findall(body) + SECRET_PATH.findall(body)
        if strong or (hits and ext):
            flag(rule, 1, "high", body, intent=",".join(sorted({h[1] for h in hits})))
        elif rule in ("unicode_tags", "variation_selector_run"):
            flag(rule, 1, "medium" if IMPERATIVE.search(body) or hits else "low", body)
        elif rule == "zero_width_run" and not body.startswith("["):
            flag(rule, 1, "medium", body)
        elif rule == "zero_width_run":
            flag(rule, 1, "low", body)
        elif hits or ext:
            flag(rule, 1, "medium", body, intent=",".join(sorted({h[1] for h in hits})) or "endpoint")
        elif rule in ("hidden_html", "base64_text") and IMPERATIVE.search(body):
            flag(rule, 1, "low", body)
        # plain HTML/markdown comments without intent are normal templating: not flagged

    # visible text
    vis = HTML_COMMENT.sub(" ", text)
    for rid, intent, snip in [h for h in lex(vis) if h[0] not in SEG_RULES] + lex_segments(vis):
        if intent in ("exfiltrate",):   # v0.3: reading a secret path alone is not exfiltration
            flag(rid, 2, "medium" if rid == "read_secrets" else "high", snip, intent)
        elif intent in STRONG:
            flag(rid, 2, "medium", snip, intent)
        elif intent == "address":
            flag(rid, 2, "info", snip, intent)
    for u in URL.findall(text):
        if exfil_url(u):
            flag("exfil_endpoint", 1, "medium", u)
    m = NO_VERIFY.search(text)
    if m:
        flag("skip_hooks", 2, "info", text[max(0, m.start() - 60):m.end() + 20])
    for m in PIPE_SHELL.finditer(text):
        flag("pipe_to_shell", 1, "info", text[max(0, m.start() - 40):m.end() + 40])
        break
    for rule, rx in AUTORUN:
        m = rx.search(text)
        if m:
            flag(rule, 1, "info", text[max(0, m.start() - 20):m.end() + 60])
    sp = SECRET_PATH.findall(text)
    if sp and any(f["intent"] == "exfiltrate" and f["sev"] == "high" for f in flags):
        flag("secret_path_with_exfil", 2, "high", " ".join(sorted(set(sp)))[:120])
    # combine: two medium signals of different families -> high
    meds = {f["rule"] for f in flags if f["sev"] == "medium"}
    top = max((SEV[f["sev"]] for f in flags), default=-1)
    if len(meds) >= 2 and top == SEV["medium"] and any(f["layer"] == 1 for f in flags if f["sev"] == "medium"):
        flags.append(dict(rule="combined", layer=2, sev="high", intent=None, snippet=",".join(sorted(meds))))
        top = SEV["high"]
    verdict = {-1: "clean", 0: "info", 1: "low", 2: "medium", 3: "high"}[top]
    return dict(name=name, version=__version__, verdict=verdict, flags=flags)


def decode(data: bytes) -> tuple[str, str]:
    """-> (text, encoding). v0.3.1: UTF-16 only with a BOM or many NUL bytes; v0.3.0 tried UTF-16 on any
    non-UTF-8 file, which turns Latin-1 text into CJK-looking garbage that no rule can match."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        pass
    if data.count(b"\x00") > len(data) // 4:
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1"), "latin-1"


def scan_bytes(data: bytes, name: str = "") -> dict:
    return scan_text(decode(data)[0], name)


AI_ADDR = next(rx for rid, _, rx in LEX if rid == "ai_address")


def features(text: str) -> dict:
    """Per-file channel counts, independent of verdicts: prevalence tables and the README/CONTRIBUTING
    control come from these. hidden_instr = hidden bodies with imperative or AI-addressed wording."""
    hid = hidden_channels(text)
    by = {}
    for rule, body in hid:
        by[rule] = by.get(rule, 0) + 1
    comments = [m.group(1) for m in HTML_COMMENT.finditer(text)]
    urls = URL.findall(text)
    return {
        "chars": len(text), "lines": text.count("\n") + 1,
        "tag_chars": len(re.findall("[\U000E0000-\U000E007F]", text)),
        "zw_chars": len(ZW.findall(text)), "zw_runs": len(ZW_RUN.findall(text)),
        "vs_runs": len(VS_RUN.findall(text)), "bidi": len(BIDI.findall(text)),
        "html_comments": len(comments), "html_comment_chars": sum(len(c) for c in comments),
        "hidden": by, "hidden_instr": sum(1 for _, b in hid if IMPERATIVE.search(b) or AI_ADDR.search(norm(b))),
        "urls": len(urls), "exfil_urls": sum(exfil_url(u) for u in urls),
        "pipe_shell": len(PIPE_SHELL.findall(text)), "secret_paths": len(SECRET_PATH.findall(text)),
        "mixed_script": len(mixed_script_words(text)),
    }


def strip(text: str) -> str:
    """Remove what a rendered view hides from people but a model still reads: Unicode tag characters, bidi
    controls, zero-width and variation-selector runs, HTML and markdown comments, and hidden HTML elements.
    Visible text is left alone, so a visible malicious instruction survives (scan for that)."""
    for rx in (TAG, BIDI, VS_RUN, ZW_RUN, HTML_COMMENT, MD_COMMENT, HIDDEN_HTML, HIDDEN_ATTR):
        text = rx.sub("", text)
    return text


def main(argv):
    if argv[:1] == ["--strip"]:   # afscan.py --strip IN [OUT]: write IN without hidden text to OUT or stdout
        with open(argv[1], "rb") as f:
            out = strip(decode(f.read())[0])
        if len(argv) > 2:
            with open(argv[2], "w", encoding="utf-8", newline="") as f:
                f.write(out)
        else:
            sys.stdout.write(out)
        return
    as_json = "--json" in argv
    for p in [a for a in argv if a != "--json"]:
        with open(p, "rb") as f:
            r = scan_bytes(f.read(), p)
        if as_json:
            print(json.dumps(r, ensure_ascii=False))
        else:
            rules = ",".join(sorted({f["rule"] for f in r["flags"] if f["sev"] != "info"})) or "-"
            print(f"{r['verdict']:7} {rules:40} {p}")


if __name__ == "__main__":
    main(sys.argv[1:])
