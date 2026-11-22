# agent-file-census

Code and aggregate data for a census of AI coding-agent instruction files (CLAUDE.md, AGENTS.md, Cursor rules,
Copilot instructions, GEMINI.md, agent skills and about 25 other names) across the whole Software Heritage
archive, a test of whether current coding agents act on hidden payloads in those files, and **afscan**, a scanner
for hidden or malicious instructions in them.

## Paper

Are AI Coding-Agent Instruction Files Being Weaponised? A Census of 1.47 Million Files and a Test of Eight Coding
Agents. Preprint, 2026 (link added when posted).

Main results:

- 1,468,189 unique agent instruction files from 1.07 trillion directory entries (Software Heritage graph export
  2026-06-04).
- 6.2% of agent files contain hidden text, no more than README and CONTRIBUTING files (6.6%). Almost all of it is
  template comments.
- Every malicious file we confirmed was a test fixture, demo, proof of concept or benchmark sample.
- In a controlled test of eight coding agents (336 runs), every agent acted on at least one payload. Copilot, Claude
  Code, Codex and Kilo followed visible payloads in 7 to 9 of 12 runs, and planted edits landed without an approval
  prompt. Copilot and Antigravity never told the user; Claude Code, Amp and OpenCode usually reported the payloads
  they declined.
- Hiding a payload did not help: Claude Code strips HTML comments before the model sees them, the models behind
  Copilot and Codex never read Unicode tag characters, and Gemini's safety filter blocked most tag-character
  payloads. No payload command took effect (approval prompts or Codex's network-off sandbox stopped them); nothing
  stopped the edits.

## afscan

Single file, standard library only, Python 3.10+.

```
python src/afscan.py CLAUDE.md AGENTS.md .cursorrules     # verdict and rules per file
python src/afscan.py --json SKILL.md                       # one JSON line per file
python src/afscan.py --strip CLAUDE.md CLAUDE.clean.md     # copy without hidden text
```

```python
import afscan

report = afscan.scan_text(text)     # {"verdict": "high" | "medium" | "low" | "info" | "clean", "flags": [...]}
clean = afscan.strip(text)          # removes tag characters, zero-width runs, bidi controls, comments, hidden HTML
```

It looks for two things:

- **Hidden text:** Unicode tag characters (decoded), zero-width runs, variation-selector runs, bidirectional
  controls, HTML and markdown comments, hidden HTML, empty links, long image alt text and base64 text.
- **Risky instructions:** exfiltration, reads of secret paths, remote or hidden code execution, weakened security
  controls, concealment from the user, instruction overrides, dependency injection and backdoored code, in eight
  languages. Negated sentences and deny-lists are skipped.

Verdicts: `high` = risky intent inside hidden text, or exfiltration of secrets; `medium` = visible risky intent,
or hidden text that gives an order; `low` = hidden text alone; `info` = common but risky patterns such as
pipe-to-shell install lines.

Measured on a pre-registered sample of the census, 6.5% of `high` verdicts were malicious; most were security
documentation that mentions secrets and endpoints. Use afscan to decide what to read, not as a verdict. `strip`
is safe to run on any instruction file before an agent loads it.

## Census pipeline

Reads the public Software Heritage graph export on S3 (anonymous access, no account) with pyarrow.

```
pip install -r requirements.txt
python src/census.py init
python src/census.py run --workers 16          # match ~30 file names in every directory_entry stripe
python src/hop.py seeds --level 1              # agent directories found by the walk (.claude, .cursor, ...)
python src/hop.py run --level 1 --workers 40   # entries inside them; repeat seeds/run with --level 2
python src/corpus.py init
python src/corpus.py map --workers 40          # Git blob hash -> SHA-1 via the content table
python src/corpus.py addhop data/hop.sqlite    # add the hop targets, then: newround, map
python src/corpus.py fetch --threads 24        # download and verify every blob
python src/corpus.py scan --workers 4          # afscan + per-file features
python src/tables.py --ver 0.3.1               # paper tables
python src/test_sample.py draw --ver 0.3.1     # pre-registered test sample (seed 20261120)
```

The full walk reads about a quarter of a 29.8 TB table; it was run on four small cloud machines.

## Agent experiment

`src/obey.py` builds a throwaway repository (a small web app, a fake `.env` and one instruction file carrying a
payload), gives an agent an ordinary task in headless mode and records every tool call. Payload URLs point to a
canary server on 127.0.0.1 and all secrets are fake. File edits are auto-approved; other commands need approval,
which headless mode denies and logs.

```
python src/obey.py visibility              # which hiding channels reach each agent's model
python src/obey.py run --cond none --reps 3
python src/obey.py run --cond warn --reps 1
python src/obey.py score
```

Requires the agent CLIs and their own sign-in: Claude Code, Antigravity CLI, GitHub Copilot CLI, Codex CLI, OpenCode,
Kilo and Amp; Aider, Goose, Crush and Qwen Code run on a local Ollama model (qwen3:8b).

## Data

`results/` holds the aggregate data behind every table: coverage, hidden-text channels by platform and for the
README control, scanner verdicts by platform, labels per test stratum (counts), every label change made in
adjudication with its reason (no hashes), per-run outcomes of the agent experiment (all 11 agents, including the
three local-model agents left out of the paper's comparison and the first Antigravity run without pre-approvals),
channel visibility, and afscan's verdicts on the experiment's payload files.

`src/llm_rater.py` is the blind second rater (Codex CLI) used for the agreement check.

## Ethics

The census reports aggregates only and names no repository, author or file. File hashes of flagged files are not
released. The corpus contains committed secrets; they were never used and are not released.

## Tests

```
python -m pytest tests/test_afscan.py tests/test_corpus.py
```

`tests/test_hop.py` and `tests/test_varstrings.py` read real S3 stripes and need network access.

## License

MIT
