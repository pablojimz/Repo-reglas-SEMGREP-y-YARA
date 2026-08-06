# -*- coding: utf-8 -*-
"""
generate_scored_yara.py

Builds a curated, self-contained YARA rule set from the entries in
yara_scores_output/yara_rule_scores.json: for every scored rule, pulls its
real rule body (strings:/condition:) from the yara_rules/Yara-Rules-Repo
submodule and re-emits it with the risk-scoring fields injected into its
meta: block -- ready to hand to another repo / the `yara` engine directly.

Only the rules present in yara_rule_scores.json are included (plus any
`private rule` helper that a scored rule's condition depends on, so the
output still compiles standalone).

Usage:
    python scripts/generate_scored_yara.py

Run from anywhere; paths are resolved relative to the repo root (this
file's parent directory).
"""
import subprocess, re, json, os, sys, datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBMODULE = os.path.join(REPO_ROOT, "yara_rules", "Yara-Rules-Repo")
SCORES_JSON = os.path.join(REPO_ROOT, "yara_scores_output", "yara_rule_scores.json")
OUT_DIR = os.path.join(REPO_ROOT, "dist", "yara_scored")

# ---------- extraction helpers (mirrors the scorer's parser) ----------

def git_show(path):
    r = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=SUBMODULE, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"git show failed for {path}: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode("utf-8", errors="replace")

def strip_comments(text):
    out = []
    i, n = 0, len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i+1] == '/':
            j = text.find('\n', i)
            if j == -1:
                break
            i = j
            continue
        if c == '/' and i + 1 < n and text[i+1] == '*':
            j = text.find('*/', i + 2)
            if j == -1:
                i = n
                break
            i = j + 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)

RULE_HEADER_RE = re.compile(
    r'(?m)^[ \t]*((?:private\s+|global\s+)*rule)\s+([A-Za-z0-9_]+)\s*(:\s*([^\n{]*))?\s*\{'
)

def split_rules(text):
    matches = list(RULE_HEADER_RE.finditer(text))
    rules = []
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx+1].start() if idx+1 < len(matches) else len(text)
        rules.append({
            "name": m.group(2),
            "private": 'private' in m.group(1),
            "raw": text[start:end].rstrip() + "\n",
        })
    return rules

# ---------- meta injection ----------

def yara_escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')

def inject_score_meta(raw_rule_text, score):
    lines = [
        f'\t\tseverity_score = {score["severity_score"]}',
        f'\t\tconfidence_score = {score["confidence_score"]}',
        f'\t\texploitability_score = {score["exploitability_score"]}',
        f'\t\trisk_score = {score["risk_score"]}',
        f'\t\trisk_justification = "{yara_escape(score["risk_justification"])}"',
    ]
    block = "\n".join(lines) + "\n"
    m = re.search(r'meta:\s*\n', raw_rule_text)
    if m:
        insert_at = m.end()
        return raw_rule_text[:insert_at] + block + raw_rule_text[insert_at:]
    # no meta: section -- add one right after the opening brace of the rule
    brace_idx = raw_rule_text.index('{')
    return raw_rule_text[:brace_idx+1] + "\n\tmeta:\n" + block + raw_rule_text[brace_idx+1:]

# ---------- main ----------

def main():
    with open(SCORES_JSON, "r", encoding="utf-8") as fh:
        scores_doc = json.load(fh)

    by_file = {}
    for s in scores_doc["scores"]:
        by_file.setdefault(s["file"], {})[s["rule_name"]] = s

    os.makedirs(OUT_DIR, exist_ok=True)
    written = []

    for rel_file, scores_by_name in sorted(by_file.items()):
        text = git_show(rel_file)
        clean = strip_comments(text)
        rules = split_rules(clean)

        private_rules = [r for r in rules if r["private"]]
        scored_out = []
        missing = set(scores_by_name.keys())
        for r in rules:
            if r["name"] in scores_by_name:
                scored_out.append(inject_score_meta(r["raw"], scores_by_name[r["name"]]))
                missing.discard(r["name"])
        if missing:
            print(f"WARNING: {rel_file}: rule(s) in scores JSON not found in source: {sorted(missing)}", file=sys.stderr)

        out_path = os.path.join(OUT_DIR, rel_file.replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        header = (
            f"// AUTO-GENERATED by scripts/generate_scored_yara.py -- DO NOT EDIT BY HAND\n"
            f"// Source: yara_rules/Yara-Rules-Repo/{rel_file} (Yara-Rules project, "
            f"https://github.com/Yara-Rules/rules)\n"
            f"// Risk scores per .claude/criterioPuntuacionReglas.md "
            f"(risk = 0.45*severity + 0.30*confidence + 0.25*exploitability)\n"
            f"// Generated: {datetime.datetime.now().isoformat()}\n"
            f"// Contains only the {len(scored_out)} rule(s) present in "
            f"yara_scores_output/yara_rule_scores.json"
            + (f" (+ {len(private_rules)} private helper rule(s) required as dependencies)"
               if private_rules else "")
            + "\n\n"
        )

        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header)
            for pr in private_rules:
                fh.write("// -- structural dependency, not individually scored --\n")
                fh.write(pr["raw"])
                fh.write("\n")
            for block in scored_out:
                fh.write(block)
                fh.write("\n")

        written.append((out_path, len(scored_out)))

    total = sum(n for _, n in written)
    print(f"Wrote {len(written)} file(s), {total} scored rule(s) total, to {OUT_DIR}")
    for path, n in written:
        print(f"  {os.path.relpath(path, REPO_ROOT)}: {n} rule(s)")

if __name__ == "__main__":
    main()
