# -*- coding: utf-8 -*-
"""
classify_semgrep_finding_type.py

Adds `finding_type` (and, for genuinely ambiguous rules, `needs_review` /
`needs_review_reason`) to `metadata:` in every already-scored Semgrep rule
file under a given root (rules/semgrep/custom/ or rules/semgrep/third-party/),
right after the existing `risk_justification:` line -- same insertion point
convention as the YARA side (see scripts/generate_scored_yara.py /
scripts/backfill_finding_type_yara.py).

Classification schema: .claude/criterioPuntuacionReglas.md
Background/decisions: .claude/separacion_vul_cog_malicoso.md

Default is `vulnerability` for every scored rule: the overwhelming majority
of this ruleset targets flaws in otherwise-legitimate application code
(SQLi, XSS, insecure crypto, hardcoded secrets, insecure deserialization,
SSRF, path traversal, etc). A small curated MALICIOUS_IDS set overrides the
default for the handful of rules whose matched pattern *is itself* code with
no reasonable non-offensive use (verified by manually reading every rule
under custom/, id-by-id, plus a targeted content search across third-party/
for reverse-shell / download-and-execute / curl-pipe-to-shell-style literal
patterns -- see PR description for the exact search used). Borderline cases
that were checked and kept as `vulnerability` on purpose, with reasoning:

  - bash-curl-pipe-to-shell: risk_justification explicitly frames it as a
    build/install-script pattern ("tipico en scripts de build/instalacion"),
    not a malware indicator -- unlike powershell-download-and-execute, whose
    own justification calls it "indicador clasico de malware droppers".
    curl|sh is a common (if risky) real-world install idiom (Docker, rustup,
    nvm...), so this stays a legitimate-code risk, not a malicious payload.
  - powershell-invoke-expression-dynamic, php-eval-dynamic-code, curl-eval:
    flag a dangerous *capability* in application code (every eval/IEX call,
    including safe literals, by the rule's own design), not a payload that
    was already planted.

If a rule is added to MALICIOUS_IDS in the future, or a rule's nature turns
out to be genuinely dual-use, add NEEDS_REVIEW[id] = "reason" instead of
guessing blindly.

Usage:
    python scripts/classify_semgrep_finding_type.py <root> [--dry-run]

    <root>      e.g. rules/semgrep/custom or rules/semgrep/third-party
    --dry-run   print counts, write nothing

Re-running is safe: files/rule-blocks that already have a finding_type line
in their metadata are left untouched.
"""
import argparse
import glob
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MALICIOUS_IDS = {
    "bash_reverse_shell",
    "powershell-download-and-execute",
}

NEEDS_REVIEW = {
    # id -> reason. Empty by design: every rule reviewed so far resolved
    # cleanly to malicious or vulnerability without reasonable doubt.
}

# One block per top-level list item under `rules:`. `id:` is usually (but
# not always -- see aws-provisioner-exec.yaml, where `patterns:` is the
# first key of the mapping) the first key on the same line as the dash, so
# blocks are split on the dash marker itself, and `id:` is then searched for
# anywhere inside the resulting block. The dash's indentation varies by
# file (custom/ tends to use 2 spaces, third-party/ tends to use 0), so it
# is detected per file from the first list item found after `rules:`,
# rather than assumed fixed.
RULES_KEY_RE = re.compile(r'(?m)^rules:\s*$')
ID_IN_BLOCK_RE = re.compile(r'(?m)^[ \t]*(?:-[ \t]*)?id:[ \t]*(\S+)[ \t]*$')
RISK_JUSTIFICATION_RE = re.compile(r'(?m)^([ \t]*)risk_justification:.*$')


def split_rule_blocks(text):
    """Return [(start, end, rule_id), ...] byte offsets for each top-level rule entry."""
    rules_m = RULES_KEY_RE.search(text)
    if not rules_m:
        return []
    first_item_m = re.search(r'(?m)^([ \t]*)-\s', text[rules_m.end():])
    if not first_item_m:
        return []
    indent = re.escape(first_item_m.group(1))
    item_re = re.compile(rf'(?m)^{indent}-\s')
    matches = list(item_re.finditer(text, rules_m.end()))
    blocks = []
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        id_m = ID_IN_BLOCK_RE.search(text, start, end)
        rule_id = id_m.group(1) if id_m else None
        blocks.append((start, end, rule_id))
    return blocks


def classify(rule_id):
    if rule_id in MALICIOUS_IDS:
        finding_type = "malicious"
    else:
        finding_type = "vulnerability"
    reason = NEEDS_REVIEW.get(rule_id)
    return finding_type, reason


def process_file(path, dry_run):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    blocks = split_rule_blocks(text)
    if not blocks:
        return None  # not a rule file (e.g. config.yaml) -- caller filters these out

    # Work back-to-front so earlier offsets stay valid as we splice text in.
    changed = 0
    already = 0
    skipped_no_risk_score = 0
    for start, end, rule_id in reversed(blocks):
        block = text[start:end]
        if re.search(r'(?m)^\s*finding_type:', block):
            already += 1
            continue
        if rule_id is None:
            print(f"WARNING: {path}: rule block at offset {start} has no "
                  f"'id:' key found -- skipped, needs manual look.", file=sys.stderr)
            continue
        if not re.search(r'(?m)^\s*risk_score:', block):
            # Not a scored rule yet (e.g. a *.test.yaml companion or a rule
            # missing severity/confidence/exploitability/risk_score) --
            # finding_type rides along with the scoring fields, so leave it
            # alone rather than guessing on an unscored rule.
            skipped_no_risk_score += 1
            continue
        m = RISK_JUSTIFICATION_RE.search(block)
        if not m:
            print(f"WARNING: {path}: rule '{rule_id}' has risk_score but no "
                  f"risk_justification: line found -- skipped, needs manual look.",
                  file=sys.stderr)
            continue
        indent = m.group(1)
        finding_type, reason = classify(rule_id)
        insert_lines = [f"{indent}finding_type: {finding_type}"]
        if reason:
            insert_lines.append(f"{indent}needs_review: true")
            insert_lines.append(f'{indent}needs_review_reason: "{reason}"')
        insert_text = "\n" + "\n".join(insert_lines)
        insert_at = start + m.end()
        text = text[:insert_at] + insert_text + text[insert_at:]
        changed += 1

    if changed and not dry_run:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    return changed, already, skipped_no_risk_score


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", help="e.g. rules/semgrep/custom or rules/semgrep/third-party")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root_abs = os.path.join(REPO_ROOT, args.root)
    files = sorted(glob.glob(os.path.join(root_abs, "**", "*.yaml"), recursive=True))
    files += sorted(glob.glob(os.path.join(root_abs, "**", "*.yml"), recursive=True))
    files = [f for f in files if not f.endswith(".test.yaml") and os.path.basename(f) != "config.yaml"]

    total_changed = total_already = total_skipped = 0
    files_touched = 0
    for f in files:
        result = process_file(f, args.dry_run)
        if result is None:
            continue
        changed, already, skipped = result
        if changed:
            files_touched += 1
        total_changed += changed
        total_already += already
        total_skipped += skipped

    print(f"Files scanned: {len(files)}")
    print(f"Files with new finding_type lines: {files_touched}")
    print(f"Rule blocks updated: {total_changed}")
    print(f"Rule blocks already classified (skipped): {total_already}")
    print(f"Rule blocks without risk_score, i.e. unscored (skipped): {total_skipped}")
    if args.dry_run:
        print("(dry-run, nothing written)")


if __name__ == "__main__":
    main()
