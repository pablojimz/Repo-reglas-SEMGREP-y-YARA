# -*- coding: utf-8 -*-
"""
backfill_finding_type_yara.py

One-off (but idempotent) migration that adds `finding_type` --
and, when the classification is uncertain, `needs_review` /
`needs_review_reason` -- to every entry in
yara_scores_output/yara_rule_scores.json that doesn't have it yet.

Classification schema: .claude/criterioPuntuacionReglas.md
Background/decisions: .claude/separacion_vul_cog_malicoso.md

Per-category default, decided after sampling a portion of each category's
`risk_justification` text (see PR description / commit message for the
sample used):

  webshell         -> malicious
                       Every sampled entry's risk_justification reads
                       "Web shell / backdoor signature -- indicates a
                       deployed remote-code-execution capability if it
                       matches" -- the code that trips the rule *is* the
                       backdoor, uniformly, so no needs_review.

  antidebug_antivm -> malicious, needs_review=true
                       These are generic anti-debug/anti-VM API/string
                       checks (IsDebugged, NtGlobalFlags, CheckRemoteDebugger
                       Present...). They dominate in malware (evade
                       analysis) but the same technique also appears in
                       legitimate DRM/anti-cheat/license-protection code,
                       so a human should confirm before treating a match as
                       automatic containment.

A category with no mapping here is left untouched (no finding_type is
guessed blindly) and reported so a human can extend CATEGORY_DEFAULTS
deliberately -- this mirrors the "no inventes un criterio... sin dejarlo
por escrito" restriction in .claude/separacion_vul_cog_malicoso.md.

Usage:
    python scripts/backfill_finding_type_yara.py [--category NAME] [--dry-run]

    --category NAME   only backfill entries whose "category" == NAME
                       (repeatable). Default: all categories with a known
                       mapping below. Used to roll this out to one category
                       at a time (e.g. webshell first, validated, then
                       antidebug_antivm) per the phased-commit requirement.
    --dry-run         print what would change, write nothing.

Re-running is safe: entries that already have "finding_type" are skipped.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCORES_JSON = os.path.join(REPO_ROOT, "yara_scores_output", "yara_rule_scores.json")

CATEGORY_DEFAULTS = {
    "webshell": {
        "finding_type": "malicious",
    },
    "antidebug_antivm": {
        "finding_type": "malicious",
        "needs_review": True,
        "needs_review_reason": (
            "tecnica dual-use; contexto del ruleset (firmas pensadas para "
            "triage de malware) hace mas probable malicious, pero el mismo "
            "patron aparece tambien en DRM/anti-cheat legitimo"
        ),
    },
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--category", action="append", default=None,
                     help="restrict to this category (repeatable); default: all known categories")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    target_categories = set(args.category) if args.category else set(CATEGORY_DEFAULTS.keys())
    unknown = target_categories - set(CATEGORY_DEFAULTS.keys())
    if unknown:
        print(f"ERROR: no default mapping for categor(y/ies): {sorted(unknown)}. "
              f"Add them to CATEGORY_DEFAULTS first (see module docstring).", file=sys.stderr)
        sys.exit(1)

    with open(SCORES_JSON, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    updated = 0
    skipped_already_set = 0
    skipped_unmapped_category = set()

    for s in doc["scores"]:
        cat = s.get("category")
        if "finding_type" in s:
            skipped_already_set += 1
            continue
        if cat not in target_categories:
            if cat not in CATEGORY_DEFAULTS:
                skipped_unmapped_category.add(cat)
            continue
        defaults = CATEGORY_DEFAULTS[cat]
        # Insert in the same relative position every time: right after
        # risk_justification, same as inject_score_meta() does for the
        # generated .yar meta: block.
        new_entry = {}
        for k, v in s.items():
            new_entry[k] = v
            if k == "risk_justification":
                for extra_k, extra_v in defaults.items():
                    new_entry[extra_k] = extra_v
        s.clear()
        s.update(new_entry)
        updated += 1

    print(f"Updated: {updated}")
    print(f"Already had finding_type (skipped): {skipped_already_set}")
    if skipped_unmapped_category:
        print(f"Skipped, no mapping for category: {sorted(skipped_unmapped_category)}")

    if args.dry_run:
        print("(dry-run, nothing written)")
        return

    if updated:
        with open(SCORES_JSON, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"Wrote {SCORES_JSON}")


if __name__ == "__main__":
    main()
