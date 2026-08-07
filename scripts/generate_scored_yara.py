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
    # Ultimo caracter no-blanco ya escrito en `out`. Se usa para decidir si
    # un '/' abre un literal de regex de YARA (ej. `$re = /foo\/bar/`) en
    # vez de tratarlo como texto normal: en la gramatica de YARA, un
    # literal de regex solo puede empezar justo despues de un '=' (la
    # forma con diferencia mas comun, `$id = /regex/flags`). Sin este
    # chequeo, un regex que contenga una secuencia `\/` seguida del '/' de
    # cierre (o cualquier `//`/`/*` interna) se confunde con un comentario
    # y strip_comments() se come el resto de la linea, dejando el regex
    # sin cerrar -- bug real detectado en webshells/WShell_Drupalgeddon2_icos.yar
    # (la regex terminaba en `...\*\//`, y el '//' final se interpretaba
    # como inicio de comentario de linea).
    last_non_space = ''
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
            last_non_space = c
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
        if c == '/' and last_non_space == '=':
            # Literal de regex: consumir tal cual (respetando '\' como
            # escape, igual que en las cadenas) hasta el '/' de cierre sin
            # escapar, sin tratar ningun '//' ni '/*' interno como
            # comentario.
            out.append(c)
            j = i + 1
            re_escape = False
            while j < n:
                rc = text[j]
                out.append(rc)
                if re_escape:
                    re_escape = False
                elif rc == '\\':
                    re_escape = True
                elif rc == '/':
                    j += 1
                    break
                j += 1
            i = j
            last_non_space = '/'
            continue
        out.append(c)
        if not c.isspace():
            last_non_space = c
        i += 1
    return ''.join(out)


IMPORT_RE = re.compile(r'(?m)^[ \t]*import\s+"([^"]+)"\s*$')

def extract_imports(clean_text):
    """
    Modulos declarados con `import "modulo"` en el fichero fuente (p.ej.
    `import "pe"`). split_rules() solo extrae bloques `rule { ... }`, asi
    que estas declaraciones se perdian por completo en el fichero
    regenerado -- bug real detectado en antidebug_antivm.yar, que usa
    `pe.imports(...)` en una condition sin que el fichero de salida
    tuviera el `import "pe"` correspondiente. Se devuelven todos los
    imports del fichero fuente (no solo los de las reglas seleccionadas):
    un import de mas es inocuo en YARA, perder uno necesario no compila.
    """
    seen = []
    for m in IMPORT_RE.finditer(clean_text):
        name = m.group(1)
        if name not in seen:
            seen.append(name)
    return seen

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
        imports = extract_imports(clean)

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
            for imp in imports:
                fh.write(f'import "{imp}"\n')
            if imports:
                fh.write("\n")
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
