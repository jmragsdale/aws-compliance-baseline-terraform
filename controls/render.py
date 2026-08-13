#!/usr/bin/env python3
"""Render controls/controls.yaml into CONTROLS.md and verify it against the Terraform source.

This is the integrity check that makes the compliance claims in this repo falsifiable:
every control in controls.yaml names the Terraform address that implements it, and this
script fails if that address does not exist in terraform/. A control cannot be claimed
without code behind it.

Usage:
    python3 controls/render.py            # regenerate CONTROLS.md
    python3 controls/render.py --check    # verify CONTROLS.md is current and all addresses resolve
                                          # (exit 1 on drift or dangling reference) -- used by CI

controls.yaml schema
--------------------
metadata:
  cloud: aws|azure|gcp
  cloud_name: "Amazon Web Services"
  frameworks:                       # ordered; keys become matrix columns
    fedramp:
      name: "FedRAMP Rev 5"
      version: "Rev 5"
    nist_800_53_r5: {...}
    cis: {...}
controls:
  - id: LOG-001                     # unique, <AREA>-<NNN>
    title: "..."
    module: logging                 # dir under terraform/modules (or "root")
    enforcement: preventive|detective|foundational
    frameworks:
      fedramp: [AU-2, AU-9]         # control IDs in that framework; [] means not mapped
      nist_800_53_r5: [AU-2]
      cis: ["3.1"]
    implementation:                 # "<module>:<tf_type>.<tf_name>" or "<module>:module.<name>"
      - logging:aws_cloudtrail.org
    demo_safe: true                 # deployable in examples/single-account without org scope
    billable: false                 # incurs metered cost when enabled
    notes: "optional caveat"        # rendered verbatim; use for honest limitations
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO = Path(__file__).resolve().parent.parent
CONTROLS_YAML = REPO / "controls" / "controls.yaml"
CONTROLS_MD = REPO / "CONTROLS.md"
TF_ROOT = REPO / "terraform"

ADDRESS_RE = re.compile(r"^(?P<module>[A-Za-z0-9_\-]+):(?P<addr>[A-Za-z0-9_\.\-\[\]\"]+)$")
ENFORCEMENT = {"preventive", "detective", "foundational"}

GENERATED_BANNER = (
    "<!-- GENERATED FILE - do not edit by hand.\n"
    "     Source: controls/controls.yaml   Regenerate: python3 controls/render.py -->"
)


# --------------------------------------------------------------------------- loading


def load_controls() -> dict:
    if not CONTROLS_YAML.exists():
        sys.exit(f"missing {CONTROLS_YAML.relative_to(REPO)}")
    with CONTROLS_YAML.open() as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "controls" not in doc or "metadata" not in doc:
        sys.exit("controls.yaml must be a mapping with 'metadata' and 'controls' keys")
    return doc


def terraform_addresses() -> dict[str, set[str]]:
    """Map module dir name -> set of declared addresses found in its .tf files.

    Recognises `resource "type" "name"`, `data "type" "name"` (as data.type.name)
    and `module "name"` (as module.name).
    """
    found: dict[str, set[str]] = defaultdict(set)
    if not TF_ROOT.exists():
        return found

    res_re = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"', re.M)
    data_re = re.compile(r'^\s*data\s+"([^"]+)"\s+"([^"]+)"', re.M)
    mod_re = re.compile(r'^\s*module\s+"([^"]+)"', re.M)

    def scan(directory: Path, key: str) -> None:
        for tf in sorted(directory.glob("*.tf")):
            text = tf.read_text(encoding="utf-8")
            for typ, name in res_re.findall(text):
                found[key].add(f"{typ}.{name}")
            for typ, name in data_re.findall(text):
                found[key].add(f"data.{typ}.{name}")
            for name in mod_re.findall(text):
                found[key].add(f"module.{name}")

    scan(TF_ROOT, "root")
    modules_dir = TF_ROOT / "modules"
    if modules_dir.exists():
        for child in sorted(p for p in modules_dir.iterdir() if p.is_dir()):
            scan(child, child.name)
            # one level of submodules, addressed as "<parent>_<child>"
            for grandchild in sorted(p for p in child.iterdir() if p.is_dir()):
                scan(grandchild, f"{child.name}_{grandchild.name}")
    return found


# --------------------------------------------------------------------------- validation


def validate(doc: dict) -> list[str]:
    errors: list[str] = []
    framework_keys = list(doc["metadata"].get("frameworks", {}))
    if not framework_keys:
        errors.append("metadata.frameworks is empty")

    declared = terraform_addresses()
    seen_ids: set[str] = set()

    for ctl in doc["controls"]:
        cid = ctl.get("id", "<missing id>")
        if cid in seen_ids:
            errors.append(f"{cid}: duplicate control id")
        seen_ids.add(cid)

        for field in ("title", "module", "enforcement", "frameworks", "implementation"):
            if not ctl.get(field):
                errors.append(f"{cid}: missing required field '{field}'")

        if ctl.get("enforcement") and ctl["enforcement"] not in ENFORCEMENT:
            errors.append(
                f"{cid}: enforcement '{ctl['enforcement']}' not one of {sorted(ENFORCEMENT)}"
            )

        for key in ctl.get("frameworks", {}):
            if key not in framework_keys:
                errors.append(f"{cid}: unknown framework key '{key}'")

        if not any(ctl.get("frameworks", {}).get(k) for k in framework_keys):
            errors.append(f"{cid}: maps to no framework control in any framework")

        for ref in ctl.get("implementation", []) or []:
            match = ADDRESS_RE.match(ref)
            if not match:
                errors.append(f"{cid}: implementation '{ref}' is not '<module>:<address>'")
                continue
            module, addr = match.group("module"), match.group("addr")
            if module not in declared:
                errors.append(
                    f"{cid}: implementation '{ref}' -> no terraform module directory '{module}'"
                )
            elif addr not in declared[module]:
                errors.append(
                    f"{cid}: implementation '{ref}' -> address '{addr}' not declared in '{module}'"
                )

    return errors


# --------------------------------------------------------------------------- rendering


def coverage(doc: dict) -> dict[str, tuple[int, int]]:
    """framework key -> (controls mapped, distinct framework control ids referenced)"""
    out: dict[str, tuple[int, int]] = {}
    for key in doc["metadata"]["frameworks"]:
        mapped = 0
        ids: set[str] = set()
        for ctl in doc["controls"]:
            refs = ctl.get("frameworks", {}).get(key) or []
            if refs:
                mapped += 1
                ids.update(str(r) for r in refs)
        out[key] = (mapped, len(ids))
    return out


def render(doc: dict) -> str:
    meta = doc["metadata"]
    frameworks = meta["frameworks"]
    controls = sorted(doc["controls"], key=lambda c: c["id"])
    total = len(controls)
    cov = coverage(doc)

    lines: list[str] = [GENERATED_BANNER, ""]
    lines.append(f"# Control Matrix - {meta.get('cloud_name', meta['cloud'])}")
    lines.append("")
    lines.append(
        f"{total} implemented controls, each backed by a Terraform address that CI verifies exists."
    )
    lines.append("")

    # ---- framework summary
    lines.append("## Framework coverage")
    lines.append("")
    lines.append("| Framework | Version | Controls implemented | Distinct framework IDs mapped |")
    lines.append("|---|---|---:|---:|")
    for key, fw in frameworks.items():
        mapped, ids = cov[key]
        lines.append(
            f"| {fw.get('name', key)} | {fw.get('version', '-')} | {mapped} / {total} | {ids} |"
        )
    lines.append("")
    lines.append(
        "> **Read this honestly:** these numbers count *technical* controls implemented in "
        "Terraform. They are not an assessment, an ATO, or a claim of full baseline coverage. "
        "Administrative and procedural control families (AT, PS, PE, and much of PL/PM) cannot "
        "be implemented in infrastructure code at all."
    )
    lines.append("")

    # ---- enforcement split
    by_enf: dict[str, int] = defaultdict(int)
    for ctl in controls:
        by_enf[ctl["enforcement"]] += 1
    lines.append("## Enforcement split")
    lines.append("")
    lines.append("| Type | Count | Meaning |")
    lines.append("|---|---:|---|")
    meanings = {
        "preventive": "blocks the non-compliant configuration from being created",
        "detective": "detects and reports the non-compliant configuration",
        "foundational": "provides the substrate other controls depend on (logging, keys, scope)",
    }
    for enf in ("preventive", "detective", "foundational"):
        if by_enf.get(enf):
            lines.append(f"| {enf} | {by_enf[enf]} | {meanings[enf]} |")
    lines.append("")

    # ---- main matrix
    lines.append("## Matrix")
    lines.append("")
    header = ["ID", "Control", "Type", "Module"]
    header += [fw.get("short", fw.get("name", k)) for k, fw in frameworks.items()]
    header += ["Demo-safe", "Billable"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))
    for ctl in controls:
        row = [
            f"`{ctl['id']}`",
            ctl["title"],
            ctl["enforcement"],
            f"`{ctl['module']}`",
        ]
        for key in frameworks:
            refs = ctl.get("frameworks", {}).get(key) or []
            row.append(", ".join(str(r) for r in refs) if refs else "-")
        row.append("yes" if ctl.get("demo_safe") else "no")
        row.append("yes" if ctl.get("billable") else "no")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # ---- implementation index
    lines.append("## Implementation index")
    lines.append("")
    lines.append("Terraform addresses backing each control. CI fails if any of these stop existing.")
    lines.append("")
    lines.append("| ID | Terraform addresses |")
    lines.append("|---|---|")
    for ctl in controls:
        addrs = ", ".join(f"`{a}`" for a in ctl.get("implementation", []) or [])
        lines.append(f"| `{ctl['id']}` | {addrs} |")
    lines.append("")

    # ---- reverse index
    lines.append("## Reverse index (framework control -> repo control)")
    lines.append("")
    for key, fw in frameworks.items():
        reverse: dict[str, list[str]] = defaultdict(list)
        for ctl in controls:
            for ref in ctl.get("frameworks", {}).get(key) or []:
                reverse[str(ref)].append(ctl["id"])
        if not reverse:
            continue
        lines.append(f"### {fw.get('name', key)}")
        lines.append("")
        lines.append("| Framework control | Implemented by |")
        lines.append("|---|---|")
        for ref in sorted(reverse, key=_natural_key):
            lines.append(f"| {ref} | {', '.join(f'`{c}`' for c in sorted(reverse[ref]))} |")
        lines.append("")

    # ---- caveats
    notes = [(c["id"], c["notes"]) for c in controls if c.get("notes")]
    if notes:
        lines.append("## Caveats and limitations")
        lines.append("")
        for cid, note in notes:
            lines.append(f"- **`{cid}`** - {note}")
        lines.append("")

    if meta.get("framework_notes"):
        lines.append("## Framework notes")
        lines.append("")
        for note in meta["framework_notes"]:
            lines.append(f"- {note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _natural_key(value: str):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", value)]


# --------------------------------------------------------------------------- entrypoint


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify CONTROLS.md is current and every implementation address resolves",
    )
    args = parser.parse_args()

    doc = load_controls()
    errors = validate(doc)
    if errors:
        print(f"controls.yaml failed validation ({len(errors)} problem(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    rendered = render(doc)

    if args.check:
        current = CONTROLS_MD.read_text(encoding="utf-8") if CONTROLS_MD.exists() else ""
        if current != rendered:
            print(
                "CONTROLS.md is out of date - run: python3 controls/render.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {len(doc['controls'])} controls, all implementation addresses resolve.")
        return 0

    CONTROLS_MD.write_text(rendered, encoding="utf-8")
    print(f"wrote {CONTROLS_MD.relative_to(REPO)} ({len(doc['controls'])} controls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
