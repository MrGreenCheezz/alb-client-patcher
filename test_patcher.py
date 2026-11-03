#!/usr/bin/env python3
"""Tests for patch_albion.py.

Default tests are intentionally fast and do not rewrite deliverables:
  - foreign build is rejected and writes no output;
  - --dry-run reports a plan and writes no output;
  - rerunning on an already patched DLL preserves bytes and says already patched.

Use --include-golden to additionally compare a full patch of the reference
original client DLL with the known golden patched DLL.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHER = ROOT / "patcher" / "patch_albion.py"
TMP = ROOT / "work" / "tmp"
NEW_DLL = ROOT / "work" / "new" / "GameAssembly.dll"
NEW_MD = ROOT / "work" / "new" / "global-metadata.dat"
PATCHED_NEW = ROOT / "work" / "GameAssembly.dll.new"
OLD_DLL = ROOT / "work" / "ref" / "GA_old_original.dll"
OLD_MD = ROOT / "work" / "ref" / "global-metadata_old.dat"
OLD_GOLDEN = ROOT / "work" / "ref" / "GA_old_golden.dll"
FOREIGN_DLL = ROOT / "game" / "UnityPlayer.dll"


def sha256_file(path, block=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(block)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def run_patcher(args):
    cp = subprocess.run(
        [sys.executable, str(PATCHER)] + [str(a) for a in args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    return cp.returncode, cp.stdout, cp.stderr


def remove_if_exists(path):
    if path.exists():
        path.unlink()


def require(condition, message, failures):
    if condition:
        print("PASS %s" % message)
    else:
        print("FAIL %s" % message)
        failures.append(message)


def test_foreign_build(failures):
    out = TMP / "test_foreign_output.dll"
    remove_if_exists(out)
    rc, out_text, err_text = run_patcher([
        "--dll", FOREIGN_DLL,
        "--metadata", NEW_MD,
        "--output", out,
        "--dry-run",
    ])
    print(rc)
    print(out_text)
    print(err_text)
    require(rc != 0, "foreign DLL: patcher exits with non-zero status", failures)
    require(not out.exists(), "foreign DLL: patcher creates no output file", failures)
    require("ERROR:" in out_text, "foreign DLL: patcher prints an English error", failures)


def test_dry_run(failures):
    out = TMP / "test_dry_run_output.dll"
    remove_if_exists(out)
    rc, out_text, err_text = run_patcher([
        "--dll", PATCHED_NEW,
        "--metadata", NEW_MD,
        "--output", out,
        "--dry-run",
        "--quiet",
    ])
    print(rc)
    print(out_text)
    print(err_text)
    require(rc == 0, "dry run: patcher exits zero for a patched DLL", failures)
    require(not out.exists(), "dry run: patcher creates no output file", failures)
    require("Dry run: no file written" in out_text, "dry run: patcher prints no-write plan", failures)


def test_idempotency(failures):
    out = TMP / "test_idempotency_output.dll"
    remove_if_exists(out)
    rc, out_text, err_text = run_patcher([
        "--dll", PATCHED_NEW,
        "--metadata", NEW_MD,
        "--output", out,
        "--quiet",
    ])
    print(rc)
    print(out_text)
    print(err_text)
    same = out.exists() and sha256_file(out) == sha256_file(PATCHED_NEW)
    require(rc == 0, "idempotency: rerun exits zero", failures)
    require(same, "idempotency: rerun output bytes equal patched input", failures)
    require("STATUS: already patched" in out_text, "idempotency: rerun reports already patched", failures)


def test_golden(failures):
    out = TMP / "test_golden_output.dll"
    remove_if_exists(out)
    rc, out_text, err_text = run_patcher([
        "--dll", OLD_DLL,
        "--metadata", OLD_MD,
        "--output", out,
        "--quiet",
    ])
    print(rc)
    print(out_text)
    print(err_text)
    same = out.exists() and sha256_file(out) == sha256_file(OLD_GOLDEN)
    require(rc == 0, "golden: reference old DLL patch exits zero", failures)
    require(same, "golden: reference old DLL output equals golden DLL", failures)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-golden", action="store_true",
                    help="run the full old original vs golden comparison")
    args = ap.parse_args()
    TMP.mkdir(parents=True, exist_ok=True)
    for path in (NEW_DLL, NEW_MD, PATCHED_NEW, OLD_DLL, OLD_MD, OLD_GOLDEN, FOREIGN_DLL):
        if not path.is_file():
            print("FAIL required file missing: %s" % path)
            return 1
    failures = []
    test_foreign_build(failures)
    test_dry_run(failures)
    test_idempotency(failures)
    if args.include_golden:
        test_golden(failures)
    if failures:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
