"""Run every offline test module in its own Python process and aggregate the counts.

Several existing modules install process-wide audit hooks at import, so importing all
suites into one process produces unrelated failures (see src/comparison/M4_VALIDATION.md).
Each module is therefore executed separately, and only TestCase classes *defined* in that
module are run, so classes imported from another test module are not counted twice.

Standard library only. No network, Docker, VM or AWS call is made by this runner itself.
Nothing is skipped or deselected: a module that cannot be imported is reported as ERROR.

    py -3.15 -B tools/run_offline_tests.py [--out DIR] [suite ...]
"""
import argparse
import importlib
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def _run_one(path: Path) -> dict:
    sys.path.insert(0, str(ROOT))
    if (path.parent / "__init__.py").exists():
        name = ".".join(path.relative_to(ROOT).with_suffix("").parts)
    else:
        sys.path.insert(0, str(path.parent))
        name = path.stem
    module = importlib.import_module(name)
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for value in vars(module).values():
        if (isinstance(value, type) and issubclass(value, unittest.TestCase)
                and value.__module__ == module.__name__):
            suite.addTests(loader.loadTestsFromTestCase(value))
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
    bad = len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses)
    return {"run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "passed": result.testsRun - bad - len(result.skipped) - len(result.expectedFailures)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--one")
    parser.add_argument("--out")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("suites", nargs="*")
    args = parser.parse_args()
    if args.one:
        result = _run_one(Path(args.one).resolve())
        print("\nRESULT " + json.dumps(result), flush=True)  # own line: a test may leave a partial line on stdout
        return 0

    out = Path(args.out).resolve() if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    modules = sorted(p for p in TESTS.rglob("test_*.py")
                     if not args.suites or p.relative_to(TESTS).parts[0] in args.suites)
    rows, totals = [], {}
    for path in modules:
        rel = path.relative_to(ROOT).as_posix()
        started = time.monotonic()
        try:
            proc = subprocess.run([sys.executable, "-B", __file__, "--one", str(path)],
                                  cwd=ROOT, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=args.timeout)
            lines = [x for x in proc.stdout.splitlines() if x.startswith("RESULT ")]
            row = (json.loads(lines[-1][7:]) if lines else
                   {"run": 0, "failures": 0, "errors": 1, "skipped": 0, "passed": 0,
                    "expected_failures": 0, "unexpected_successes": 0,
                    "note": "MODULE_DID_NOT_REPORT exit=%d" % proc.returncode})
            log = proc.stderr + proc.stdout
        except subprocess.TimeoutExpired as exc:
            row = {"run": 0, "failures": 0, "errors": 1, "skipped": 0, "passed": 0,
                   "expected_failures": 0, "unexpected_successes": 0, "note": "TIMEOUT"}
            log = str(exc)
        row.update(module=rel, seconds=round(time.monotonic() - started, 1))
        rows.append(row)
        if out:
            (out / (rel.replace("/", "__") + ".log")).write_text(log, encoding="utf-8")
        for key in ("run", "passed", "failures", "errors", "skipped"):
            totals[key] = totals.get(key, 0) + row[key]
        print("%-52s run=%-4d pass=%-4d fail=%d err=%d skip=%d %s" % (
            rel, row["run"], row["passed"], row["failures"], row["errors"],
            row["skipped"], row.get("note", "")), flush=True)
    report = {"python": sys.version.split()[0], "modules": len(rows), "totals": totals,
              "rows": rows}
    print("TOTAL " + json.dumps(totals))
    if out:
        (out / "summary.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    return 0 if totals.get("failures", 0) == 0 and totals.get("errors", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
