import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
SCRIPTS_DIR = HERE.parent / "scripts"

SUITES = [
    ("block_scan.py", "cases_scan.jsonl"),
    ("block_sensitive_files.py", "cases_sensitive.jsonl"),
    ("block_destructive.py", "cases_destructive.jsonl"),
]


def run_suite(script_name: str, cases_name: str):
    script = SCRIPTS_DIR / script_name
    cases = HERE / cases_name
    total = 0
    failures = 0
    print(f"\n=== {script_name} ({cases_name}) ===")
    with open(cases, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            payload = json.dumps(case["payload"])
            proc = subprocess.run(
                [sys.executable, "-I", str(script)],
                input=payload,
                capture_output=True,
                text=True,
            )
            total += 1
            try:
                out = json.loads(proc.stdout)
                got = "allow" if out.get("continue", True) else "deny"
            except Exception:
                got = f"ERROR({proc.stdout!r}/{proc.stderr!r})"
            status = "OK" if got == case["expect"] else "FAIL"
            if status == "FAIL":
                failures += 1
            print(f"[{status}] {case['name']}: expected={case['expect']} got={got}")
            if proc.stderr:
                print("  stderr:", proc.stderr.strip())
    return total, failures


def main():
    grand_total = 0
    grand_failures = 0
    for script_name, cases_name in SUITES:
        total, failures = run_suite(script_name, cases_name)
        grand_total += total
        grand_failures += failures

    print(f"\n{'='*50}")
    print(f"TOTAL: {grand_total - grand_failures}/{grand_total} passed, {grand_failures} failure(s)")
    sys.exit(1 if grand_failures else 0)


if __name__ == "__main__":
    main()
