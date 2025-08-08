#!/usr/bin/env python3
import subprocess, sys, pathlib

def main():
    here = pathlib.Path(__file__).parent
    tests = sorted(p for p in here.glob("test_*.py"))
    print(f"[INFO] Running {len(tests)} tests…")
    ok = 0
    for t in tests:
        print(f"\n[RUN] {t.name}")
        proc = subprocess.run([sys.executable, str(t)])
        if proc.returncode == 0:
            ok += 1
        else:
            print(f"[FAIL] {t.name} (rc={proc.returncode})")
            return proc.returncode
    print(f"\n[ALL PASS] {ok}/{len(tests)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
