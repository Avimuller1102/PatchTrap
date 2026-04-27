"""
target_app.py — a dummy application used for testing PatchTrap end-to-end.
"""
import sys
import time

def sensitive_function():
    return "original_value"

def main():
    print("[target_app] Starting...")
    val = sensitive_function()
    print(f"[target_app] sensitive_function() returned: {val}")
    if len(sys.argv) > 1 and sys.argv[1] == "sleep":
        time.sleep(0.5)
    print("[target_app] Done.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
