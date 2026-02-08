import sys
import os

# Add the project root to sys.path so we can import scan_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scan_engine.helpers.target_utils import validate_target

def test_validate_target():
    test_cases = [
        # Safe targets
        ("8.8.8.8", True),
        ("http://google.com", True),
        ("https://example.com", True),
        ("google.com", True),
        ("1.1.1.1:80", True),
        #("2606:4700:4700::1111", True), # Cloudflare IPv6 - commenting out to avoid IPv6 issues if env doesn't support

        # Unsafe targets
        ("127.0.0.1", False),
        ("localhost", False),
        ("10.0.0.1", False),
        ("192.168.1.50", False),
        ("172.16.0.5", False),
        ("0.0.0.0", False),
        ("http://127.0.0.1", False),
        ("https://10.2.3.4:8443", False),
        ("[::1]", False), # IPv6 Loopback
        ("169.254.1.1", False), # Link-local
    ]

    print("Running validation tests...")
    failed = False
    for target, expected in test_cases:
        try:
            is_safe, msg = validate_target(target)
            result = "PASS" if is_safe == expected else "FAIL"
            if result == "FAIL":
                failed = True
                print(f"{result}: {target} -> Got {is_safe} ({msg}), Expected {expected}")
            else:
                # print(f"{result}: {target}")
                pass
        except Exception as e:
            print(f"ERROR: {target} -> Exception: {e}")
            failed = True

    if failed:
        print("Some tests failed!")
        sys.exit(1)
    else:
        print("All tests passed!")

if __name__ == "__main__":
    test_validate_target()
