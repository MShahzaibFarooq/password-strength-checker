from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.password_logic import analyze_password  # noqa: E402


def pass_fail(value: bool) -> str:
    return "PASS" if value else "FAIL"


def yes_no(value: bool) -> str:
    return "YES" if value else "NO"


def print_analysis(result: dict) -> None:
    checks = result["checks"]

    if not result["breach_check_available"]:
        breach_status = "UNAVAILABLE"
    elif checks["breached_password"]:
        breach_status = "FOUND"
    else:
        breach_status = "NOT FOUND"

    print()
    print("Password Analysis")
    print("-----------------")
    print(f"Minimum length:       {pass_fail(checks['minimum_length'])}")
    print(f"Lowercase letter:     {pass_fail(checks['lowercase'])}")
    print(f"Uppercase letter:     {pass_fail(checks['uppercase'])}")
    print(f"Number:               {pass_fail(checks['number'])}")
    print(f"Special character:    {pass_fail(checks['symbol'])}")
    print(f"Common password:      {yes_no(checks['common_password'])}")
    print(f"Breach status:        {breach_status}")

    if result["breach_check_available"] and checks["breached_password"]:
        print(f"Known breach occurrences: {result['breach_count']}")

    if result["feedback"]:
        print()
        print("Notes:")
        for message in result["feedback"]:
            print(f"- {message}")

    print()
    print("Final Strength:")
    print(result["strength"])
    print(f"Effective score: {result['score']} / 6")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze password strength from the terminal.")
    parser.add_argument(
        "--password",
        help="Analyze an exact password value. Use only for local testing.",
    )
    args = parser.parse_args()

    print("=" * 40)
    print("       PASSWORD STRENGTH CHECKER")
    print("=" * 40)
    if args.password is not None:
        password = args.password
    elif sys.stdin.isatty():
        password = input("Enter password: ")
    else:
        print("Enter password: ", end="")
        password = sys.stdin.readline().rstrip("\n")
    result = analyze_password(password)
    print_analysis(result)


if __name__ == "__main__":
    main()
