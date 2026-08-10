from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMMON_PASSWORD_FILE = PROJECT_ROOT / "data" / "10k-most-common.txt"
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_TIMEOUT_SECONDS = 5


@lru_cache(maxsize=1)
def load_common_passwords() -> set[str]:
    """Load the local common-password list once and keep it in memory."""
    if not COMMON_PASSWORD_FILE.exists():
        return set()

    with COMMON_PASSWORD_FILE.open("r", encoding="utf-8", errors="ignore") as file:
        return {line.strip().casefold() for line in file if line.strip()}


def check_length(password: str) -> dict[str, Any]:
    length = len(password)
    return {
        "minimum_length": length >= 8,
        "length": length,
        "length_points": 0 if length < 8 else 2 if length >= 12 else 1,
    }


def check_lowercase(password: str) -> bool:
    return any(char.islower() for char in password)


def check_uppercase(password: str) -> bool:
    return any(char.isupper() for char in password)


def check_number(password: str) -> bool:
    return any(char.isdigit() for char in password)


def check_symbol(password: str) -> bool:
    return any((not char.isalnum()) and (not char.isspace()) for char in password)


def check_character_requirements(password: str) -> dict[str, bool]:
    return {
        "lowercase": check_lowercase(password),
        "uppercase": check_uppercase(password),
        "number": check_number(password),
        "symbol": check_symbol(password),
    }


def check_common_password(password: str) -> bool:
    normalized_password = password.strip().casefold()
    common_passwords = load_common_passwords()
    return normalized_password in common_passwords


def sha1_hash_password(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_hibp_response(response_text: str, hash_suffix: str) -> tuple[bool, int]:
    for line in response_text.splitlines():
        if ":" not in line:
            continue

        suffix, count_text = line.split(":", 1)
        suffix = suffix.strip().upper()

        if hmac.compare_digest(suffix, hash_suffix):
            try:
                return True, int(count_text.strip())
            except ValueError:
                return True, 0

    return False, 0


def check_pwned_password(password: str) -> dict[str, Any]:
    full_hash = sha1_hash_password(password)
    hash_prefix = full_hash[:5]
    hash_suffix = full_hash[5:]

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=hash_prefix),
            timeout=HIBP_TIMEOUT_SECONDS,
            headers={"Add-Padding": "true", "User-Agent": "password-strength-checker"},
        )
        response.raise_for_status()
    except requests.RequestException as error:
        return {
            "breached_password": False,
            "breach_count": 0,
            "breach_check_available": False,
            "breach_check_error": error.__class__.__name__,
        }

    if not response.text or ":" not in response.text:
        return {
            "breached_password": False,
            "breach_count": 0,
            "breach_check_available": False,
            "breach_check_error": "UnexpectedResponse",
        }

    breached, breach_count = parse_hibp_response(response.text, hash_suffix)
    return {
        "breached_password": breached,
        "breach_count": breach_count,
        "breach_check_available": True,
        "breach_check_error": None,
    }


def calculate_strength(
    length_check: dict[str, Any],
    character_checks: dict[str, bool],
    is_common_password: bool,
    breach_result: dict[str, Any],
) -> tuple[str, int, list[str]]:
    score = int(length_check["length_points"]) + sum(
        1 for passed in character_checks.values() if passed
    )
    reasons: list[str] = []

    if not length_check["minimum_length"]:
        reasons.append("Password is shorter than 8 characters.")
        return "WEAK", score, reasons

    if is_common_password:
        reasons.append("Password appears in the local common-password list.")
        return "WEAK", score, reasons

    if breach_result["breach_check_available"] and breach_result["breached_password"]:
        reasons.append("Password has appeared in known breach data.")
        return "WEAK", score, reasons

    missing_variety = [label for label, passed in character_checks.items() if not passed]
    if missing_variety:
        reasons.append("Missing character variety: " + ", ".join(missing_variety) + ".")

    if score >= 6:
        return "STRONG", score, reasons
    if score >= 4:
        return "MEDIUM", score, reasons
    return "WEAK", score, reasons


def analyze_password(password: str) -> dict[str, Any]:
    length_check = check_length(password)
    character_checks = check_character_requirements(password)
    is_common_password = check_common_password(password)
    breach_result = check_pwned_password(password)

    strength, score, feedback = calculate_strength(
        length_check=length_check,
        character_checks=character_checks,
        is_common_password=is_common_password,
        breach_result=breach_result,
    )

    checks = {
        "minimum_length": length_check["minimum_length"],
        **character_checks,
        "common_password": is_common_password,
        "breached_password": breach_result["breached_password"],
    }

    return {
        "strength": strength,
        "score": score,
        "checks": checks,
        "breach_count": breach_result["breach_count"],
        "breach_check_available": breach_result["breach_check_available"],
        "breach_check_error": breach_result["breach_check_error"],
        "feedback": feedback,
    }
