import requests

import app as password_app


def offline_breach_result(password):
    return {
        "breached_password": False,
        "breach_count": 0,
        "breach_check_available": True,
        "breach_check_error": None,
    }


def test_short_password_is_weak(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    result = password_app.analyze_password("Ab1!")

    assert result["strength"] == "WEAK"
    assert result["checks"]["minimum_length"] is False


def test_common_password_is_weak(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    result = password_app.analyze_password("password")

    assert result["strength"] == "WEAK"
    assert result["checks"]["common_password"] is True


def test_password1_is_not_strong(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    result = password_app.analyze_password("Password1")

    assert result["strength"] != "STRONG"


def test_lacking_variety_is_weak(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    assert password_app.analyze_password("abcdefgh")["strength"] == "WEAK"
    assert password_app.analyze_password("ABCDEFGH")["strength"] != "STRONG"


def test_long_random_password_can_be_strong(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    result = password_app.analyze_password("Q7m!vL2z#rT9nP4x")

    assert result["strength"] == "STRONG"
    assert result["score"] == 6


def test_breached_password_forces_weak(monkeypatch):
    def breached_result(password):
        return {
            "breached_password": True,
            "breach_count": 1000,
            "breach_check_available": True,
            "breach_check_error": None,
        }

    monkeypatch.setattr(password_app, "check_pwned_password", breached_result)

    result = password_app.analyze_password("Q7m!vL2z#rT9nP4x")

    assert result["strength"] == "WEAK"
    assert result["breach_count"] == 1000


def test_hibp_failure_does_not_crash(monkeypatch):
    def failed_result(password):
        return {
            "breached_password": False,
            "breach_count": 0,
            "breach_check_available": False,
            "breach_check_error": "Timeout",
        }

    monkeypatch.setattr(password_app, "check_pwned_password", failed_result)

    result = password_app.analyze_password("Q7m!vL2z#rT9nP4x")

    assert result["breach_check_available"] is False
    assert result["strength"] == "STRONG"


def test_empty_spaces_unicode_and_symbols_do_not_crash(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    for password in ["", "        ", "pässW0rd!", "!@#$%^&*"]:
        result = password_app.analyze_password(password)
        assert "strength" in result
        assert "checks" in result


def test_very_long_password_does_not_crash(monkeypatch):
    monkeypatch.setattr(password_app, "check_pwned_password", offline_breach_result)

    result = password_app.analyze_password("A" * 5000 + "a1!")

    assert result["checks"]["minimum_length"] is True


def test_api_rejects_missing_password():
    client = password_app.app.test_client()

    response = client.post("/api/check-password", json={})

    assert response.status_code == 400


def test_hibp_sends_only_sha1_prefix(monkeypatch):
    captured = {}

    class FakeResponse:
        text = "ABCDEF1234567890ABCDEF1234567890ABC:2"

        def raise_for_status(self):
            return None

    def fake_get(url, timeout, headers):
        captured["url"] = url
        captured["timeout"] = timeout
        captured["headers"] = headers
        return FakeResponse()

    monkeypatch.setattr(password_app.requests, "get", fake_get)

    password_app.check_pwned_password("MyVeryLongPassword123!")
    prefix = captured["url"].rsplit("/", 1)[-1]

    assert len(prefix) == 5
    assert "MyVeryLongPassword123!" not in captured["url"]
    assert len(password_app.sha1_hash_password("MyVeryLongPassword123!")) == 40


def test_hibp_timeout_returns_unavailable(monkeypatch):
    def fake_get(url, timeout, headers):
        raise requests.Timeout()

    monkeypatch.setattr(password_app.requests, "get", fake_get)

    result = password_app.check_pwned_password("anything")

    assert result["breach_check_available"] is False
    assert result["breached_password"] is False
