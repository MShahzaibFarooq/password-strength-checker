from __future__ import annotations

from datetime import datetime, timezone
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.password_logic import analyze_password  # noqa: E402


app = Flask(__name__)
ANALYSIS_HISTORY: list[dict] = []
MAX_HISTORY_ITEMS = 50


def save_analysis_history(password: str, result: dict) -> None:
    checks = result["checks"]
    ANALYSIS_HISTORY.insert(
        0,
        {
            "id": len(ANALYSIS_HISTORY) + 1,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "password_length": len(password),
            "strength": result["strength"],
            "score": result["score"],
            "common_password": checks["common_password"],
            "breached_password": checks["breached_password"],
            "breach_count": result["breach_count"],
            "breach_check_available": result["breach_check_available"],
        },
    )
    del ANALYSIS_HISTORY[MAX_HISTORY_ITEMS:]


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/check-password", methods=["POST"])
def check_password_api():
    data = request.get_json(silent=True) or {}
    password = data.get("password")

    if not isinstance(password, str):
        return jsonify({"error": "Password must be provided as text."}), 400

    result = analyze_password(password)
    save_analysis_history(password, result)
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def analysis_history_api():
    return jsonify({"history": ANALYSIS_HISTORY})


if __name__ == "__main__":
    app.run(debug=True)
