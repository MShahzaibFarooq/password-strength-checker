from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.password_logic import analyze_password  # noqa: E402


app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/check-password", methods=["POST"])
def check_password_api():
    data = request.get_json(silent=True) or {}
    password = data.get("password")

    if not isinstance(password, str):
        return jsonify({"error": "Password must be provided as text."}), 400

    return jsonify(analyze_password(password))


if __name__ == "__main__":
    app.run(debug=True)
