"""Minimal Flask auth API for React login flow."""

from flask import Flask, jsonify, request

import database

app = Flask(__name__)


@app.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip()
    password = payload.get("password", "")

    result = database.create_user(email, password)
    if result.get("success"):
        return jsonify({"success": True})

    return jsonify(
        {
            "success": False,
            "message": result.get("message", "User already exists"),
        }
    )


@app.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip()
    password = payload.get("password", "")

    user = database.get_user(email)
    if user is None:
        return jsonify({"success": False, "message": "User not registered"})

    if user.get("password") != password:
        return jsonify({"success": False, "message": "Invalid password"})

    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
