#!/usr/bin/env python3
""" basic flask app
"""
from flask import Flask, jsonify, request
from auth import Auth

app = Flask(__name__)
Auth = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """  returns a welcome message
    """
    message = {"message": "Bienvenue"}

    return jsonify(message)


@app.route("/users", methods=["post"], strict_slashes=False)
def users() -> str:
    """ returns 400 status code
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = Auth.register_user(email, password)

        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
