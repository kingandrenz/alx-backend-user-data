#!/usr/bin/env python3
""" basic flask app
"""
from flask import Flask, jsonify, request, make_response, abort
from auth import Auth

app = Flask(__name__)
Auth = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """  returns a welcome message
    """
    message = {"message": "Bienvenue"}

    return jsonify(message)


@app.route("/users", methods=["POST"], strict_slashes=False)
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


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """ this function responds to the POST /session
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not Auth.valid_login(email, password):
        abort(401)

    session_id = Auth.create_session(email)
    response = jsonify({"email": f"{email}", "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """ logout with session ID
    """
    session_id = request.cookies.get("session_id")
    user = Auth.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    Auth.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """ find if user exists and respon with 200
    """
    session_id = request.cookies.get("session_id")
    user = Auth.get_user_from_session_id(session_id)

    if user is None:
        abort(403)
    return jsonify({"email": f"{user.email}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
