#!/usr/bin/env python3
"""app module
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', strict_slashes=False)
def hello() -> str:
    """ GET /
    Return:
      - greeting represented in JSON
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """ POST /users
    JSON body:
      - email
      - password
    Return:
      - User object JSON represented
      - 400 if can't register the new User
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    return jsonify({"email": email, "message": "user created"})


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ POST /sessions
    JSON body:
      - email
      - password
    Return:
      - User object JSON represented
      - 401 if can't register the new User
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password):
        sessId = AUTH.create_session(email)
        res = jsonify({"email": email, "message": "logged in"})
        res.set_cookie('session_id', sessId)
        return res
    abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """ DELETE /sessions
    JSON body:
      - session_id
    Return:
      - 400 if can't register the new User
    Redirect:
        GET /
    """
    sessId = request.cookies.get('session_id')
    usr = AUTH.get_user_from_session_id(sessId)
    if usr is not None:
        AUTH.destroy_session(usr.id)
        return redirect('/')
    else:
        abort(403)


@app.route('/profile', strict_slashes=False)
def profile() -> str:
    """ GET /profile
    Return:
      - user email represented in JSON
    """
    try:
        sessId = request.cookies.get('session_id')
        usr = AUTH.get_user_from_session_id(sessId)
        print('usr', usr)
        return jsonify({"email": usr.email}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """ POST /reset_password
    JSON body:
      - email
    Return:
      - User object JSON represented
      - 401 if can't register the new User
    """
    email = request.form.get('email')
    try:
        resetToken = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": resetToken}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """ PUT /reset_password
    JSON body:
      - email
      - reset_token
      - new_password
    Return:
      - User object JSON represented
      - 401 if can't register the new User
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
