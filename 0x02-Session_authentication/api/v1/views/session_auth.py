#!/usr/bin/env python3
"""A view that handles all routes for the Session authentication
"""
import os
from flask import session
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_session_login() -> str:
    """ POST /api/v1/auth_session/login
    JSON body:
      - email
      - password
      - last_name (optional)
      - first_name (optional)
    Return:
      - User object JSON represented
      - 400 if can't create the new User
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if (email is None or email == ""):
        return jsonify({ "error": "email missing" }), 400
    elif(password is None or password == ""):
        return jsonify({ "error": "password missing" }), 400

    userObjList =  User.search({ 'email': email })
    if not userObjList:
        return jsonify({ "error": "no user found for this email" }), 404
    for usrObj in userObjList:
        if not usrObj.is_valid_password(password):
            return jsonify({ "error": "wrong password" }), 401
        else:
            from api.v1.app import auth
            sessId = auth.create_session(usrObj.id)
            sessName = os.getenv('SESSION_NAME')
            session[sessName] = sessId
            return jsonify(usrObj.to_json(), session[sessName])

