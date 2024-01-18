#!/usr/bin/env python3
"""Module for handling session routes
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login/', strict_slashes=False,
                 methods=['POST'])
def auth_session_login() -> str:
    """handles login for a session
    """
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get('password')
    if not password:
        return jsonify({"error": "password missing"}), 400

    is_valid_user = User.search({'email': email})

    if not is_valid_user:
        return jsonify({"error": "no user found for this email"}), 404

    is_valid_user = is_valid_user[0]

    if not is_valid_user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth
    session_id = auth.create_session(is_valid_user.id)
    cookie_response = getenv('SESSION_NAME')
    user_dict = jsonify(is_valid_user.to_json())

    user_dict.set_cookie(cookie_response, session_id)
    return user_dict


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def session_logout() -> str:
    """ DELETE /api/v1/auth/session/logout
    Returns deleted json (if correctly done)
    404 if fails
    """
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
