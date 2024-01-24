#!/usr/bin/env python3
"""A basic flask app
"""
from flask import abort, Flask, jsonify, redirect, request
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route('/', strict_slashes=False)
def home():
    """default route for the app
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users/', strict_slashes=False, methods=['POST'])
def users():
    """Registers a user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({
            "email": email,
            "message": "user created"
        })
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions/', strict_slashes=False, methods=['POST'])
def login():
    """creates a new session for the user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({'email': email, 'message': 'logged in'})
    response.set_cookie('session_id', session_id)

    return response


@app.route('/sessions/', strict_slashes=False, methods=['DELETE'])
def logout():
    """deletes a user session
    """
    session_id = request.cookies.get('session_id')

    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
