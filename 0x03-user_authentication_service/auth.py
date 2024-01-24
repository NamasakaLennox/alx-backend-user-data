#!/usr/bin/env python3
"""Takes a password string and returns a hashed byte string
"""
from bcrypt import gensalt, hashpw
from db import DB
from user import User
from sqlalchemy.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            password = _hash_password(password)

            user = self._db.add_user(email, password)

            return user


def _hash_password(password: str) -> bytes:
    """generates a hashed password using bcrypt
    """
    hashed = password.encode('utf-8')

    salt = gensalt()
    return hashpw(hashed, salt)
