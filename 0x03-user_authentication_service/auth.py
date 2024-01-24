#!/usr/bin/env python3
"""Takes a password string and returns a hashed byte string
"""
from bcrypt import checkpw, gensalt, hashpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Constructor method
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except (NoResultFound, InvalidRequestError):
            password = _hash_password(password)

            user = self._db.add_user(email, password)

            return user

    def valid_login(self, email: str, password: str) -> bool:
        """checks if the login credentials are valid
        """
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode('utf-8')
            if checkpw(password, user.hashed_password):
                return True
            return False
        except (NoResultFound, InvalidRequestError):
            return False


def _hash_password(password: str) -> bytes:
    """generates a hashed password using bcrypt
    """
    hashed = password.encode('utf-8')

    salt = gensalt()
    return hashpw(hashed, salt)
