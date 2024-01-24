#!/usr/bin/env python3
"""Takes a password string and returns a hashed byte string
"""
from bcrypt import checkpw, gensalt, hashpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from uuid import uuid4
from typing import Union


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

    def create_session(self, email: str) -> str:
        """creates a session and returns session id
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id

        except (NoResultFound, InvalidRequestError):
            pass

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """gets a user from the session using session id
        """
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user
            except (NoResultFound, InvalidRequestError):
                pass


def _hash_password(password: str) -> bytes:
    """generates a hashed password using bcrypt
    """
    hashed = password.encode('utf-8')

    salt = gensalt()
    return hashpw(hashed, salt)


def _generate_uuid() -> str:
    """generates a uuid
    """
    return str(uuid4())
