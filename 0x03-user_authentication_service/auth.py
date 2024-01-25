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

    def destroy_session(self, user_id: int) -> None:
        """destroys a user session
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """gets a reset password token for the user
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)

            return reset_token

        except (NoResultFound, InvalidRequestError):
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user password given a reset token and the new password
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            password = _hash_password(password)
            self._db.update_user(user.id,
                                 reset_token=None,
                                 hashed_password=password)

        except (NoResultFound, InvalidRequestError):
            raise ValueError


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
