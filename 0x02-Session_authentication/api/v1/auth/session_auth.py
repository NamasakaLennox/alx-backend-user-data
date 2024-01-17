#!/usr/bin/env python3
"""
Implements a session auth
"""
from api.v1.auth.auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """a class that manages a session auth
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a new session and generates session id
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        ses_id = str(uuid4())
        self.user_id_by_session_id[ses_id] = user_id

        return ses_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Extracts a user id from the session id
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """returns a user instance based on the cookie value
        """
        cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie)

        return User.get(user_id)
