#!/usr/bin/env python3
"""
Implements a session auth
"""
from api.v1.auth.auth import Auth
from uuid import uuid4


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
