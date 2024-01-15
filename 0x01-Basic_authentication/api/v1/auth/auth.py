#!/usr/bin/python3
"""Manages API Authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """a class to manage api authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """check if path requires auth
        """
        if path is None or excluded_paths is None:
            return True
        path2 = path + '/'

        if path in excluded_paths or path2 in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """sets the auth header
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """checks the current user
        """
        return None
