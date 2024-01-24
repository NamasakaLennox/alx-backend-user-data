#!/usr/bin/env python3
"""Takes a password string and returns a hashed byte string
"""
from bcrypt import gensalt, hashpw


def _hash_password(password: str):
    """generates a hashed password using bcrypt
    """
    hashed = password.encode('utf-8')

    salt = gensalt()
    return hashpw(hashed, salt)
