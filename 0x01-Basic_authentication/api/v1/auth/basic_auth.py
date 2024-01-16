#!/usr/bin/env python3
"""Basic Authentication
"""
from api.v1.auth.auth import Auth
from base64 import b64decode
from binascii import Error


class BasicAuth(Auth):
    """Handles basic authentication
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for basic authentication
        """
        if authorization_header is None or type(authorization_header) != str:
            return None
        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header:
                                           str) -> str:
        """decodes value of Base64 string
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) != str:
            return None

        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Error:
            return None
