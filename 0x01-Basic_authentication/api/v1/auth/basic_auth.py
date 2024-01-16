#!/usr/bin/env python3
"""Basic Authentication
"""
from api.v1.auth.auth import Auth
from base64 import b64decode, decode
from binascii import Error
import base64


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

    def decode_base64_authorization_header(self, b64_auth_header: str) -> str:
        """ Returns decode base64 authorization """
        if b64_auth_header is None or not isinstance(b64_auth_header, str):
            return None
        try:
            b64 = base64.b64decode(b64_auth_header)
            b64_decode = b64.decode('utf-8')
        except Exception:
            return None
        return b64_decode
