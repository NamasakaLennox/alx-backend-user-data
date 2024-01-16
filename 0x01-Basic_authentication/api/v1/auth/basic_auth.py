#!/usr/bin/env python3
"""Basic Authentication
"""
from api.v1.auth.auth import Auth


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
