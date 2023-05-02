#!/usr/bin/env python3
"""
Auth module for the API
"""
from flask import request
from typing import List, TypeVar


class Auth():
    """Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """method to enforce auth
        """
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """method for auth_header
        """
        if request:
            return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """method that returns user
        """
        return None
