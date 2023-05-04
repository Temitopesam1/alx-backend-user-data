#!/usr/bin/env python3
"""session_auth module
"""
from api.v1.auth.auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """session authentication class
    """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """A method to create session
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        self.session_id = str(uuid4())
        self.user_id_by_session_id[self.session_id] = user_id
        return self.session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns user ID based on session ID
        """
        if session_id is None or not isinstance(session_id,str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> User:
        """A method that returns a User instance based on a cookie value
        """
        sessionId = self.session_cookie(request)
        userId = self.user_id_for_session_id(sessionId)
        return User.get(userId)
