#!/usr/bin/env python3
"""The UserSession module
"""
from models.base import Base


class UserSession(Base):
    """The UserSession class
    """
    def __init__(self, *args: list, **kwargs: dict):
        """initialize the UserSession instance
        """
        super().__init__(*args, **kwargs)
        self.session_id = kwargs.get('session_id')
        self.user_id = kwargs.get('user_id')
