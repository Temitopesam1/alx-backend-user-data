#!/usr/bin/env python3
"""auth module
"""
from uuid import uuid4
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """method to hash password
    """
    hshd_pswd = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hshd_pswd

def _generate_uuid() -> str:
    """A method to generate random ID
    """
    return str(uuid4())

from user import User


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """A method to register user
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
           hshpw =  _hash_password(password)
           usrObj = self._db.add_user(email, hshpw)
           return usrObj
        raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """A method to validate login
        """
        try:
            usr = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode(), usr.hashed_password):
                return True
            else:
                return False
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """A method to create session
        """
        try:
            usr = self._db.find_user_by(email=email)
            sessId = _generate_uuid()
            self._db._session.query(User).update(
                    {'session_id': sessId},
                    synchronize_session=False)
            return sessId
        except Exception:
            return None
        return None
