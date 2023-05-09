#!/usr/bin/env python3
"""auth module
"""
from uuid import uuid4
from typing import Union
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from user import User


def _hash_password(password: str) -> bytes:
    """method to hash password
    """
    hshd_pswd = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hshd_pswd


def _generate_uuid() -> str:
    """A method to generate random ID
    """
    return str(uuid4())


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
            hshpw = _hash_password(password)
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

    def create_session(self, email: str) -> Union[str, None]:
        """A method to create session
        """
        try:
            self._db.find_user_by(email=email)
            sessId = _generate_uuid()
            self._db._session.query(User).update(
                    {'session_id': sessId},
                    synchronize_session=False)
            return sessId
        except Exception:
            return None
        return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """A method to get user from session ID
        """
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """A method to destroy a user session
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """A method to reset password token
        """
        try:
            usr = self._db.find_user_by(email=email)
            resetToken = _generate_uuid()
            self._db.update_user(usr.id, reset_token=resetToken)
            return resetToken
        except Exception:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """A method to update user password
        """
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
            hshpw = _hash_password(password)
            self._db.update_user(usr.id, hashed_password=hshpw)
            self._db.update_user(usr.id, reset_token=None)
            return None
        except Exception:
            raise ValueError()
