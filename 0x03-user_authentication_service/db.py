#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """method to add user to the User model
        """
        try:
            usrObj = User(email=email, hashed_password=hashed_password)
            self._session.add(usrObj)
            self._session.commit()
        except Exception:
            self._session.rollback()
            usrObj = None
        return usrObj

    def find_user_by(self, **kwargs) -> User:
        """method to find user by keyword argument
        """
#         for key, val in kwargs.items():
#             if key not in User.__dict__.keys():
#                 raise InvalidRequestError()
#             else:
#                 attr = getattr(User, key)
#                 result = self._session.query(User).filter(attr == val).first()
#                 if result is None:
#                     raise NoResultFound()
#             return result
        fields, values = [], []
        for key, value in kwargs.items():
            if hasattr(User, key):
                fields.append(getattr(User, key))
                values.append(value)
            else:
                raise InvalidRequestError()
        result = self._session.query(User).filter(
            tuple_(*fields).in_([tuple(values)])
        ).first()
        if result is None:
            raise NoResultFound()
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """method to update user by id
        """
        usr = self.find_user_by(id=user_id)
        for key, val in kwargs.items():
            if not hasattr(usr, key):
                raise ValueError()
            else:
                attr = getattr(User, key)
                self._session.query(User).update(
                        {attr: val},
                        synchronize_session=False)
                self._session.commit()
                return None
#         user = self.find_user_by(id=user_id)
#         if user is None:
#             return
#         update_source = {}
#         for key, value in kwargs.items():
#             if hasattr(User, key):
#                 update_source[getattr(User, key)] = value
#             else:
#                 raise ValueError()
#         self._session.query(User).filter(User.id == user_id).update(
#             update_source,
#             synchronize_session=False,
#         )
#         self._session.commit()
