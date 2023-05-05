#!/usr/bin/env python3
"""SessionExpAuth module
"""
from api.v1.auth.session_auth import SessionAuth
import os
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """"The SessionExpAuth class
    """
    def __init__(self):
        """initialize SessionExpAuth instance
        """
        super().__init__()

    try:
        session_duration = int(os.getenv("SESSION_DURATION"))
    except Exception:
        session_duration = 0

    def create_session(self, user_id=None):
        """Create a Session ID
        """
        sessId = super().create_session(user_id)
        if sessId:
            session_dictionary = {}
            session_dictionary['user_id'] = user_id
            session_dictionary['created_at'] = datetime.now()
            self.user_id_by_session_id[sessId] = session_dictionary
            return sessId
        return None

    def user_id_for_session_id(self, session_id=None):
        """returns user ID for current session
        """
        if session_id is None:
            return None
        elif session_id not in self.user_id_by_session_id.keys():
            return None
        else:
            sessDict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return sessDict['user_id']
            elif 'created_at' not in sessDict.keys():
                return None
            else:
                sessDurSecs = timedelta(seconds=self.session_duration)
                totDur = sessDict['created_at'] + sessDurSecs
                curTime = datetime.now()
                if curTime > totDur:
                    return None
                else:
                    return sessDict['user_id']
