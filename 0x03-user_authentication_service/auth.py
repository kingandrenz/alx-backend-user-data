#!/usr/bin/env python3
""" user authentication module
"""

from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from typing import Union

import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.hashpw

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the input password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


def _generate_uuid() -> str:
    """ generates a string representation of UUID
    """
    new_uuid = uuid.uuid4()

    return str(new_uuid)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ register new user if the email does not exit in dattabase.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")

        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)

            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """  validate password, return true if password match
        """
        try:
            user = self._db.find_user_by(email=email)

            if user and bcrypt.checkpw(
                    password.encode("utf-8"), user.hashed_password):

                return True

            return False
        except NoResultFound:

            return False

    def create_session(self, email: str) -> str:
        """ returns created session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)

            return session_id

        except NoResultFound:

            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ return User on None if user is not found
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:

            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session associated with a given user.
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """ find user corresponding to emaill and generate UUId
            and update user's with reset_token in the database
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = self._generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)

            return reset_token

        except NoResultFound:
            raise ValueError
