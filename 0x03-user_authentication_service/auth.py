#!/usr/bin/env python3
""" user authentication module
"""

from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound

import bcrypt


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
