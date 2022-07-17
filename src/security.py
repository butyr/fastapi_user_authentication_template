from datetime import datetime, timedelta
from typing import Union

from secrets import token_bytes
from base64 import b64encode
from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from schemas import ProcssedStuff


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

db_data = {
    "johndoe": {
        "user_id": "johndoe",
        "hashed_password": "$2b$12$oAN9XRwhA3w4wAu4pCQ6DelBS2dxXMqHC0HGkP0YklKzmuAybs.ue",
        "salt": "FIxFUpNcPVr2BCwBTe5LNqhTzbpAtsS40fodLwfp/IQ=",
    }
}


class Authenticator:
    def __init__(self, hash_scheme: str = "bcrypt"):
        self.pwd_context = CryptContext(schemes=[hash_scheme], deprecated="auto")

        self.credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        self.username_password_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    def authenticate_user(self, user_id: str, password: str):
        user_data = self._get_user_data(user_id)

        if not user_data:
            raise self.username_password_exception

        if not self._verify_password(
            password,
            user_data["hashed_password"],
            user_data["salt"],
        ):
            raise self.username_password_exception

        return user_data["user_id"]

    def _get_user_data(self, user_id: str):
        return db_data[user_id]

    def _verify_password(self, plain_password: str, hashed_password: str, salt: str):
        return self.pwd_context.verify(salt + plain_password, hashed_password)

    def create_access_data(self, user_id: str, password: str):
        salt = self._create_salt()
        hashed_password = self._create_password_hash(password, salt)
        self._write_user_data(user_id, hashed_password, salt)

    def _create_salt(self):
        return b64encode(token_bytes(32)).decode()

    def _create_password_hash(self, password, salt):
        return self.pwd_context.hash(salt + password)

    def _write_user_data(self, user_id: str, hashed_password: str, salt: str):
        db_data[user_id] = {
            "user_id": user_id,
            "hashed_password": hashed_password,
            "salt": salt,
        }

    def create_access_token(
        self, data: dict, expires_delta: Union[timedelta, None] = None
    ):
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        return encoded_jwt

    def verify_access_token(self, token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")

            if username is None:
                raise self.credentials_exception

            return ProcssedStuff(stuff=username)

        except JWTError:
            raise self.credentials_exception


if __name__ == "__main__":
    auth = Authenticator()
    salt = auth._create_salt()
    hashed_password = auth._create_password_hash("secret", salt)

    print(salt, hashed_password)
