import hashlib
from typing import Optional

from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED

from app_distribution_server.config import USER_CREDENTIALS_PATH


class Credentials(BaseModel):
    credentials: dict[str, str] | None = None


CREDENTIALS = None


if USER_CREDENTIALS_PATH:
    with open(USER_CREDENTIALS_PATH) as f:
        CREDENTIALS = Credentials.model_validate_json(f.read())


class BasicAuth(HTTPBasic):
    async def __call__(self, request: Request) -> Optional[HTTPBasicCredentials]:
        credendials = await super().__call__(request)
        if not credendials:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Basic"},
            )
        if not CREDENTIALS or not CREDENTIALS.credentials:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Basic"},
            )
        password_hash = CREDENTIALS.credentials.get(credendials.username)
        if password_hash is None:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Basic"},
            )
        if password_hash != hashlib.sha256(credendials.password.encode("utf-8")).hexdigest():
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credendials
