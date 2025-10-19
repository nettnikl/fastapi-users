from typing import Generic, Optional

import jwt

from fastapi_users import exceptions, models
from fastapi_users.authentication.strategy.base import (
    Strategy,
    StrategyDestroyNotSupportedError,
    StrategyRefresh,
)
from fastapi_users.jwt import SecretType, decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager


class JWTStrategyDestroyNotSupportedError(StrategyDestroyNotSupportedError):
    def __init__(self) -> None:
        message = "A JWT can't be invalidated: it's valid until it expires."
        super().__init__(message)


class JWTStrategy(Strategy[models.UP, models.ID], Generic[models.UP, models.ID]):
    def __init__(
        self,
        secret: SecretType,
        lifetime_seconds: Optional[int],
        token_audience: list[str] = ["fastapi-users:auth"],
        algorithm: str = "HS256",
        public_key: Optional[SecretType] = None,
    ):
        self.secret = secret
        self.lifetime_seconds = lifetime_seconds
        self.token_audience = token_audience
        self.algorithm = algorithm
        self.public_key = public_key

    @property
    def encode_key(self) -> SecretType:
        return self.secret

    @property
    def decode_key(self) -> SecretType:
        return self.public_key or self.secret

    async def read_token(
        self, token: Optional[str], user_manager: BaseUserManager[models.UP, models.ID]
    ) -> Optional[models.UP]:
        if token is None:
            return None

        try:
            data = decode_jwt(
                token, self.decode_key, self.token_audience, algorithms=[self.algorithm]
            )
            user_id = data.get("sub")
            if user_id is None:
                return None
        except jwt.PyJWTError:
            return None

        try:
            parsed_id = user_manager.parse_id(user_id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID):
            return None

    async def write_token(self, user: models.UP) -> str:
        data = {"sub": str(user.id), "aud": self.token_audience}
        return generate_jwt(
            data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm
        )

    async def destroy_token(self, token: str, user: models.UP) -> None:
        raise JWTStrategyDestroyNotSupportedError()


class JWTRefreshStrategy(StrategyRefresh[models.UP, models.ID], Generic[models.UP, models.ID]):
    def __init__(
        self,
        secret: SecretType,
        # No access token blacklisting is in this implementation, so you need to keep lifetime of access tokens short
        lifetime_seconds: int | None = 60 * 5,
        refresh_lifetime_seconds: int | None = 60 * 60 * 24 * 7,
        token_audience: list[str] = ["fastapi-users:auth"],
        algorithm: str = "HS256",
        public_key: SecretType | None = None,
    ):
        self.secret = secret
        self.lifetime_seconds = lifetime_seconds
        self.refresh_lifetime_seconds = refresh_lifetime_seconds
        self.token_audience = token_audience
        self.algorithm = algorithm
        self.public_key = public_key

    @property
    def encode_key(self) -> SecretType:
        return self.secret

    @property
    def decode_key(self) -> SecretType:
        return self.public_key or self.secret

    async def read_token(
        self, token: str | None, user_manager: BaseUserManager[models.UP, models.ID]
    ) -> models.UP | None:
        if token is None:
            return None

        try:
            data = decode_jwt(token, self.decode_key, self.token_audience, algorithms=[self.algorithm])
            if data.get("type") != "access":
                print("falsche typ??", data.get("type"))
                return None
            user_id = data.get("sub")
            if user_id is None:
                return None
        except jwt.PyJWTError:
            return None

        try:
            parsed_id = user_manager.parse_id(user_id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID):
            return None

    async def write_token(self, user: models.UP) -> tuple[str, str]:
        access_data = {
            "sub": str(user.id),
            "aud": self.token_audience,
            "type": "access",
        }
        access_token = generate_jwt(access_data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm)

        refresh_data = {
            "sub": str(user.id),
            "aud": self.token_audience,
            "type": "refresh",
        }
        refresh_token = generate_jwt(
            refresh_data, self.encode_key, self.refresh_lifetime_seconds, algorithm=self.algorithm
        )

        return access_token, refresh_token

    async def read_token_by_refresh(
        self, refresh_token: str | None, user_manager: BaseUserManager[models.UP, models.ID]
    ) -> models.UP | None:
        if refresh_token is None:
            return None
        try:
            data = decode_jwt(refresh_token, self.decode_key, self.token_audience, algorithms=[self.algorithm])
            if data.get("type") != "refresh":
                return None
            user_id = data.get("sub")
            if user_id is None:
                return None
        except jwt.PyJWTError:
            return None

        try:
            parsed_id = user_manager.parse_id(user_id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID):
            return None

    async def destroy_token(self, token: str, user: models.UP) -> None:
        raise JWTStrategyDestroyNotSupportedError()

    async def destroy_token_by_refresh(self, refresh_token: str | None, user: models.UP) -> None:
        pass  # A JWT can't be invalidated: it's valid until it expires.
