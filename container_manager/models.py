import re
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .errors import Failure

# Infrastructure remains reserved even when currently not listening.
RESERVED = {
    2222,
    2379,
    2380,
    5000,
    5187,
    6443,
    6444,
    8090,
    8472,
    9443,
    9444,
    9445,
    10010,
    10248,
    10249,
    10250,
    10256,
    10257,
    10258,
    10259,
}
PortNumber = Annotated[int, Field(strict=True, ge=1024, le=65535)]


def canonical_id(value: str) -> str:
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise Failure("invalid_id", 422) from None
    return value


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Check(Model):
    protocol: Literal["tcp", "udp"]
    public_port: PortNumber


class Port(Check):
    target_port: Annotated[int, Field(strict=True, ge=1, le=65535)]


class Password(Model):
    root_password: SecretStr = Field(min_length=16, max_length=256)

    @field_validator("root_password")
    @classmethod
    def password_lines(cls, value: SecretStr) -> SecretStr:
        if any(c in value.get_secret_value() for c in "\r\n\x00:"):
            raise ValueError("invalid_password")
        return value


class Create(Password):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    domain: str
    cpu: Annotated[int, Field(strict=True, ge=1, le=4)]
    memory_gb: Decimal = Field(gt=0, le=16, max_digits=8, decimal_places=3)
    ports: list[Port] = Field(default_factory=list, max_length=64)

    @field_validator("memory_gb", mode="before")
    @classmethod
    def memory_type(cls, value):
        if isinstance(value, bool):
            raise ValueError("invalid_memory")
        return value

    @field_validator("domain")
    @classmethod
    def domain_syntax(cls, value: str) -> str:
        if len(value) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("invalid_domain")
        return value


def validate_port(port: Check, configured: set[int]) -> None:
    if port.public_port in RESERVED | configured or 30000 <= port.public_port <= 32767:
        raise Failure("reserved_port", 409)
