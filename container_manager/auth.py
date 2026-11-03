import httpx
from fastapi import Request

from .errors import Failure


class Auth:
    def __init__(self, transport=None):
        self.transport = transport

    def __call__(self, request: Request) -> str:
        header = request.headers.get("authorization", "")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            raise Failure("unauthenticated", 401)
        try:
            with httpx.Client(
                timeout=httpx.Timeout(3, connect=1),
                follow_redirects=False,
                transport=self.transport,
                trust_env=False,
            ) as client:
                response = client.get(
                    "http://auth:8000/api/user/",
                    headers={"Authorization": "Bearer " + parts[1]},
                )
            if response.status_code in {401, 403}:
                raise Failure("unauthenticated", 401)
            if response.status_code != 200:
                raise Failure("auth_unavailable")
            user = response.json()
            # Auth's self-filtered DRF /api/user/ route returns a list, not
            # a detail object. Never select one identity out of an ambiguous
            # response; malformed/empty/multiple-user lists fail closed.
            if isinstance(user, list):
                if len(user) != 1:
                    raise Failure("auth_unavailable")
                user = user[0]
            if not isinstance(user, dict):
                raise Failure("auth_unavailable")
            services = user.get("services")
            # Hosting has a service-specific administrator grant. Never infer
            # it from staff/superuser, a portal tile or stale JWT role claims.
            if (
                user.get("is_active") is not True
                or not isinstance(services, dict)
                or services.get("hosting") is not True
            ):
                raise Failure("administrator_required", 403)
            actor = user.get("id")
            if not isinstance(actor, (str, int)) or isinstance(actor, bool):
                raise Failure("auth_unavailable")
            # Bounded opaque actor ID, not user-supplied token/email/profile fields.
            return str(actor)[:128]
        except (httpx.HTTPError, ValueError, TypeError):
            raise Failure("auth_unavailable") from None
