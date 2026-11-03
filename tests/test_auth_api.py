import json
import time
import threading
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from container_manager.api import app_for
from container_manager.auth import Auth


def client(controller, response=None):
    def handler(request):
        assert str(request.url) == "http://auth:8000/api/user/"
        assert request.headers["authorization"] == "Bearer token"
        return response or httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": True,
                    "is_staff": True,
                    "services": {"hosting": True},
                }
            ],
        )

    return TestClient(
        app_for(controller, Auth(httpx.MockTransport(handler))),
        raise_server_exceptions=False,
    )


AUTH = {"Authorization": "Bearer token"}


@pytest.mark.parametrize(
    "user",
    [
        {},
        {"is_active": True},
        {"is_staff": True},
        {"is_staff": "true", "is_active": True},
        {"is_staff": 1, "is_active": True},
        {"is_staff": True, "is_active": "true"},
        {"is_staff": True, "is_active": False},
        {"is_staff": False, "is_active": True},
    ],
)
def test_exact_live_admin(controller, user):
    api = client(controller, httpx.Response(200, json={"id": 1, **user}))
    assert api.get("/api/containers/", headers=AUTH).status_code == 403


@pytest.mark.parametrize("code", [301, 302, 307, 404, 500, 503])
def test_auth_outage_redirects_denied(controller, code):
    api = client(
        controller, httpx.Response(code, headers={"Location": "http://evil.invalid"})
    )
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 503


@pytest.mark.parametrize(
    "payload", [[], [None], [True], [[]], [1], ["admin"], [{}, {}]]
)
def test_ambiguous_or_malformed_user_list_fails_closed(controller, payload):
    api = client(controller, httpx.Response(200, json=payload))
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 503


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"is_active": True},
        {"is_staff": True},
        {"is_active": True, "is_staff": "true"},
        {"is_active": True, "is_staff": 1},
        {"is_active": "true", "is_staff": True},
        {"is_active": False, "is_staff": True},
        {"is_active": True, "is_staff": False},
        {"is_active": True, "is_staff": None},
    ],
)
def test_missing_hosting_grant_fails_closed_even_with_legacy_staff_flags(
    controller, fields
):
    api = client(controller, httpx.Response(200, json=[{"id": 1, **fields}]))
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 403


def test_real_profile_list_revocation_with_same_bearer_has_no_positive_cache(
    controller,
):
    calls = []

    def handler(request):
        assert request.headers["authorization"] == "Bearer token"
        calls.append(1)
        return httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": True,
                    "is_staff": True,
                    "services": {"hosting": len(calls) == 1},
                }
            ],
        )

    api = TestClient(app_for(controller, Auth(httpx.MockTransport(handler))))
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 200
    assert api.get("/api/containers/", headers=AUTH).status_code == 403
    assert len(calls) == 2


def test_multiple_users_never_selects_an_administrator(controller):
    user = {"id": 1, "is_active": True, "is_staff": True}
    api = client(controller, httpx.Response(200, json=[user, {**user, "id": 2}]))
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 503


@pytest.mark.parametrize("staff", [False, True])
def test_explicit_hosting_grant_not_staff_is_the_authority(controller, staff):
    api = client(
        controller,
        httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": True,
                    "is_staff": staff,
                    "services": {"hosting": True},
                }
            ],
        ),
    )
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 200


@pytest.mark.parametrize("grant", [None, False, "true", 1, {"enabled": True}])
def test_staff_or_superuser_never_bypasses_missing_exact_hosting_grant(
    controller, grant
):
    api = client(
        controller,
        httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": True,
                    "is_staff": True,
                    "is_superuser": True,
                    "services": {"hosting": grant},
                }
            ],
        ),
    )
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 403


@pytest.mark.parametrize("active", [None, False, "true", 1, {}, []])
def test_hosting_grant_still_requires_exact_active_boolean(controller, active):
    api = client(
        controller,
        httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": active,
                    "services": {"hosting": True},
                }
            ],
        ),
    )
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 403


@pytest.mark.parametrize("services", [None, True, [], "hosting", {}])
def test_malformed_service_map_never_falls_back_to_staff(controller, services):
    api = client(
        controller,
        httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "is_active": True,
                    "is_staff": True,
                    "services": services,
                }
            ],
        ),
    )
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 403


def test_cookie_only_denied(controller):
    api = client(controller)
    api.cookies.set("access_token", "token")
    assert api.get("/api/containers/").status_code == 401


def test_no_positive_cache(controller):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(
            200,
            json={
                "id": 1,
                "is_staff": True,
                "is_active": True,
                "services": {"hosting": len(calls) == 1},
            },
        )

    api = TestClient(app_for(controller, Auth(httpx.MockTransport(handler))))
    assert api.get("/api/containers/capabilities", headers=AUTH).status_code == 200
    assert api.get("/api/containers/", headers=AUTH).status_code == 403
    assert len(calls) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("cpu", True),
        ("cpu", 5),
        ("memory_gb", True),
        ("memory_gb", 16.001),
        ("name", "x" * 33),
        ("domain", "evil.ru"),
        ("root_password", "secret\ninjected"),
        ("image", "https://evil.invalid"),
    ],
)
def test_validation_secret_redaction(controller, body, field, value, caplog):
    body[field] = value
    secret = body["root_password"]
    response = client(controller).post("/api/containers/", json=body, headers=AUTH)
    assert response.status_code == 422
    assert secret not in response.text
    assert secret not in caplog.text
    assert secret.encode() not in open(controller.store.path, "rb").read()


def test_malformed_json_redacts(controller):
    response = client(controller).post(
        "/api/containers/",
        content='{"root_password":"SECRETOOPS',
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert "SECRETOOPS" not in response.text


def test_api_contract(controller, body):
    api = client(controller)
    caps = api.get("/api/containers/capabilities", headers=AUTH).json()
    assert caps["home_separate"] and caps["root_persistence"] == "full"
    key = str(uuid4())
    headers = {**AUTH, "Idempotency-Key": key}
    result = api.post("/api/containers/", json=body, headers=headers)
    assert result.status_code == 200, result.text
    instance = result.json()
    assert instance["status"] == "creating"
    assert set(instance["ports"][0]) == {
        "id",
        "protocol",
        "public_port",
        "target_port",
        "status",
        "reachability",
    }
    assert "password" not in result.text
    assert (
        api.post("/api/containers/", json=body, headers=headers).json()["id"]
        == instance["id"]
    )
    resource = instance["id"]
    deadline = time.monotonic() + 2
    while (
        controller.store.instance(resource)["status"] == "creating"
        and time.monotonic() < deadline
    ):
        time.sleep(0.005)
    assert controller.store.instance(resource)["status"] == "running"
    assert api.post(
        f"/api/containers/{resource}/password",
        json={"root_password": body["root_password"]},
        headers=AUTH,
    ).json() == {"changed": True}
    assert (
        api.post(f"/api/containers/{resource}/stop", headers=AUTH).json()["status"]
        == "stopped"
    )
    assert (
        api.post(f"/api/containers/{resource}/start", headers=AUTH).json()["status"]
        == "running"
    )
    assert api.delete(f"/api/containers/{resource}", headers=AUTH).status_code == 404
    assert (
        api.get("/api/containers/", headers=AUTH).json()["instances"][0]["id"]
        == resource
    )
    assert api.post("/api/containers/NOT-A-UUID/start", headers=AUTH).status_code == 422


def test_check_contract_unknown_never_free(controller):
    api = client(controller)
    body = {"protocol": "tcp", "public_port": 2223}
    result = api.post("/api/containers/ports/check", json=body, headers=AUTH)
    assert result.json() == {
        "available": True,
        "reason": "free",
        "checks": {
            host: {"status": "free", "reason": "free"}
            for host in ("alpha", "gamma", "registry")
        },
    }
    controller.node.fail = "inspect"
    result = api.post("/api/containers/ports/check", json=body, headers=AUTH)
    assert result.status_code == 503
    assert result.json()["available"] is False
    assert result.json()["checks"]["gamma"]["status"] == "unknown"


def test_auth_timeout(controller):
    def handler(request):
        raise httpx.ReadTimeout("sensitive exception")

    api = TestClient(app_for(controller, Auth(httpx.MockTransport(handler))))
    response = api.get("/api/containers/", headers=AUTH)
    assert response.status_code == 503
    assert "sensitive" not in response.text


def test_http_create_does_not_wait_for_bootstrap(controller, body):
    entered, release = threading.Event(), threading.Event()

    def slow_create(*args):
        entered.set()
        release.wait(5)

    controller.node.create = slow_create
    api = client(controller)
    start = time.monotonic()
    try:
        response = api.post("/api/containers/", json=body, headers=AUTH)
        assert response.status_code == 200
        assert response.json()["status"] == "creating"
        assert time.monotonic() - start < 1
        assert entered.wait(1)
        assert controller.store.instance(response.json()["id"])["status"] == "creating"
    finally:
        release.set()
        controller.create_workers.shutdown(wait=True)


@pytest.mark.parametrize(
    "password", ["A" * 15, "A" * 257, "A" * 15 + ":", "A" * 15 + "\n"]
)
def test_password_contract_minimum16_and_colon_rejection(controller, body, password):
    body["root_password"] = password
    response = client(controller).post("/api/containers/", json=body, headers=AUTH)
    assert response.status_code == 422
    assert password not in response.text
    assert not controller.store.instances()


@pytest.mark.parametrize("length", [16, 256])
def test_password_contract_accepts_valid_boundary_lengths(controller, body, length):
    from container_manager.models import Password

    assert (
        Password(root_password="A" * length).root_password.get_secret_value()
        == "A" * length
    )
