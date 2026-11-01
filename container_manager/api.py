from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .auth import Auth
from .errors import Failure
from .models import Check, Create, Password, Port


def app_for(controller, auth=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        controller.schedule_reconcile()
        yield

    app = FastAPI(
        lifespan=lifespan,
        title="Ubuntu container manager",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
    )
    authorize = auth or Auth()

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        try:
            request.state.actor = await run_in_threadpool(authorize, request)
        except Failure as error:
            return JSONResponse(
                {"detail": {"code": error.code, "message": error.code}},
                status_code=error.status,
                headers={"Cache-Control": "no-store"},
            )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Failure)
    async def failure(request, error):
        return JSONResponse(
            {"detail": {"code": error.code, "message": error.code}},
            status_code=error.status,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid(request, error):
        # Never serialize error.errors(): input/ctx/body may contain root_password.
        return JSONResponse(
            {
                "detail": {
                    "code": "invalid_request",
                    "message": "Request validation failed",
                }
            },
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def unexpected(request, error):
        return JSONResponse(
            {"detail": {"code": "operation_failed", "message": "Operation failed"}},
            status_code=503,
        )

    prefix = "/api/containers"

    @app.get(prefix + "/capabilities")
    def capabilities():
        return {
            "administrator": True,
            "node": "gamma",
            "max_cpu": 4,
            "max_memory_gb": 16,
            "domain_suffix": controller.config.domain_suffix,
            "image": "Ubuntu 24.04 LTS",
            "disk_quota": False,
            "home_separate": True,
            "root_persistence": "full",
            "external_ingress_ready": any(
                controller.config.public_port_ranges.values()
            ),
            "public_port_ranges": controller.config.public_port_ranges,
            "aggregate_budget": {
                "cpu": controller.config.pool_cpu,
                "memory_gb": controller.config.pool_memory_gb,
            },
        }

    @app.get(prefix + "/")
    def instances():
        controller.schedule_reconcile()
        return {"instances": controller.store.instances()}

    @app.post(prefix + "/")
    def create(
        body: Create,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        instance, work = controller.prepare_create(
            body, request.state.actor, idempotency_key
        )
        if work is not None:
            controller.enqueue_create(work)
        return instance

    @app.post(prefix + "/ports/check")
    def check(body: Check):
        result = controller.check(body)
        return JSONResponse(
            result,
            status_code=(
                503
                if any(c["status"] == "unknown" for c in result["checks"].values())
                else 200
            ),
        )

    @app.post(prefix + "/{resource}/start")
    def start(
        resource: str,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        return controller.power(resource, True, request.state.actor, idempotency_key)

    @app.post(prefix + "/{resource}/stop")
    def stop(
        resource: str,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        return controller.power(resource, False, request.state.actor, idempotency_key)

    @app.post(prefix + "/{resource}/password")
    def password(
        resource: str,
        body: Password,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        return controller.password(
            resource,
            body.root_password.get_secret_value(),
            request.state.actor,
            idempotency_key,
        )

    @app.post(prefix + "/{resource}/ports")
    def add_port(
        resource: str,
        body: Port,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        return controller.add_port(resource, body, request.state.actor, idempotency_key)

    @app.delete(prefix + "/{resource}/ports/{port_id}")
    def remove_port(
        resource: str,
        port_id: str,
        request: Request,
        idempotency_key: str | None = Header(default=None),
    ):
        return controller.remove_port(
            resource, port_id, request.state.actor, idempotency_key
        )

    return app
