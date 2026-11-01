from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import grpc
from pydantic import ValidationError

from .errors import Failure
from .models import Check, validate_port
from .proto import control_pb2 as pb
from .proto import control_pb2_grpc as wire


def port_spec(request) -> dict:
    return {
        "id": request.id,
        "instance_id": request.instance_id,
        "protocol": request.protocol,
        "public_port": request.public_port,
        "target_port": request.target_port,
    }


class Service(wire.NodeServicer, wire.RelayServicer):
    def __init__(self, backend, config, inspector):
        self.backend, self.config, self.inspector = backend, config, inspector

    def invoke(self, context, callback):
        auth = context.auth_context()
        identities = auth.get("x509_common_name", [])
        if auth.get("transport_security_type") != [b"ssl"] or identities != [
            self.config.controller_cn.encode()
        ]:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "controller_certificate_required"
            )
        try:
            return callback()
        except Failure as error:
            status = {
                409: grpc.StatusCode.ALREADY_EXISTS,
                404: grpc.StatusCode.NOT_FOUND,
                422: grpc.StatusCode.INVALID_ARGUMENT,
            }.get(error.status, grpc.StatusCode.UNAVAILABLE)
            context.abort(status, error.code)
        except ValidationError:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid_request")
        except Exception:
            context.abort(grpc.StatusCode.UNAVAILABLE, "agent_operation_failed")

    def InstanceStatus(self, request, context):
        return self.invoke(
            context, lambda: pb.State(state=self.backend.instance_status(request.id))
        )

    def PortStatus(self, request, context):
        return self.invoke(
            context,
            lambda: pb.State(state=self.backend.port_status(port_spec(request))),
        )

    def Inspect(self, request, context):
        def inspect():
            port = Check(protocol=request.protocol, public_port=request.public_port)
            validate_port(port, set(self.config.reserved_ports))
            try:
                self.inspector.check(port.protocol, port.public_port)
                return pb.Inspection(available=True, reason="free")
            except Failure as error:
                if error.status == 409:
                    return pb.Inspection(available=False, reason=error.code)
                raise

        return self.invoke(context, inspect)

    def Create(self, request, context):
        return self.invoke(
            context,
            lambda: self.empty(
                self.backend.create,
                request.id,
                request.cpu,
                request.memory_bytes,
                request.root_password,
            ),
        )

    def Power(self, request, context):
        return self.invoke(
            context, lambda: self.empty(self.backend.power, request.id, request.start)
        )

    def Password(self, request, context):
        return self.invoke(
            context,
            lambda: self.empty(
                self.backend.password, request.id, request.root_password
            ),
        )

    def Publish(self, request, context):
        return self.invoke(
            context, lambda: self.empty(self.backend.publish, port_spec(request))
        )

    def Reserve(self, request, context):
        return self.invoke(
            context, lambda: self.empty(self.backend.reserve, port_spec(request))
        )

    def Activate(self, request, context):
        return self.invoke(
            context, lambda: self.empty(self.backend.activate, port_spec(request))
        )

    def Remove(self, request, context):
        return self.invoke(
            context, lambda: self.empty(self.backend.remove, port_spec(request))
        )

    @staticmethod
    def empty(function, *args):
        function(*args)
        return pb.Empty()


def server(config, backend, inspector):
    credentials = grpc.ssl_server_credentials(
        [(Path(config.key).read_bytes(), Path(config.cert).read_bytes())],
        root_certificates=Path(config.ca).read_bytes(),
        require_client_auth=True,
    )
    host = grpc.server(
        ThreadPoolExecutor(max_workers=8),
        maximum_concurrent_rpcs=32,
        options=[
            ("grpc.max_receive_message_length", 65536),
            ("grpc.max_send_message_length", 65536),
        ],
    )
    service = Service(backend, config, inspector)
    if config.mode == "node":
        wire.add_NodeServicer_to_server(service, host)
    else:
        wire.add_RelayServicer_to_server(service, host)
    if not host.add_secure_port(config.bind, credentials):
        raise Failure("grpc_bind_failed")
    return host


class Remote:
    def __init__(self, config, kind: str):
        credentials = grpc.ssl_channel_credentials(
            root_certificates=Path(config.ca).read_bytes(),
            private_key=Path(config.key).read_bytes(),
            certificate_chain=Path(config.cert).read_bytes(),
        )
        address = config.node_address if kind == "node" else config.relay_address
        identity = config.node_identity if kind == "node" else config.relay_identity
        # Override is operator-pinned expected certificate identity, NOT request data.
        self.channel = grpc.secure_channel(
            address,
            credentials,
            options=[
                ("grpc.ssl_target_name_override", identity),
                ("grpc.max_receive_message_length", 65536),
                ("grpc.max_send_message_length", 65536),
            ],
        )
        self.stub = (
            wire.NodeStub(self.channel)
            if kind == "node"
            else wire.RelayStub(self.channel)
        )

    def call(self, method: str, request):
        try:
            return getattr(self.stub, method)(
                request, timeout=180 if method == "Create" else 15, wait_for_ready=False
            )
        except grpc.RpcError as error:
            # Peer descriptions are not trusted to be safe for browser responses.
            if error.code() == grpc.StatusCode.ALREADY_EXISTS:
                raise Failure("host_port_conflict", 409) from None
            if error.code() == grpc.StatusCode.NOT_FOUND:
                raise Failure("host_resource_missing", 409) from None
            if error.code() == grpc.StatusCode.INVALID_ARGUMENT:
                raise Failure("agent_rejected_request", 422) from None
            raise Failure("private_agent_unavailable") from None

    def instance_status(self, resource):
        return self.call("InstanceStatus", pb.InstanceId(id=resource)).state

    def port_status(self, spec):
        return self.call("PortStatus", pb.Port(**spec)).state

    def inspect(self, spec: dict) -> dict:
        answer = self.call("Inspect", pb.Port(**spec))
        return {
            "available": answer.available,
            "reason": "free" if answer.available else "host_port_conflict",
        }

    def create(self, resource, cpu, memory_bytes, password):
        self.call(
            "Create",
            pb.Instance(
                id=resource, cpu=cpu, memory_bytes=memory_bytes, root_password=password
            ),
        )

    def power(self, resource, start):
        self.call("Power", pb.PowerRequest(id=resource, start=start))

    def password(self, resource, password):
        self.call("Password", pb.PasswordRequest(id=resource, root_password=password))

    def reserve(self, spec):
        self.call("Reserve", pb.Port(**spec))

    def publish(self, spec):
        self.call("Publish", pb.Port(**spec))

    def activate(self, spec):
        self.call("Activate", pb.Port(**spec))

    def remove(self, spec):
        self.call("Remove", pb.Port(**spec))
