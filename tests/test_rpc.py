import subprocess
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import grpc
import pytest

from container_manager.proto import control_pb2 as pb
from container_manager.proto import control_pb2_grpc as wire
from container_manager.rpc import Remote, server
from conftest import FakeAgent, FreeInspector


def openssl(*args):
    subprocess.run(
        ["openssl", *map(str, args)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("mtls")
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        root / "ca.key",
        "-out",
        root / "ca.crt",
        "-days",
        "1",
        "-subj",
        "/CN=test-ca",
    )
    for identity, usage in [
        ("gamma-agent", "serverAuth"),
        ("pp-ubuntu-controller", "clientAuth"),
        ("intruder", "clientAuth"),
    ]:
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            root / f"{identity}.key",
            "-out",
            root / f"{identity}.csr",
            "-subj",
            f"/CN={identity}",
        )
        ext = root / f"{identity}.ext"
        ext.write_text(f"subjectAltName=DNS:{identity}\nextendedKeyUsage={usage}\n")
        openssl(
            "x509",
            "-req",
            "-in",
            root / f"{identity}.csr",
            "-CA",
            root / "ca.crt",
            "-CAkey",
            root / "ca.key",
            "-CAcreateserial",
            "-out",
            root / f"{identity}.crt",
            "-days",
            "1",
            "-extfile",
            ext,
        )
    return root


def test_real_grpc_mtls_cn_allowlist_and_identity(config, certificates):
    root = certificates
    agent_config = replace(
        config,
        mode="node",
        bind="127.0.0.1:0",
        ca=str(root / "ca.crt"),
        key=str(root / "gamma-agent.key"),
        cert=str(root / "gamma-agent.crt"),
    )
    agent = FakeAgent()
    host = server(agent_config, agent, FreeInspector())
    # Server factory binds :0; use an additional secure listener with known port.
    credentials = grpc.ssl_server_credentials(
        [(Path(agent_config.key).read_bytes(), Path(agent_config.cert).read_bytes())],
        root_certificates=Path(agent_config.ca).read_bytes(),
        require_client_auth=True,
    )
    port = host.add_secure_port("127.0.0.1:0", credentials)
    host.start()
    controller = replace(
        config,
        node_address=f"127.0.0.1:{port}",
        ca=str(root / "ca.crt"),
        key=str(root / "pp-ubuntu-controller.key"),
        cert=str(root / "pp-ubuntu-controller.crt"),
    )
    remote = Remote(controller, "node")
    try:
        assert remote.inspect({"protocol": "tcp", "public_port": 2223})["available"]
        remote.create(str(uuid4()), 1, 1_000_000_000, "TransientSecret42!")
        assert agent.calls[0][0] == "create"
        resources = remote.resources()
        assert resources["cpu"] == 64 and resources["gpus"][0]["id"] == "0000:01:00.0"
        assert (
            remote.update_resources(
                str(uuid4()),
                8,
                32_000_000_000,
                ["0000:01:00.0"],
                True,
                str(uuid4()),
                1,
                1_000_000_000,
                [],
            )
            == "running"
        )
        intruder = Remote(
            replace(
                controller,
                key=str(root / "intruder.key"),
                cert=str(root / "intruder.crt"),
            ),
            "node",
        )
        try:
            with pytest.raises(grpc.RpcError) as denied:
                intruder.stub.Inspect(
                    pb.Port(protocol="tcp", public_port=2223), timeout=2
                )
            assert denied.value.code() == grpc.StatusCode.PERMISSION_DENIED
            for method, request in [
                (intruder.stub.Resources, pb.Empty()),
                (intruder.stub.UpdateResources, pb.ResourceRequest(id=str(uuid4()))),
            ]:
                with pytest.raises(grpc.RpcError) as denied_resource:
                    method(request, timeout=2)
                assert denied_resource.value.code() == grpc.StatusCode.PERMISSION_DENIED
        finally:
            intruder.channel.close()
        bad_identity = Remote(replace(controller, node_identity="wrong-server"), "node")
        try:
            with pytest.raises(grpc.RpcError):
                bad_identity.stub.Inspect(
                    pb.Port(protocol="tcp", public_port=2223), timeout=2
                )
        finally:
            bad_identity.channel.close()
        plain = grpc.insecure_channel(controller.node_address)
        try:
            with pytest.raises(grpc.RpcError):
                wire.NodeStub(plain).Inspect(
                    pb.Port(protocol="tcp", public_port=2223), timeout=2
                )
        finally:
            plain.close()
        no_client = grpc.secure_channel(
            controller.node_address,
            grpc.ssl_channel_credentials(
                root_certificates=Path(controller.ca).read_bytes()
            ),
            options=[("grpc.ssl_target_name_override", "gamma-agent")],
        )
        try:
            with pytest.raises(grpc.RpcError):
                wire.NodeStub(no_client).Inspect(
                    pb.Port(protocol="tcp", public_port=2223), timeout=2
                )
        finally:
            no_client.close()
    finally:
        remote.channel.close()
        host.stop(0).wait()
