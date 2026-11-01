"""Native backend cleanup is not relay-only, including startup failures."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from container_manager import cli


@pytest.mark.parametrize("mode", ["node", "relay"])
@pytest.mark.parametrize("fault", ["recover", "server", "termination"])
def test_native_backend_always_closed(config, monkeypatch, mode, fault):
    config = replace(config, mode=mode)
    closed = []

    def recover():
        if fault == "recover":
            raise RuntimeError("injected")

    backend = SimpleNamespace(recover=recover, close=lambda: closed.append(True))

    def server(*_):
        if fault == "server":
            raise RuntimeError("injected")
        return SimpleNamespace(start=lambda: None, wait_for_termination=lambda: None)

    monkeypatch.setattr("sys.argv", ["container-manager", "--config", "unused"])
    monkeypatch.setattr(cli.Config, "load", lambda _: config)
    monkeypatch.setattr(cli, "Incus", lambda *_: backend)
    monkeypatch.setattr(cli, "Relay", lambda *_: backend)
    monkeypatch.setattr(cli, "server", server)
    if fault == "termination":
        cli.main()
    else:
        with pytest.raises(RuntimeError, match="injected"):
            cli.main()
    assert closed == [True]
