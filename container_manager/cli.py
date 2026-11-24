import argparse
import fcntl
import logging
import os
import re
import time
from pathlib import Path

import uvicorn

from .api import app_for
from .config import Config
from .controller import Controller
from .incus import Incus
from .inspection import Inspector
from .relay import Relay
from .rpc import Remote, server
from .store import Store


def main():
    parser = argparse.ArgumentParser(
        description="Ubuntu manager (no production defaults)"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="operator-owned JSON; mode controller/node/relay",
    )
    parser.add_argument("--repair-mc-native-once", metavar="ROOT_0600_PIN_JSON")
    args = parser.parse_args()
    os.umask(0o077)
    config = Config.load(args.config)
    if args.repair_mc_native_once and (config.mode != "node" or os.geteuid() != 0):
        parser.error("startup repair requires root node mode")
    Path(config.database).parent.mkdir(parents=True, exist_ok=True)
    # A second process must not reinterpret in-flight operations as interrupted.
    with open(config.database + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = Store(config.database)
        logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
        if config.mode == "controller":
            controller = Controller(
                config, store, Remote(config, "node"), Remote(config, "relay")
            )
            host, port = config.bind.rsplit(":", 1)
            # No access logs, forwarded headers, reload, or multiworker recovery.
            uvicorn.run(
                app_for(controller),
                host=host,
                port=int(port),
                access_log=False,
                proxy_headers=False,
                log_level="critical",
            )
        else:
            inspector = Inspector(config.host_addresses, sudo=config.inspection_sudo)
            backend = (
                Incus(config, store, inspector)
                if config.mode == "node"
                else Relay(config, store, inspector)
            )
            try:
                if args.repair_mc_native_once:
                    from .errors import Failure
                    from .mc_startup_repair import check_scope, load_pin, repair

                    pin = None
                    try:
                        pin = load_pin(args.repair_mc_native_once)
                        check_scope(backend, pin)
                    except (Failure, OSError):
                        logging.getLogger("container_manager.node").error(
                            "mc_startup_repair_scope_rejected"
                        )
                        pin = None
                    deadline = time.monotonic() + 90
                    backend.recover(deadline=deadline)
                    if pin is not None:
                        try:
                            repair(backend, pin, deadline)
                        except Failure as error:
                            code = error.code
                            if not isinstance(code, str) or not re.fullmatch(
                                "[a-z_]{1,64}", code
                            ):
                                code = "recovery_failure"
                            logging.getLogger("container_manager.node").error(
                                "mc_startup_repair_failed code=%s", code
                            )
                else:
                    backend.recover()
                host = server(config, backend, inspector)
                host.start()
                try:
                    host.wait_for_termination()
                except KeyboardInterrupt:
                    host.stop(5).wait()
            finally:
                backend.close()
