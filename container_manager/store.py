import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .errors import Failure


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.transaction() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS instances (
                  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, domain TEXT NOT NULL,
                  cpu INTEGER NOT NULL, memory_gb REAL NOT NULL, status TEXT NOT NULL,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error TEXT);
                CREATE TABLE IF NOT EXISTS ports (
                  id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, protocol TEXT NOT NULL,
                  public_port INTEGER NOT NULL, target_port INTEGER NOT NULL,
                  status TEXT NOT NULL, reachability TEXT NOT NULL DEFAULT 'not_checked',
                  UNIQUE(protocol, public_port));
                CREATE TABLE IF NOT EXISTS operations (
                  id TEXT PRIMARY KEY, action TEXT NOT NULL, resource TEXT NOT NULL,
                  state TEXT NOT NULL, actor TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS address_bindings_v1 (
                  instance_id TEXT PRIMARY KEY, nic TEXT NOT NULL,
                  network TEXT NOT NULL, mac TEXT NOT NULL, address TEXT NOT NULL,
                  version INTEGER NOT NULL CHECK(version=1), state TEXT NOT NULL,
                  UNIQUE(network,address));
                CREATE TABLE IF NOT EXISTS native_tcp_v1 (
                  id TEXT PRIMARY KEY, spec TEXT NOT NULL, public_port INTEGER UNIQUE NOT NULL,
                  transport TEXT NOT NULL CHECK(transport='native_tcp_v1'),
                  address_version INTEGER NOT NULL CHECK(address_version=1),
                  state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ownership (
                  id TEXT PRIMARY KEY, spec TEXT NOT NULL, state TEXT NOT NULL);
            """)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def instance(self, resource: str) -> dict:
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM instances WHERE id=?", (resource,)
            ).fetchone()
            if row is None:
                raise Failure("not_found", 404)
            result = dict(row)
            result["node"] = "gamma"
            result["ports"] = [
                dict(p)
                for p in db.execute(
                    "SELECT id,protocol,public_port,target_port,status,reachability FROM ports WHERE instance_id=? ORDER BY public_port",
                    (resource,),
                )
            ]
            return result

    def instances(self) -> list[dict]:
        with self.transaction() as db:
            ids = [
                r[0] for r in db.execute("SELECT id FROM instances ORDER BY created_at")
            ]
        return [self.instance(i) for i in ids]

    def status(self, resource: str, status: str, error: str | None = None):
        with self.transaction() as db:
            db.execute(
                "UPDATE instances SET status=?,error=?,updated_at=? WHERE id=?",
                (status, error, now(), resource),
            )

    def ownership(self) -> list[dict]:
        with self.transaction() as db:
            return [dict(r) for r in db.execute("SELECT * FROM ownership")]

    def own(self, resource: str, spec: dict, state: str):
        # This table accepts only non-secret instance/port metadata, never RPC bodies.
        safe = {
            k: v
            for k, v in spec.items()
            if k
            in {
                "id",
                "instance_id",
                "protocol",
                "public_port",
                "target_port",
                "cpu",
                "memory_bytes",
            }
        }
        with self.transaction() as db:
            old = db.execute(
                "SELECT spec FROM ownership WHERE id=?", (resource,)
            ).fetchone()
            encoded = json.dumps(safe, sort_keys=True)
            if old and old[0] != encoded:
                raise Failure("ownership_conflict", 409)
            db.execute(
                "INSERT INTO ownership VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                (resource, encoded, state),
            )

    def disown(self, resource: str):
        with self.transaction() as db:
            db.execute("DELETE FROM ownership WHERE id=?", (resource,))

    def address_binding(self, resource):
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM address_bindings_v1 WHERE instance_id=?", (resource,)
            ).fetchone()
            return dict(row) if row else None

    def save_address(self, binding, state):
        keys = ("instance_id", "nic", "network", "mac", "address", "version")
        with self.transaction() as db:
            old = db.execute(
                "SELECT * FROM address_bindings_v1 WHERE instance_id=?",
                (binding["instance_id"],),
            ).fetchone()
            if old and any(old[key] != binding[key] for key in keys):
                raise Failure("address_ownership_conflict", 409)
            try:
                db.execute(
                    "INSERT INTO address_bindings_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET state=excluded.state",
                    (*[binding[key] for key in keys], state),
                )
            except sqlite3.IntegrityError:
                raise Failure("address_allocation_conflict", 409) from None

    def native_records(self):
        with self.transaction() as db:
            return [dict(row) for row in db.execute("SELECT * FROM native_tcp_v1")]

    def native_state(self, spec, state):
        encoded = json.dumps(spec, sort_keys=True)
        with self.transaction() as db:
            old = db.execute(
                "SELECT spec FROM ownership WHERE id=?", (spec["id"],)
            ).fetchone()
            if old and old[0] != encoded:
                raise Failure("ownership_conflict", 409)
            native = db.execute(
                "SELECT spec FROM native_tcp_v1 WHERE id=?", (spec["id"],)
            ).fetchone()
            if native and native[0] != encoded:
                raise Failure("ownership_conflict", 409)
            if old and not native:
                raise Failure("proxy_requires_reconciliation", 409)
            binding = db.execute(
                "SELECT state FROM address_bindings_v1 WHERE instance_id=?",
                (spec["instance_id"],),
            ).fetchone()
            if (not binding or binding[0] != "ready") and not (
                native and state == "error"
            ):
                raise Failure("address_requires_reconciliation", 409)
            try:
                db.execute(
                    "INSERT INTO native_tcp_v1 VALUES(?,?,?,'native_tcp_v1',1,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                    (spec["id"], encoded, spec["public_port"], state),
                )
            except sqlite3.IntegrityError:
                raise Failure("native_tcp_allocation_conflict", 409) from None
            db.execute(
                "INSERT INTO ownership VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                (
                    spec["id"],
                    encoded,
                    (
                        "ready"
                        if state in {"active", "paused"}
                        else "error" if state == "error" else "creating"
                    ),
                ),
            )

    def remove_native(self, spec):
        with self.transaction() as db:
            row = db.execute(
                "SELECT spec FROM native_tcp_v1 WHERE id=?", (spec["id"],)
            ).fetchone()
            if not row or row[0] != json.dumps(spec, sort_keys=True):
                raise Failure("ownership_conflict", 409)
            db.execute("DELETE FROM native_tcp_v1 WHERE id=?", (spec["id"],))
            db.execute("DELETE FROM ownership WHERE id=?", (spec["id"],))

    def recover_controller(self):
        with self.transaction() as db:
            # Interrupted mutations are not guessed to be complete or rolled back.
            resources = [
                r[0]
                for r in db.execute(
                    "SELECT resource FROM operations WHERE state='pending'"
                )
            ]
            for resource in resources:
                db.execute(
                    "UPDATE instances SET status='error',error='interrupted_operation',updated_at=? WHERE id=?",
                    (now(), resource),
                )
            db.execute(
                "UPDATE instances SET status='error',error='interrupted_operation',updated_at=? WHERE status='creating'",
                (now(),),
            )
            db.execute("UPDATE operations SET state='error' WHERE state='pending'")

    def begin_operation(
        self, key: str, action: str, resource: str, actor: str
    ) -> str | None:
        with self.transaction() as db:
            row = db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone()
            if row:
                if (
                    row["action"] != action
                    or row["actor"] != actor
                    or (resource and row["resource"] != resource)
                ):
                    raise Failure("idempotency_conflict", 409)
                if row["state"] == "pending" and action == "create" and row["resource"]:
                    return row["resource"]
                if row["state"] != "done":
                    raise Failure("operation_requires_reconciliation", 409)
                return row["resource"]
            db.execute(
                "INSERT INTO operations VALUES(?,?,?,'pending',?)",
                (key, action, resource, actor),
            )
        return None

    def finish_operation(self, key: str, state: str, resource: str):
        with self.transaction() as db:
            db.execute(
                "UPDATE operations SET state=?,resource=CASE WHEN ?='' THEN resource ELSE ? END WHERE id=?",
                (state, resource, resource, key),
            )
