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
