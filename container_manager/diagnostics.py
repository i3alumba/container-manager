"""Secret-free failure records. Never serialize exception or configuration objects."""

import json
import logging
import re
import time
from datetime import datetime, timezone

from .errors import Failure

CODES = frozenset(
    (
        "address_allocation_conflict",
        "address_binding_mismatch",
        "address_binding_unavailable",
        "address_claim_ambiguous",
        "address_lease_ambiguous",
        "address_lease_domain_timeout",
        "address_lease_domain_unavailable",
        "address_ownership_conflict",
        "address_pin_requires_running_dynamic_guest",
        "address_requires_reconciliation",
        "administrator_required",
        "agent_rejected_request",
        "aggregate_budget_exceeded",
        "auth_unavailable",
        "create_queue_full",
        "create_unavailable",
        "cyclic_nat_rule",
        "cyclic_nft_rule",
        "deletion_requires_reconciliation",
        "domain_not_allowed",
        "external_ingress_not_configured",
        "gpu_inventory_unavailable",
        "gpu_not_allowed",
        "gpu_ownership_mismatch",
        "grpc_bind_failed",
        "host_forwarding_conflict",
        "host_listener_conflict",
        "host_port_conflict",
        "host_resource_missing",
        "host_resources_unavailable",
        "idempotency_conflict",
        "incus_operation_failed",
        "incus_query_unavailable",
        "incus_status_unavailable",
        "incus_unavailable",
        "inspection_too_large",
        "inspection_unavailable",
        "instance_creating",
        "instance_not_running",
        "instance_requires_reconciliation",
        "invalid_agent_state",
        "invalid_gpu",
        "invalid_id",
        "invalid_limits",
        "invalid_repair_manifest",
        "invalid_restart",
        "local_nic_requires_reconciliation",
        "managed_instance_mismatch",
        "managed_volume_mismatch",
        "mapping_requires_reconciliation",
        "mappings_require_cleanup",
        "name_in_use",
        "native_tcp_allocation_conflict",
        "native_tcp_address_in_use",
        "native_tcp_bind_failed",
        "native_tcp_not_ready",
        "not_found",
        "operation_requires_reconciliation",
        "operator_profile_mismatch",
        "operator_profile_unavailable",
        "ownership_conflict",
        "physical_capacity_exceeded",
        "port_limit",
        "port_not_found",
        "port_reserved",
        "private_agent_unavailable",
        "proxy_not_ready",
        "proxy_requires_reconciliation",
        "relay_requires_reconciliation",
        "repair_scope_mismatch",
        "reserved_port",
        "resource_change_requires_reconciliation",
        "resource_device_mismatch",
        "resource_state_mismatch",
        "resources_conflict",
        "restart_required",
        "unauthenticated",
        "unparseable_host_inspection",
        "unparseable_nat_declaration",
        "unparseable_nat_rules",
        "unparseable_nft_port_range",
        "unparseable_nft_rules",
        "unparseable_socket_table",
        "unsupported_destination",
        "unsupported_nat_rule",
        "unsupported_nft_target",
        "unsupported_port_set",
        "unsupported_relevant_nat_match",
        "unsupported_relevant_nft_rule",
    )
)
TOKENS = frozenset(
    "native_tcp incus allocation controller bind client_validation upstream_connect pause recover port_status query validate reconcile power precondition start stop active paused error ready running stopped creating missing applied stale timeout exit oserror json other instance network projects leases profile claims snapshot ownership record pin version listener internal_error".split()
)


def emit(component, stage, error=None, *, started=None, spec=None, **fields):
    _emit(False, component, stage, error, started, spec, fields)


def emit_transition(component, stage, *, started=None, spec=None, **fields):
    _emit(True, component, stage, None, started, spec, fields)


def _emit(transition, component, stage, error, started, spec, fields):
    # Logging must never replace a failure, including with hostile values/handlers.
    try:
        code = error.code if type(error) is Failure else "internal_error"
        record = {
            "event": "mapping_transition" if transition else "mapping_failure",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "logger": "container_manager.diagnostics",
            "level": "INFO" if transition else "ERROR",
            "component": (
                component if type(component) is str and component in TOKENS else "other"
            ),
            "stage": stage if type(stage) is str and stage in TOKENS else "other",
            "duration_ms": (
                max(0, round((time.monotonic() - started) * 1000))
                if type(started) in (int, float)
                else 0
            ),
        }
        if not transition:
            record["code"] = (
                code if type(code) is str and code in CODES else "internal_error"
            )
        if type(spec) is dict:
            fields = {
                **fields,
                "mapping_id": spec.get("id"),
                "instance_id": spec.get("instance_id"),
                "protocol": spec.get("protocol"),
                "public_port": spec.get("public_port"),
                "target_port": spec.get("target_port"),
            }
        for key, value in fields.items():
            if key in {"instance_id", "mapping_id", "operation_id"}:
                if type(value) is str and re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    value,
                ):
                    record[key] = value
            elif key in {"public_port", "target_port"}:
                if type(value) is int and 1 <= value <= 65535:
                    record[key] = value
            elif key in {"generation", "current_generation", "errno", "returncode"}:
                if type(value) is int:
                    record[key] = value
            elif key == "protocol":
                if type(value) is str and value in {"tcp", "udp"}:
                    record[key] = value
            elif key in {
                "previous_state",
                "desired_state",
                "outcome",
                "category",
                "route_kind",
                "action",
                "gate",
            }:
                if type(value) is str and value in TOKENS:
                    record[key] = value
        logger = logging.getLogger("container_manager.diagnostics")
        write = logger.info if transition else logger.error
        write(json.dumps(record, sort_keys=True))
    except Exception:
        pass


def route_kind(uri):
    if type(uri) is not str:
        return "other"
    path = uri.split("?", 1)[0]
    if path == "/1.0/projects":
        return "projects"
    if path.startswith("/1.0/profiles/"):
        return "profile"
    if path.startswith("/1.0/instances/"):
        return "instance"
    if path.startswith("/1.0/networks/"):
        return "leases" if path.endswith("/leases") else "network"
    return "other"
