# Ubuntu container manager

Admin-only FastAPI control plane for persistent, unprivileged Ubuntu system
containers on gamma. This repository is implementation, **not a production release**.
There is no Minecraft/Java/game installer, VM runtime, disk quota, host-volume
migration, guest deletion, web terminal, arbitrary exec/config/image/host-path API,
or change to existing Auth identities.

## Repository boundary and history

This is the standalone service repository
[`i3alumba/container-manager`](https://github.com/i3alumba/container-manager).
The parent [`public-page`](https://github.com/LumbaBalumba/public-page) pins an
exact published commit as the `container-manager/` Git submodule. Clone this
repository directly for service development, then run the local commands below
from its root. In the parent use `git submodule update --init --recursive`; do not
use `--remote` to change the pinned version implicitly.

Controller, node agent, relay, typed RPC/protobuf source, Dockerfile, operator
examples and service tests live here. The UI stays in
[`dashboard`](https://github.com/i3alumba/dashboard); parent CI, Kubernetes,
image inventories and the [deployment runbook](https://github.com/LumbaBalumba/public-page/blob/dev/docs/UBUNTU-CONTAINERS.md)
stay in `public-page`. Child publication does not deploy an application or update
the parent gitlink automatically.

The original three service commits were extracted without squash using
`git subtree split --prefix=container-manager` at parent
`13878759bc9168e7f522e7d78e59446ce4871592`. Preserved subtree head:
`e2508fd2981af2c2d4f9c645afc1fddabe184a71`; its tree exactly matches the original
service directory. Import is a merge on a dev-based feature branch, not a new
copy-only source history. Service changes follow feature → checked `dev` →
separate `master` PR; the parent updates its gitlink only after child publication.

## Current release status

Extraction does **not** approve deployment. Operator acceptance on 2026-11-01
passed native TCP gamma-direct and WAN paths (60 transfers each, zero truncation),
UDP nonce replies, pinned-key password SSH, port edits, ordinary power cycles,
held-stream closure, resource/UID/network isolation and a fresh second create.
Full root-plus-home archive restore and consistent recovery of the node, relay
and private acceptance-controller databases passed separately. Temporary backup/import exceptions were
explicitly approved and the complete original restricted project policy restored
before guest start; neither exception is a standing application permission.
Both marked scratch guests, their homes, mappings and pins were subsequently
removed; archives, metadata snapshots and private audit records were retained.
Original workloads/PVCs/credentials/packages/kernel/old-service identities passed
preservation comparison. New agents are enabled with empty ownership registries.
Only new-agent and guard restarts were tested, **not host reboot**.

Parent release PR
[#185](https://github.com/LumbaBalumba/public-page/pull/185) remains Draft pending
exact source pinning, running-controller NetworkPolicy proof and checked selective
release. New controller prerequisites and nonroot Pod routing/storage/mTLS/Auth
preflight are prepared; this does not mean the controller application is deployed.
Live administrator/revocation and same-origin browser acceptance remain release
gates before production-user admission. Local tests do not replace those checks.

## Architecture and trust boundaries

```text
browser -> same-origin nginx /api/containers/ -> controller (non-root)
    controller -> http://auth:8000/api/user/ (live explicit bearer, every request)
    controller -- private gRPC/mTLS --> gamma node agent (host root / Incus socket)
    controller -- private gRPC/mTLS --> alpha relay (unprivileged native process)
WAN TCP:port -> upstream NAT -> alpha LAN relay -> gamma native TCP -> pinned guest IPv4:target
WAN UDP:port -> upstream NAT -> alpha LAN relay -> gamma Incus UDP proxy -> guest loopback:target
```

The gamma agent is a **host-root trust boundary**: Incus socket access is equivalent
to host root. A compromised agent, controller certificate/key, CA, or operator can
bypass application restrictions. Never expose Incus TCP publicly or mount its
socket into the controller. The relay requires no root socket, privileged container,
Docker socket, host-network controller pod, or general firewall-write capability.
Its optional sudo grant permits only three exact read-only inspection commands.
Agents listen on an operator-specified WireGuard address only; certificates do not
replace private-network filtering. Only the controller certificate's exact CN is
accepted. No insecure gRPC listener/fallback exists; clients verify a pinned server
certificate DNS identity against their private CA.

The operator owns host firewall/ACL/network configuration. The application never
adds/flushes firewall rules, kills an incumbent listener, upgrades packages on a
host, or changes existing workloads. Root runs `apt-get` **inside newly owned guests
only**, with constant bootstrap commands. Public inputs never become shell text.
Passwords go exclusively to guest `chpasswd` stdin, not argv, SQLite, audit logs,
validation responses, or return values. Python/protobuf transient memory is not
cryptographically zeroized; disable core dumps and keep tracing/body capture off.

## Fixed guest specification

- Incus project `pp-ubuntu`, dir pool `pp-ubuntu-ssd`, managed bridge `ppub0`.
  Operator provisions the pool on gamma NVMe at
  `/var/lib/public-page/incus-ssd` (root-owned0711 traversal, matching Incus
  ancestors; never recursively relax volume permissions). Docker default HDD
  volumes are not suitable.
  Incus 7.5.1 is the current operator baseline; no install/upgrade is done here.
- `ppub0` candidate `10.211.0.1/24` needs operator overlap review and native bridge
  ACL/restricted-project policy. No arbitrary host/firewall edits by this app.
- Operator pins a **locally available, verified 64-hex Ubuntu 24.04 LTS image
  fingerprint**. No remote image URL, profile or user-selected image is accepted.
- UUID-owned names `pp-ubuntu-<canonical-uuid>`; no user slug is an Incus name.
  Ordinary CLI calls use argv, fixed `--project pp-ubuntu`, no shell. Read-only
  `incus query` calls use project scope in the URI only: network metadata uses
  `project=default`, and leases use each authoritative shared-domain project.
  Project inventory and all-project instance queries have no project scope. Only a constant
  guest bootstrap uses `/bin/sh -c`.
- Full persistent root, including `/etc`, packages and SSH host keys; separate
  managed custom volume `<owned-name>-home`, mounted at `/home` from the same pool.
  Stop/start/port/password changes never recreate or delete either volume.
- Uses only the fixed operator-managed project `default` profile; never overrides
  its root pool, managed network, IPv4/IPv6/MAC filtering or port isolation.
  Native TCP alone pins the existing legitimate DHCP IPv4 using a local `eth0`
  override cloned from that profile, changing only `ipv4.address`. The agent
  verifies that exact fixed profile (including no extra devices) before creation,
  and fails closed on operator drift. Explicit
  `security.privileged=false`, `security.nesting=false`,
  `security.idmap.isolated=true`. Operator must verify
  subordinate ID ranges/kernel support. Minimal Ubuntu plus openssh-server and CA
  certificates, not Java/games. Guest root SSH password login is intentional;
  effective sshd settings and syntax are checked by constant bootstrap commands.
- CPU is a positive integer (never bool); memory is positive finite decimal GB,
  up to three decimal places (GB = 1,000,000,000 bytes). There is **no fixed 4 CPU /
  16 GB per-container ceiling and no default aggregate quota**. UInt32 CPU/UInt64
  byte representability and the node's real physical CPU/RAM inventory still bound
  an individual request. Optional operator `pool_cpu`/`pool_memory_gb` quotas are
  supported only when explicitly configured; `null`/omitted means no quota.
  Aggregate overcommit is therefore possible: limits are not reserved RAM or a
  guarantee of k3s priority. Monitor host memory/CPU pressure and reserve capacity
  through operator policy when required. No disk quota/low-space protection is
  implied; separately monitor NVMe capacity/inodes.

## Browser API v1

All routes, including list/capabilities/check, require an explicit
`Authorization: Bearer ...` header. Cookies alone do not authorize. Every request
calls `http://auth:8000/api/user/`, with 1s connect / 3s IO timeouts, environment
proxies and redirects disabled. Auth's self-filtered `/api/user/` list must contain
exactly one object; empty/multiple/malformed lists fail closed. A detail object
remains compatible. `is_active is True` and the exact boolean
`services.hosting is True` from the live read-only profile are both required;
missing/string/numeric/object grants fail. Neither `is_staff` nor `is_superuser`
is a fallback or override. A specifically authorized non-staff Hosting
administrator can use this service without gaining central user-management
rights. There is no positive grant cache.

This prepared consumer contract must be published/deployed and verified **before**
Auth enables `USER_ADMIN_HOSTING_GRANTS_READY`. Until that default-off switch is
enabled, Auth computes `services.hosting` from its original active/staff rule,
so deploying the consumer first preserves legacy admission. Independent grant
editing remains unavailable until coordinated release; no production change is
performed here.
401 unauthenticated, 403 ineligible, 409 conflict, 422 invalid input, 503 unavailable
Auth/host inspection. Generic errors contain only fixed `detail.code/message`.
Mutations audit actor/action/resource/result, never request bodies/tokens/passwords.

Base: same-origin `/api/containers/`. Routes are slash-exact; no redirect is needed.

`GET capabilities`:

```json
{
  "administrator": true,
  "node": "gamma",
  "max_cpu": null,
  "max_memory_gb": null,
  "resources_editing_enabled": true,
  "gpu_shared": true,
  "gpus": [],
  "host_resources": { "cpu": 64, "memory_gb": 128 },
  "domain_suffix": "hosting.i3alumba.ru",
  "image": "Ubuntu 24.04 LTS",
  "disk_quota": false,
  "home_separate": true,
  "root_persistence": "full",
  "external_ingress_ready": true,
  "public_port_ranges": { "tcp": [[3000, 50000]], "udp": [[3000, 50000]] },
  "aggregate_budget": { "cpu": null, "memory_gb": null }
}
```

`GET /` returns `{instances:[Instance,...]}`. Each Instance has
`{id,name,domain,node,status,cpu,memory_gb,gpu_ids,resource_version,ports,created_at,updated_at,error}`.
Legacy rows gain additive metadata defaults `gpu_ids=[]`, `resource_version=0`;
no guest, root, home or mapping is recreated. The hardware values above are an
illustration, not a claim about the production host. Missing/old/unavailable node
RPC capabilities advertise editing disabled and no GPUs; unsupported mutations
fail closed until the matching native agent is published/installed.
IDs are canonical lowercase UUIDs, node is `gamma`, status is
`creating|running|stopped|error`; error is null or a fixed sanitized code. Port:
`{id,protocol,public_port,target_port,status,reachability}`, status
`reserved|active|error`, reachability
`not_checked|reachable|unreachable|unknown`.

- `POST /`: `{name,domain,cpu,memory_gb,root_password,ports:[PortSpec,...]}` ->
  durable **creating Instance immediately** (HTTP200). Bootstrap runs after the
  response; poll authorized `GET /` until running/error. This avoids a long browser
  request/Cloudflare timeout. Password exists only in the in-memory background job;
  daemon restart loses it and records error rather than persisting/replaying it.
  Name is a free slug matching `^[a-z][a-z0-9-]{0,31}$`, **not an allowlist**.
  Domain must be exactly one valid lowercase DNS label (1..63 characters, no
  leading/trailing hyphen) below operator `domain_suffix=hosting.i3alumba.ru`.
  The UI selects the label, e.g. `mc` -> `mc.hosting.i3alumba.ru`; arbitrary
  suffixes, nested names, URLs and wildcard input are rejected server-side.
  DNS records/wildcard must be operator-prepared; the app never creates them.
  Root password is
  write-only SecretStr, 16..256 characters, no CR/LF/NUL/colon (colon is forbidden because
  `chpasswd` uses a colon-delimited stdin record).
- PortSpec: `{protocol:"tcp"|"udp",public_port:1024..65535,target_port:1..65535}`.
  The approved forwarded span is **3000..50000**, additionally restricted by
  infrastructure/NodePort reservations and actual occupancy. Shared-IP guest SSH
  can use public3001 -> target22 after successful checks,
  explicitly requested in ports. Public2222 is existing infrastructure, not free.
  Domain is display/selection identity, **not** a TCP/UDP virtual-host boundary.
- `POST ports/check`: `{protocol,public_port}` ->
  `{available,reason,checks:{alpha:{status,reason},gamma:{status,reason},registry:{status,reason}}}`.
  Each status is exactly `free|conflict|unknown`; reasons are sanitized plain strings.
  `available===true` only if **all three** statuses are `free`. Any unknown returns
  HTTP503 with this same check-result shape; invalid/reserved policy is never free.
  This endpoint allocates nothing.
- `POST {id}/start`, `POST {id}/stop` -> **updated Instance**, never delete storage.
- `POST {id}/resources`:
  `{cpu,memory_gb,gpu_ids,expected_version,allow_restart}` -> updated Instance.
  `expected_version` is the opening `resource_version`; stale revisions return409.
  Running GPU-set changes or RAM decreases require explicit `allow_restart:true`;
  CPU/RAM increases are applied live. A stopped guest stays stopped. Restarts use
  the normal power path, closing TCP streams and preserving pinned addresses,
  port reservations, SSH keys, full root and `/home`. No force-stop or recreation.
- `POST {id}/password`: `{root_password}` -> exactly `{changed:true}`.
- `POST {id}/ports`: PortSpec -> updated Instance after checked activation.
- `DELETE {id}/ports/{port_id}` -> updated Instance; matching owned mapping only.

All mutation routes accept optional `Idempotency-Key: <canonical UUID>`. Reuse
returns the current instance for the original completed actor/action/resource
(password still returns `{changed:true}`); keys identify an operation, not a body
hash. Never reuse a key for a different intended operation. A pending create key returns the same creating Instance without starting another
job; other pending/error keys return409 requiring reconciliation. Retrying cannot
silently recreate a guest.
Unknown JSON fields are rejected, including image/profile/config/host path fields.

## CPU/RAM edits and shared physical GPUs (new source, not activated)

Create also accepts `gpu_ids:[canonical PCI address,...]`, default `[]`; GPU devices
are attached before the first guest start. Capabilities list only live cards in
node operator `gpu_allowed_pci`, e.g. `0000:01:00.0` (example, not a production
selection), and only while the fixed restricted project explicitly permits GPU
devices. Unknown IDs, duplicates, host paths, arbitrary device/config/profile
fields and unverified inventory are refused. One listed card may be shared by
multiple managed containers; there is no exclusive lease or VRAM/compute quota.
Sharing exposes the host GPU driver and allows GPU contention/OOM across guests;
it is not strong workload isolation. Compatible host drivers and guest userspace
libraries are operator/guest prerequisites, never installed by these API actions.

The application **never changes project restrictions**. Before a separately
approved rollout, an operator must review existing Incus project CPU/RAM limits
(the old 4/16 baseline remains effective until changed), allow only the reviewed
GPU device class, configure the specific physical PCI allowlist, and verify
unprivileged isolated UID/GID permissions. Keep VM/privilege/nesting/unmanaged
host-path/PCI/USB restrictions, fixed profile, root/home and network policy intact.
An empty allowlist or denied project GPU policy yields no selectable GPUs.

Upgrade the native node agent first, then the matching controller and Dashboard;
new RPCs are additive but an old node cannot safely implement resource editing.
Every edit verifies stored ownership against actual secure instance/profile,
CPU/RAM, home, NIC/pin and exact managed GPU/proxy devices before mutation. A
node intent is committed before stop/config operations. Readback and original
running/stopped state are required before ownership/HTTP metadata acknowledgement.
Controller revisions and actor-bound idempotency prevent stale/replayed updates.
A timeout, crash or partial write preserves error ownership and any increased
resource reservation: never blindly retry, adopt foreign devices, reset a row,
restart an uncertain guest or restore an old database to make the UI green.
Reconciliation is a separately backed-up operator action, not a public force API.
Queued bootstrap jobs remain bounded independently of resource quotas.

Local mocked tests do not prove live GPU/CUDA/render access, driver safety,
resource hotplug, reboot, persistent data or public mapping preservation. These
require separately authorized native acceptance with reviewed versions/backups.

## Upstream ingress ownership (required before publication)

Alpha owns LAN address `192.168.0.120`; advertised WAN `95.165.90.137` is **not** a
local interface address. Host socket/NAT inspection cannot discover or reserve
ports on the upstream gateway. The operator confirmed forwarding **3000..50000**;
controller examples/Kubernetes declare that span separately for TCP and UDP.
Default Config ranges remain empty: no implicit gateway ownership for other installs.

**DNS prerequisite verified:** after explicit operator approval, the prepared
`*.hosting.i3alumba.ru` A record was switched to **DNS only**, still targeting
`95.165.90.137`. Both `mc.hosting.i3alumba.ru` and a fresh random child resolved
only to that origin. No exact `mc` record shadows the wildcard. The
`hosting.i3alumba.ru` apex remains proxied and unchanged; it is not a guest address.
Do not enable ordinary Cloudflare proxying for arbitrary SSH/TCP/UDP, or assume
that a wildcard overrides an exact proxied record. The application never changes
DNS; subsequent operator edits must be reverified before admitting guests.

Controller `public_port_ranges` defaults to `{"tcp":[],"udp":[]}`. Each inclusive
range must be explicitly certified by the operator as already forwarded/routed
through **every** upstream NAT/firewall to alpha and reserved for this service.
TCP and UDP declarations are independent. Empty/missing ranges block checks from
saying available and block create/add public mappings **before** host mutation.
Capabilities expose `external_ingress_ready`; UI warns and disables public-port
creation while it is false. A private guest with no published ports remains an
explicit administrator option. Existing power/removal operations are preserved.

Do not set broad ranges merely to bypass this gate. A dedicated gateway range
and explicit exceptions, or a separately authorized router-API integration, must
be agreed first. The app does not control UPnP/NAT-PMP/PCP/router credentials.
Configured ranges are operator ownership declarations, **not a live external
reachability probe**. External TCP/UDP acceptance remains required after release.
Relay `public_ip` is its fixed **owned inbound bind address**, which is the alpha
LAN address behind NAT, not a nonlocal advertised WAN IP. No IP-forwarding/global
router changes are performed by the application.

## Allocation, inspection and recovery

1. A SQLite WAL `BEGIN IMMEDIATE` transaction admits aggregate resources and commits
   a globally unique `(protocol,public_port)` reservation and operation state.
2. Both hosts' **actual** listeners and forwarding rules are checked again. Alpha
   then acquires an exclusive public socket (no reuse flags), held while reserved.
3. For **new TCP mappings**, gamma validates a versioned, UUID-owned static IPv4
   pin and exclusively binds a native listener on `10.200.73.2:public_port` under
   the already trusted root node agent. The upstream is only the pinned guest's
   `10.211.0.x:target_port`, never DNS, a request address, or a guest-reported IP.
   **TCP applications must listen on their own guest IPv4 or `0.0.0.0`, not only
   `127.0.0.1`.** Readiness requires the exact in-process spec, live accept thread
   and owned socket, not an unrelated kernel listener. UDP is unchanged: a
   UUID-owned Incus UDP proxy on the fixed gamma address connects to guest
   `127.0.0.1:target_port`, with the existing kernel readiness check.
4. Alpha activates forwarding to the **fixed operator gamma WireGuard IP** and the
   same public port only after readiness. No user upstream address exists.
5. Failures compensate only new owned mappings. Existing ports and guest data are
   preserved. If removal/ownership is ambiguous, reservations remain in error.

Checks read Linux `/proc/net/{tcp,tcp6,udp,udp6}`, `iptables-save -t nat`,
`ip6tables-save -t nat`, and `nft -j list ruleset`; all must be readable/parseable.
They cover IPv4/IPv6 wildcards/specific listeners, protocol separation, literal
ranges/multiports, reachable NAT chains, and exclude ClusterIP-only destinations
before evaluating irrelevant rules. Declared empty chains are distinguished from
unknown targets. Kube/CNI mark and SNAT-only branches do not allocate public
destinations. An opaque predicate is irrelevant only if its entire reachable
branch is proved nonallocating for the requested protocol/port (including literal
child-port exclusions); it is never interpreted as matching a guessed port set.
Unknown predicates on possibly allocating branches and unknown effects/maps still
fail closed. nft iptables-compat MARK/SNAT/DNAT targets are classified explicitly,
not skipped along with their tables. Configure **all** host public/WireGuard/NAT
advertised addresses in `host_addresses`; a partial list is unsafe.

Relevant unknown ipset/nft sets/maps, complex predicates, cyclic rules, permission
denial, unavailable tools, or unsupported forwarding syntax fail closed (503),
never “probably free”. This deliberately supports a conservative subset, not every
kube-proxy/firewall dialect. Kernel/NAT ownership must be reviewed with real host
snapshots before release. Do not disable inspection or flush/change existing rules
to make checks pass; escalate unsupported rules to the operator. Operator serializes
out-of-band NAT/listener changes during allocations: no application can atomically
lock unrelated root-owned firewall writers against a socket bind.

Ports <1024, NodePort30000..32767, fixed infrastructure ports
`{2222,2379,2380,5000,5187,6443,6444,8090,8472,9443,9444,9445,10010,10248,10249,10250,10256,10257,10258,10259}`
(`models.RESERVED`), and operator `reserved_ports` are forbidden for public
allocation. Ordinary service ports such as 5432, 8000, 3306 or 8443 are **not**
blanket-reserved; they are permitted only when registry and both actual host
inspections confirm free. Target ports may
be below1024. A non-listening guest application is **not** an allocation conflict.
`active` means a bound published mapping, not service health. Reachability currently
stays `not_checked`; no browser operation claims a service probe was performed.
Especially, a UDP send does **not** establish external reachability. Validate real
SSH/TCP/UDP externally as an operator after authorized deployment, with bounded
probe timeouts. Alpha TCP has 3s upstream connect / 120s idle timeout, <=64KiB
pending per direction, half-close propagation, 128 concurrent connections globally.
Both the alpha relay and gamma native TCP pump enable `TCP_NODELAY` on accepted
and upstream sockets before forwarding. This avoids Nagle/delayed-ACK stalls
between small protocol messages, including chunk-batch markers; buffer bounds,
timeouts and half-close behavior are unchanged. UDP is unaffected. This applies
to new streams after a separately authorized upgrade of both native agents;
a controller-only image update does not update host agents. Coordinate agent
restarts because they close existing TCP connections.
UDP has <=256 client associations per mapping / <=1024 globally, 30s client-activity TTL, connected
fixed upstream sockets and <=65536-byte datagrams; replies cannot refresh idle TTL.
At most64 mappings per instance. There is no arbitrary broad-range exposure.

Only **one controller process** per database is supported (CLI takes an exclusive
lock). Registry uniqueness/admission is also database-atomic across connections.
SQLite stores metadata/owned mappings/operation states, not secrets. WAL uses FULL
synchronous commits. Restart marks interrupted operations/creates error and never
frees their ports. Alpha rebinds persisted reserved/active sockets; a bind/inspection
failure marks durable error. Gamma never recreates a partial guest on retry.
Controller construction performs local durable interrupted-operation recovery
only. HTTP startup and authorized list requests schedule at most one daemon
reconciliation job; they never wait for private status RPC deadlines before opening
or responding on HTTP. Inventory is a metadata snapshot while that job runs.
Missing/unavailable/error mappings become error, not free. Recovery errors
are not automatically cleared, nor are partial volumes deleted. Stop preserves
alpha allocations; native TCP closes all streams before Incus stop and keeps its
exclusive gamma socket bound but paused. Start validates the same recorded pin
before resuming only known transports. UDP proxies bind again on start. Explicit remove errors may
leave a mapping unavailable but reserved until operator review.

### Native TCP allocation and recovery

Before the first pin the owned guest must be running and inheriting the fixed
`eth0` profile. The daemon's `volatile.eth0.hwaddr`, exact managed `ppub0` bridge
(`10.211.0.1/24`, IPv6 disabled), filtering fields, instance project/type/name,
root profile and full all-project NIC claims are checked against the complete
shared-network DHCP lease domain. Hostnames and guest state IPs are not authority.
Each snapshot reads the complete project inventory (maximum 256, explicit
`features.networks=true|false` required), then leases for `default` and every
project explicitly sharing its networks (`false`, maximum 16 scopes). Query
parameters are URL-encoded; isolated (`true`) projects' same-named networks are
not conflated with this bridge. Unknown claim projects fail closed. Inventory
and all scoped lease queries share one **2s monotonic deadline**, not 2s per
scope; denial, malformed data, excess scopes or late/partial results reject the
whole snapshot before an initial pin intent or mutation. Lease provenance is
retained: the initial dynamic candidate must come from `pp-ubuntu`, and any
foreign-scope matching IP or MAC conflicts, even an identical static pair.
Stopped ready static pins may lack dynamic leases only after all scopes complete.
The one unambiguous current dynamic lease is preferred, never a first-free scan;
gateway/network/broadcast/foreign/duplicate allocations fail closed. A node-wide
allocation lock and SQLite `UNIQUE(network,address)` reserve the intent before
`config device override ... eth0 ipv4.address=...`. Readback must match the exact
local/expanded NIC, MAC and claims. An already-local dynamic NIC is reconciliation
territory: no `device set` or arbitrary overwrite is attempted, and its error
intent retains the address reservation. Once recorded ready, the same static local
NIC is validated read-only; missing dynamic leases while stopped/restarting are
allowed. Pin failure/ambiguous mutation never frees or chooses another address.

The **existing node SQLite** contains `address_bindings_v1` (UUID, NIC, network,
MAC, static address, version, pending/ready/error) and `native_tcp_v1` (exact mapping
spec, transport/address version, creating/active/paused/error). Native transport
and generic mapping ownership transitions commit atomically. There is no fourth
database. Before activation, recovery and every upstream connection the agent
revalidates the daemon-authoritative pin and uniqueness. At most eight concurrent
root validations are admitted (excess clients are rejected); daemon reads have
5s per-command deadlines. TCP reuses the byte pump with 128 global clients,
3s connect / 120s idle deadlines and at most 64KiB pending in each direction.
Generation checks after validation/connect prevent pause/remove races from
forwarding; pause/remove/agent shutdown close existing streams. Agent shutdown
preserves durable leases. Recovery validates and rebinds known active/paused
records; a stopped guest stays stopped and its binding stays paused. No service
health or external reachability is inferred.

**Legacy Incus TCP ownership is not migrated, removed, rebound or automatically
repaired.** It becomes an error requiring operator reconciliation and retains its
reservation. Interrupted creates, binding failures and ambiguous removal also
retain error ownership. Old Incus devices must be handled only by a separately
authorized operator procedure; never steal their listeners or clear metadata to
make a port appear free. UDP ownership and readiness remain unchanged.

## Operator prerequisites (not performed by this implementation)

- Separate authorized release/deployment decision, dev-based feature PR -> dev,
  then dev -> master. No automatic release from this directory.
- Preserve all existing mounts/volumes/workloads. Incus7.5.1, local Unix socket,
  fixed restricted project, NVMe dir pool at the path above, reviewed `ppub0`
  address/native ACLs, Ubuntu fingerprint and private certificate authority.
- Fixed project default profile must retain SSD root and `eth0` on `ppub0` with
  IPv4/IPv6/MAC filtering and port isolation. The app uses no network/root-device
  overrides except the validated native TCP static IPv4 pin above; review
  operator drift before admissions. Shared default-project image
  cache is supported (`features.images=false`). Project CPU/memory limits are
  operator-owned: review/remove the old 4 CPU /16GB project ceiling only in the
  authorized resource-policy rollout. Retain VM limit0, managed-only disks/NICs,
  isolated privilege, blocked nesting and scoped proxy permission. GPU access
  additionally requires a reviewed GPU-class policy and node PCI allowlist; no
  automatic project-policy broadening or driver/package installation occurs.
- No public Incus endpoint. WireGuard routing controller->gamma/alpha private gRPC
  and alpha->gamma published ports; gamma proxy ingress restricted to alpha's
  WireGuard peer; bridge ACLs isolate guest access to host/k3s/private networks.
  Existing k3s/Docker/firewall policy stays operator-owned.
- `examples/network-guard.py` is an **operator-run**, root-owned INPUT guard, not
  an API action. Install it only after reviewing the actual topology/reservations;
  run `python3 /usr/local/libexec/pp-ubuntu-network-guard.py` through a dedicated
  oneshot before the new native services. Its root-owned
  `/etc/pp-ubuntu/network-guard.json` selects `role` (`alpha`/`gamma`), pinned gamma
  `pod_cidr` (`10.42.0.0/24`), and sorted unique `reserved_ports` (union of
  `models.RESERVED` and all operator reservations). It restricts only the new
  WG-bound RPC endpoint to the gamma Pod CIDR/owned WG addresses, still requiring
  mTLS. Gamma's owned proxy rules deny NEW non-alpha ingress on the protected
  forwarded span, excluding operator infrastructure and NodePorts. **Effective
  INPUT preserves existing K3s precedence**, including its role-local Pod
  ESTABLISHED/RELATED treatment; this is not an all-state alpha-only guarantee.
  No NAT/FORWARD/Docker or incumbent K3s rule is changed. Whole-filter inspection
  errors fail before mutation; exact owned hooks and chain contents must match.
  Both roles accept either the owned hook block first or one exact recognized
  K3s INPUT hook immediately before that block, only after a read-only proof of
  every reachable rule/path. Overlapping ACCEPTs must restrict the entire source
  to the fixed local Pod CIDR and states to ESTABLISHED/RELATED: gamma uses
  `10.42.0.0/24`, alpha uses `10.42.1.0/24`. The controller/RPC allowlist remains
  `10.42.0.0/24` plus the two WG peers on both roles; alpha packet rules do not
  change. Disjoint destination/protocol/port ACCEPTs are also permitted.
  The proof deliberately over-approximates paths, including after RETURN or
  terminal verdicts; mark, addrtype and rate predicates confer no exemption.
  Positive K3s `-m set --match-set KUBE-{SRC,DST}-<16 uppercase alphanumerics>`
  matches (one `src` and one `dst` at most) are also opaque over-approximations:
  no set lookup, name or contents can narrow a proof path or justify ACCEPT.
  NFLOG alone may carry a bounded 1..64 printable-ASCII `--nflog-prefix`; it
  does not change packet headers or authorization. Packet policy and invocation
  remain unchanged; these additions only recognize nonverdict NetworkPolicy grammar.
  Unknown grammar/effects, cycles, missing targets, duplicate/drifted attachments
  or budget exhaustion refuse, never sample or repair. Bounds are 4MiB / 65,536
  ordered snapshot records / 262,144 tokens / 4,096 bytes per token, and 64
  reachable chains / 2,048 rules / depth32 / 4,096 explored entry/rule contexts.
  A recognized K3s prefix without the complete owned block refuses fresh install.
  Gamma's own proxy chain returns only conntrack `ESTABLISHED` / `REPLY` traffic
  to incumbent INPUT policy before applying its new-ingress restriction. That
  rule does not ACCEPT replies or exempt RELATED; the earlier incumbent K3s
  ESTABLISHED/RELATED behavior is preserved separately. This prevents reply
  packets to a host client's in-range ephemeral port from being mistaken for a
  new published connection. Updating an already installed old chain requires a
  separately authorized, whole-filter-verified one-rule transition; the helper
  intentionally refuses to migrate drift automatically. For that separate root
  fencing procedure only, the standalone helper exposes read-only
  `classify(snapshot, trusted_old_chains, unchanged_hooks, config)` and
  `ordered_records(snapshot)` including policy values, so pre/post evidence can
  require exactly one approved insertion without modifying/reordering K3s.
  Partial state, duplicates,
  misplaced hooks or drift require operator review, never automatic flush/repair.
  Serialize with other firewall writers and verify persistence/order after boot.
  The fixed topology is intentional; do not use this helper unchanged elsewhere.
- Linux `/proc/net`, iptables-save and ip6tables-save **including empty nat tables**,
  nft JSON support, sudo for non-root alpha as below. Verify all firewall dialects
  with representative snapshots before admitting guests. No inspection fallback.
- Python3.12+, `uv`, Incus CLI on gamma, openssl for certificate provisioning/tests;
  guest apt repository egress and working DNS. No Java/game package required.
- Dedicated service users and protected state/cert directories; CA private key stays
  offline. Guest root password login is a brute-force/public exposure risk: use
  strong unique passwords and operator-reviewed ingress/rate policy.

## Local development and tests

Run from this directory, with no production services, SSH or Incus required:

```sh
uv sync --locked
uv run black --check container_manager tests --exclude 'control_pb2'
uv run pytest -q
uv run container-manager --help
# Reproduce generated typed RPC source (checked in, never generated at runtime):
uv run python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. container_manager/proto/control.proto
```

`uv.lock` locks dependencies/hashes; generated code uses the locked grpcio-tools
version. Tests use isolated temporary DBs/certificates, fake Auth/Incus/RPC and real
localhost socket/TLS transports, not production endpoints or host firewall writes.
They cover auth revocation/flags/outages, redaction, allocation/concurrency,
rollback/retained ownership, bootstrap/SSH argv, restart persistence, firewall
parsing, exclusive binds, TCP half-close/idle timeout and UDP replies/expiry.
Handwritten synthetic kube/CNI/empty-Docker fixtures live in `tests/fixtures`;
private host snapshots are read-only dry-run inputs, never repository fixtures.
Live Incus7.5.1/project ACL/NVMe/reboot/SSH and external reachability are release
acceptance prerequisites, not claims made by the fake-backed suite.

## Configuration and native installation

`container-manager --config /absolute/operator-owned.json` is the only CLI flag
besides `--help`; `mode` selects `controller`, `node`, or `relay`. No mode auto-installs
or provisions a host. Examples in `examples/*.json` contain no secrets, and node
fingerprint intentionally fails startup until replaced. Replace documentation
addresses `192.0.2.x`, verify actual WG IPs/ports/certificate identities, and add
host-reserved infrastructure ports consistently to all three configs.

All modes require `database`, `bind`, `ca`, `cert`, `key`. Controller uses
`node_address/identity`, `relay_address/identity`, `domain_suffix`, `public_port_ranges`, and aggregate
optional `pool_cpu/pool_memory_gb` (`null`/omitted: no aggregate quota). Node's
`gpu_allowed_pci` defaults to `[]` and selects only operator-approved physical GPU
PCI addresses. Node additionally requires `wireguard_ip`, `gamma_ip`,
`host_addresses`, `image_fingerprint`. Relay requires `wireguard_ip`, `public_ip`,
`gamma_ip`, `host_addresses`; `inspection_sudo:true` enables the exact read-only
sudo argv. Native agent gRPC binds must equal their configured private WireGuard
IPv4 address (initial topology); public relay sockets support IPv4 or IPv6.

After separate installation authorization, operator installs reviewed code into
`/opt/pp-ubuntu` and runs `uv sync --locked --no-dev --no-editable`, creates dedicated
`pp-ubuntu-controller`/`pp-ubuntu-relay` users and `/etc/pp-ubuntu` configs/credentials,
and adapts the three example systemd units. `StateDirectory` and umask0077 protect
state. Each service needs only its own client/server key and the CA certificate.
Use owner-readable private keys, writable state owned by the service, immutable
operator-owned code/configs, no CA signing key online. Do not enable/start example
units until the release gate, network policy and storage paths are approved.

Alpha relay is non-root and needs no low-port capability. Verify actual root-owned
binary paths and validate `examples/relay.sudoers` with `visudo -cf` before installing
it as a narrow sudoers include. Never allow wildcard nft/iptables commands. Its
unit intentionally permits sudo escalation for **read-only inspection only**;
`NoNewPrivileges=true` would break it and inspection would fail closed. Gamma
runs as root to inspect rules and access Incus; controller has neither privilege.
Native services use the host network namespace to inspect actual host listeners;
do not put agents in an isolated Docker namespace and assume host checks work.

For non-production local HTTP development, use a dedicated local Auth test fixture
resolving `auth:8000` and separate private test agents/certificates. Start with:

```sh
uv run container-manager --config /absolute/path/to/controller.json
```

There is no anonymous/dev bypass, plaintext RPC mode, or environment password flag.

## mTLS provisioning example

Use an offline CA or existing restricted private PKI. Example commands below are
for an **isolated operator directory outside Git**, not host deployment automation.
Keys are generated into files, never copied to logs. Production CA custody,
rotation, expiration monitoring and revocation/distribution are operator duties.

```sh
umask 077
mkdir -p pki && cd pki
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj /CN=pp-ubuntu-private-ca \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
# Agent server certs; SANs must match configured node_identity/relay_identity.
for identity in gamma-agent alpha-relay; do
  openssl req -new -newkey rsa:3072 -nodes -keyout "$identity.key" \
    -out "$identity.csr" -subj "/CN=$identity"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$identity" > "$identity.ext"
  openssl x509 -req -in "$identity.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out "$identity.crt" -days 90 -extfile "$identity.ext"
done
openssl req -new -newkey rsa:3072 -nodes -keyout controller.key \
  -out controller.csr -subj /CN=pp-ubuntu-controller
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' > controller.ext
openssl x509 -req -in controller.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out controller.crt -days 90 -extfile controller.ext
```

Distribute only `ca.crt`, the relevant certificate and key to each service; adapt
example filenames (`gamma.crt/key`, `alpha.crt/key`) or copy their correctly issued
files to those configured paths. Keep CA key offline; never mount the entire PKI
directory into a runtime. Rotate via reviewed restart and certificate replacement;
gRPC does not hot-reload credentials or implement application-level CRL refresh.

## Controller Docker example

Dockerfile is for the **controller only**. The official
`python:3.12-slim-bookworm` base is pinned to the operator-verified manifest digest
`sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337`.
Image build remains a separate parent/operator check, not deployment authorization.
Example local-only commands:

```sh
docker build -t pp-ubuntu-controller:local .
# Prepare local state and read-only runtime credentials owned/readable by uid10001.
# ./runtime contains ONLY controller config/key/cert and ca.crt, not any CA key.
# Use examples/controller-docker.json as config.json; edit fixed addresses first.
mkdir -p ./state
# Operator sets ./state ownership to uid10001; do not make state world-writable.
docker run --rm --name cm-local --network YOUR_PRIVATE_TEST_NETWORK \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src="$PWD/state",dst=/state \
  --mount type=bind,src="$PWD/runtime",dst=/run/pp-ubuntu,readonly \
  -p 127.0.0.1:18000:8000 pp-ubuntu-controller:local /run/pp-ubuntu/config.json
```

The private network must resolve existing Auth as `auth`, and provide reviewed
routing to fixed private gRPC agents; the image does not deploy Auth/agents/Incus.
No root/host-network pod or Docker/Incus socket mount is justified. Same-origin
nginx integration/CI/Kubernetes are parent/operator scope, outside this directory.

## Backup and recovery runbook

- Back up controller **and both agent SQLite databases** using SQLite's backup API
  or `.backup`, not a lone copy of a live DB without WAL. Protect metadata backups
  and keep consistent timestamps. Preserve operator configs/certificate inventory;
  private key backup uses the existing secure secret mechanism, never Git.
  The node backup must include both `address_bindings_v1` and `native_tcp_v1`
  together with ownership (same SQLite snapshot); do not restore those tables
  independently or omit static NIC config from the guest restore. These tables
  add no fourth database. A restored address/UUID/MAC/config discrepancy blocks
  publication and requires operator reconciliation, never automatic reassignment.
- Guest root and custom `/home` volumes are separate. Operator-approved quiescing
  and Incus exports/snapshots must include both; instance export alone must not be
  assumed to include a custom volume. Restore on the same verified NVMe pool and
  project with UUID identities intact. Test a restore before release. There is no
  app-driven destructive restore/delete/recreate or automatic failover.
- On daemon failure: stop new mutations, examine sanitized operation/ownership
  states, compare actual owned Incus instance/device and listener/NAT state, and
  reconcile under an operator maintenance decision. Never clear registry rows or
  remove an error reservation merely because a process isn't currently listening.
- Resolve unsupported firewall snapshots by reviewed parser support/operator
  ownership analysis, not bypasses. Ambiguous Incus creates/proxies retain error
  ownership and may contain useful persistent data. Metadata changes to acknowledge
  a confirmed repair require a backed-up, reviewed operator procedure; no generic
  public “force reconcile” or arbitrary SQL endpoint is exposed.
- After restore/restart, list reconciliation marks discrepancies error. Verify
  original guest SSH host keys, packages, `/etc`, `/home`, limits and each explicitly
  published protocol/port before reopening admissions. No existing production
  workload restart, PV deletion, firewall flush or version upgrade is implied.
