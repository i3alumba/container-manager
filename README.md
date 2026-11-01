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

## Current release blockers

Extraction does **not** approve deployment or alter runtime behavior. Real-path
acceptance found intermittent reply truncation after TCP half-close through the
current gamma Incus TCP proxy. Normal SSH/TCP echo and UDP nonce replies worked,
but generic TCP release remains blocked; local tests do not waive this failure.
Additional TCP-edit, native power/restart and full root-plus-home restore gates
remain unaccepted. The restricted project currently denies backup creation; no
restriction has been relaxed. Proposed TCP-target behavior and operator backup
permission changes require explicit approval. Parent release PR
[#185](https://github.com/LumbaBalumba/public-page/pull/185) remains Draft.
New native application units and test forwarding were stopped/disabled; only an
owned stopped scratch guest retains test data. Existing production workloads and
credentials are not changed by this repository extraction.

## Architecture and trust boundaries

```text
browser -> same-origin nginx /api/containers/ -> controller (non-root)
    controller -> http://auth:8000/api/user/ (live explicit bearer, every request)
    controller -- private gRPC/mTLS --> gamma node agent (host root / Incus socket)
    controller -- private gRPC/mTLS --> alpha relay (unprivileged native process)
WAN:port -> upstream NAT -> alpha LAN relay -> gamma 10.200.73.2:same-port -> Incus proxy -> guest
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
  Every CLI call uses argv, fixed `--project pp-ubuntu`, no shell. Only a constant
  guest bootstrap uses `/bin/sh -c`.
- Full persistent root, including `/etc`, packages and SSH host keys; separate
  managed custom volume `<owned-name>-home`, mounted at `/home` from the same pool.
  Stop/start/port/password changes never recreate or delete either volume.
- Uses only the fixed operator-managed project `default` profile; never overrides
  its root pool, managed NIC, IPv4/IPv6/MAC filtering or port isolation. The agent
  verifies that exact fixed profile (including no extra devices) before creation,
  and fails closed on operator drift. Explicit
  `security.privileged=false`, `security.nesting=false`,
  `security.idmap.isolated=true`. Operator must verify
  subordinate ID ranges/kernel support. Minimal Ubuntu plus openssh-server and CA
  certificates, not Java/games. Guest root SSH password login is intentional;
  effective sshd settings and syntax are checked by constant bootstrap commands.
- CPU integer 1..4, never bool; decimal memory >0 and <=16 GB, up to three decimal
  places (GB = 1,000,000,000 bytes). Aggregate default is **4 CPU / 16 GB**, including
  stopped/error guests. Operator can explicitly change the bounded pool budget.
  Existing k3s workloads retain priority. No storage quota or automatic low-space
  admission protection is implied: separately monitor NVMe capacity/inodes.

## Browser API v1

All routes, including list/capabilities/check, require an explicit
`Authorization: Bearer ...` header. Cookies alone do not authorize. Every request
calls `http://auth:8000/api/user/`, with 1s connect / 3s IO timeouts, environment
proxies and redirects disabled. `is_active is True` and `is_staff is True` are both
required; missing/string/numeric flags fail. There is no positive grant cache.
401 unauthenticated, 403 ineligible, 409 conflict, 422 invalid input, 503 unavailable
Auth/host inspection. Generic errors contain only fixed `detail.code/message`.
Mutations audit actor/action/resource/result, never request bodies/tokens/passwords.

Base: same-origin `/api/containers/`. Routes are slash-exact; no redirect is needed.

`GET capabilities`:

```json
{
  "administrator": true,
  "node": "gamma",
  "max_cpu": 4,
  "max_memory_gb": 16,
  "domain_suffix": "hosting.i3alumba.ru",
  "image": "Ubuntu 24.04 LTS",
  "disk_quota": false,
  "home_separate": true,
  "root_persistence": "full",
  "external_ingress_ready": true,
  "public_port_ranges": { "tcp": [[3000, 50000]], "udp": [[3000, 50000]] },
  "aggregate_budget": { "cpu": 4, "memory_gb": 16 }
}
```

`GET /` returns `{instances:[Instance,...]}`. Each Instance has
`{id,name,domain,node,status,cpu,memory_gb,ports,created_at,updated_at,error}`.
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
3. Gamma adds only the UUID-owned Incus proxy, bound to
   `10.200.73.2:public_port`, connecting inside the guest to
   `127.0.0.1:target_port`. Incus success **and kernel socket presence on that fixed
   address** establish readiness, not guest service reachability.
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
alpha allocations; gamma proxies bind again on start. Explicit remove errors may
leave a mapping unavailable but reserved until operator review.

## Operator prerequisites (not performed by this implementation)

- Separate authorized release/deployment decision, dev-based feature PR -> dev,
  then dev -> master. No automatic release from this directory.
- Preserve all existing mounts/volumes/workloads. Incus7.5.1, local Unix socket,
  fixed restricted project, NVMe dir pool at the path above, reviewed `ppub0`
  address/native ACLs, Ubuntu fingerprint and private certificate authority.
- Fixed project default profile must retain SSD root and `eth0` on `ppub0` with
  IPv4/IPv6/MAC filtering and port isolation. The app uses no network/root-device
  overrides; review operator drift before admissions. Shared default-project image
  cache is supported (`features.images=false`). Project CPU/memory limits should
  independently enforce the 4 CPU / 16GB baseline; VM limit0; managed-only disks/NICs,
  isolated privilege, blocked nesting and proxy permission.
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
  mTLS. Gamma proxy INPUT is limited to alpha's source, with all infrastructure
  and NodePorts returned to the incumbent policy. No NAT/FORWARD/Docker rule is
  changed. Whole-filter inspection errors fail before mutation; exact leading
  hooks and owned chain contents must match on repeat. Partial state, duplicates,
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
`pool_cpu/pool_memory_gb`. Node additionally requires `wireguard_ip`, `gamma_ip`,
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
