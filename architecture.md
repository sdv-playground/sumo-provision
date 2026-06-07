# sumo-provision — architecture

> **Status:** living document. Keep it current as the code evolves.
> **Last updated:** 2026-06-05
>
> ## ⚠ Scope: development / test infrastructure only
> `sumo-provision` is for provisioning and updating **lab rigs** during
> development and testing. It is **not** a production OTA / fleet-management
> system and must not be used to manage real vehicles. Production provisioning
> uses a separate, offline, air-gapped signing path. The dev-only scope is what
> lets this design deliberately defer air-gapping, multi-tenant isolation, and
> key rotation (see [Status](#status)).

---

## 1. What this is

`sumo-provision` makes it a button-press for a tester or developer to bring up a
rig running the sumo stack and keep it on a software channel — instead of
hand-running per-rig provisioning scripts or `ssh`-ing in to swap binaries.

It is built from **two passive server-side "towers" plus one active
orchestrator**:

- **Tower 1 — Identity & Key Authority.** Owns device identity and key material.
  Blind to software.
- **Tower 2 — Software & Signing.** Owns content, channels, the digital twin, and
  the software signing key.
- **The orchestrator.** The only component that talks to *both* a tower and a
  rig. It relays identity, reports rig state, asks for an update, and flashes.

Neither tower ever connects to a rig. The orchestrator is the single point that
holds both a tower connection and a rig (SOVD) connection.

### Inspiration, and where it breaks
The UX model is Ansible Tower / AWX: an inventory of nodes, custody of
credentials, templated jobs, an audit trail, an API over the whole thing. Where
the analogy breaks: Tower pushes playbooks over SSH with reused credentials. Our
rigs are active diagnostic (SOVD) endpoints with their own A/B-bank state machine
(trial / commit / anti-rollback), and the "credential" is **per-device crypto**
(payload keys wrapped to each rig's public key), not one SSH key reused
everywhere. So: Tower-style control plane, SUIT/SOVD execution underneath.

---

## 2. Architecture at a glance

The dividing line between the towers is **identity/keys (T1) vs everything-software
(T2)**. "Software" includes the mutable parts — channels, the twin, the security
version — not just immutable blobs. T1 is pure identity and barely changes; T2
changes on every build.

The control-plane shape is **API server and kubelet**: the towers are a passive
control plane that gets *called* and never calls out; the orchestrator is the
kubelet — the only dual-homed component, pulling desired state and actuating
locally.

```
   tester / CI  ── publish (blobs, CEKs, hashes) ─▶ ┌─────────────────────────┐
        │                                           │  T2  Software Tower     │
        │ invoke / drive                            │  content-addr blobs,    │ passive
        ▼                                           │  channels, twin,        │ (never
  ┌──────────────┐   diff request + per-node ──────▶│  per-node signer        │  dials
  │ Orchestrator │◀── signed manifest ─────────────│  (sw-authority key)     │  a rig)
  │  the only    │                                  └─────────────────────────┘
  │  dual-homed  │   CSR + enrol + keystore ───────▶┌─────────────────────────┐
  │  component   │◀── signed keystore envelope ─────│  T1  Identity Tower     │ passive
  └──────┬───────┘                                  │  enrol, key-authority   │
         │                                          │  HSM, trust anchors,    │
         │ SOVD: flash, read state, unlock,         │  identity roster        │
         │ factory-reset                            └─────────────────────────┘
         ▼
  ┌──────────────────────────────────────────────┐
  │  the rig (SOVD node)                          │
  │  host orchestration + guest VMs               │
  │  A/B banks · non-volatile state · on-device   │
  │  HSM · secure boot                            │
  └──────────────────────────────────────────────┘
```

Because the towers never dial a rig:
- **No push.** The orchestrator polls or is invoked; a tower cannot nudge a rig.
  Fine for dev.
- **Single audit chokepoint.** Every "who flashed what onto which rig" fact passes
  through the orchestrator. The audit log lives there.
- **Towers need no route to the lab network** and hold no rig credentials.

---

## 3. Tower 1 — Identity & Key Authority

Binary: `sumo-ca` *(name provisional)*.

### Owns / holds / knows / blind-to
- **Owns** the identity roster — which rigs exist — keyed by the device CSR.
- **Holds** the **key-authority** private key, in an HSM it fronts (a soft-HSM in
  dev). Signs identity / keystore envelopes. Keys never leave the HSM: the
  provider exposes operations (`sign`, `unwrap`), never "give me the bytes."
- **Knows** **sw-authority public keys only** — enough to provision them into a
  rig's HSM as trust anchors. This is the "register the sw-authority" step.
- **Blind to** software, versions, and the anti-rollback security version. T1
  never signs software and never sees a channel.

### Identity roster
The inventory entry is the device identity (CSR / public key) plus dev metadata:
a label, an owner, and the rig's SOVD URL so the orchestrator can reach it.
Registration is "POST this CSR." Note: the roster is *identity only*. **What
software is on a rig is the twin, which lives in T2.**

### Enrollment / bootstrap (dev-simple)
No factory-floor ceremony. The trust root is "whoever can reach the rig's
factory-reset and CSR endpoints," which for a lab rig is acceptable.

1. Orchestrator factory-resets the rig → it wipes its HSM keystore, banks, and NV
   state and comes back clean.
2. The empty rig generates a fresh device key pair and serves a CSR.
3. Orchestrator fetches the CSR and **registers it with T1**.
4. T1 mints the rig's HSM keystore envelope — key-authority plus the chosen
   sw-authority public key(s) as trust anchors — signed by the key-authority and
   encrypted to the rig's CSR public key.
5. Orchestrator flashes the keystore envelope. The rig is enrolled.

T1 never reaches the rig — the CSR and the flash are **relayed by the
orchestrator**. The device *public* key is public, so relaying it leaks nothing.

### API sketch
```
POST   /rigs                  register a CSR → identity record
GET    /rigs/{id}             identity + metadata (NOT software state)
POST   /rigs/{id}/keystore    mint signed+encrypted HSM keystore envelope
POST   /sw-authorities        register an sw-authority PUBLIC key (a trust anchor)
GET    /healthz   /version
```

---

## 4. Tower 2 — Software & Signing

Binary: `sumo-hub` *(name provisional)*. Owns content, channels, the twin, the
security-version semantics, **and the software (sw-authority) signing key**.

### 4.1 Content & encryption — encrypt once, two hashes
Each artifact is encrypted **exactly once**. T2 keeps three things per artifact:
the **CEK** (content-encryption key), the **inner hash** (of the plaintext), and
the **outer hash** (of the ciphertext).

- The **ciphertext** is the content-addressed blob, keyed by the outer hash —
  shared across every rig, cacheable, de-duplicated. Per-device-ness never touches
  the big bytes.
- Two hashes, two jobs: the **outer hash** content-addresses the blob and verifies
  the download; the **inner hash is the device-independent identity of the
  software** — it verifies decryption, and it is the *same hash the rig already
  uses for secure boot* (the signed manifest carries it; the rig verifies on-disk
  content against it at boot). Secure-boot identity, twin identity, and diff key
  are one value, not three.
- Re-encrypting an artifact (new CEK → new outer hash) does **not** move the inner
  hash, so it never triggers a false "needs update."
- The blob store holds only ciphertext, useless without the CEKs — so the big
  bytes can live on dumb/cheap object storage, and the guarded secret is T2's
  small key index, not the rootfs.

### 4.2 Channels
A channel is a **mutable named pointer** that resolves to an immutable manifest
hash — like a git branch → commit, or a container tag → digest.

- `stable` → the last blessed / tagged release. `bleeding-edge` → the latest green
  `main` build. `release/x.y.z` → a pinned tag.
- **Promotion is pointer juggling over immutable content.** Git is the upstream
  truth for *what gets built*; T2 holds a thin pointer table
  (`channel → manifest_hash, source_ref, updated_at`) plus the twin. T2 **records**
  what CI and tags resolved to; it does not **decide** what is blessed.
- Channels are **whole-system, coherent sets** (the whole rig blessed together),
  never per-component — otherwise you get combinatorial "which mix was ever
  tested."
- Channel pointers double as **garbage-collection roots**: a blob no channel
  reaches is collectable.

### 4.3 Override — an overlay, not a channel
"Channel + my local build" is a **per-invocation overlay**, not a third channel.
Channels are shared and mutable (others subscribe); an override is personal and
ephemeral. Mechanism: take the channel's resolved set and swap one component's
inner hash for the developer's local build. Because content is addressed by hash,
a local build and a CI build are **indistinguishable to the rig** — both are just
blobs. The developer publishes their local artifact to T2 and the orchestrator
composes the effective manifest.

### 4.4 The twin & diff-based dispatch
T2 holds, per rig, the **observed installed state** (the twin), keyed on the inner
hash. Because T2 holds both the channel (desired) and the twin (observed), an
update is `reconcile(observed, desired)` — flash only what differs.

- The twin is a **cache**; the rig is ground truth (its reported version + image
  hash). Populate write-through on flash, reconcile by read-back against the rig
  to catch drift. The rig must **persist the inner (plaintext) hash at install**
  so reporting the twin is an O(1) lookup, not a re-hash of the rootfs every poll.
- The security version is a manifest field; the **rig** enforces the anti-rollback
  floor. T2 knows the numbers and can pre-warn "the rig will reject this
  downgrade," but T1 never counts. Dev downgrade = factory-reset (wipes the floor)
  then diff-from-empty.

### 4.5 Per-node manifest signing
T2 is the **single software signer**. At dispatch it builds a **per-node
manifest**: it wraps the CEK to the rig's device public key (supplied by the
orchestrator with the request — public, so T1 stays out of the software path) and
carries both hashes. The whole per-node manifest is signed by the **sw-authority
private key T2 holds** (in its own soft-HSM). Signing is sub-millisecond; the hot
path doesn't care. Because T2 signs, developers route local builds through T2's
signer and no per-developer signing key is needed.

### API sketch
```
# read surface (orchestrator / rig)
GET    /rigs/{id}/updates?channel=…   diff(twin, channel[+overrides]) →
                                      per-node signed manifest, or "nothing"
GET    /manifests/{hash}              immutable, content-addressed
GET    /blobs/{hash}                  ciphertext blob, range-able, cacheable
# state + publish surface
PUT    /rigs/{id}/twin                report observed state (inner hashes)
PUT    /rigs/{id}/channel             set subscription {rig → channel}
POST   /admin/artifacts               publish: ciphertext blob + CEK + hashes
PUT    /admin/channels/{name}         advance a channel pointer (CI / importer)
GET    /healthz   /version
```

A CI importer is just a publisher: it pulls CI artifacts with a CI job token and
calls `/admin/artifacts` + `/admin/channels`.

### 4.6 The vehicle model & diff

A vehicle is modelled as a **tree of entities, each holding content-hashed
parts**; a release describes the desired tree; the diff aligns observed (a rig)
against desired (a release / channel). The model is **schema-agnostic** — `kind`s
are open strings, so the engine never hardcodes any fleet's component types.
(In `wire`: `Entity`, `Part`, `Tree`, `diff`.)

- **Entity** — a tree node `{ path, kind, parent }`. The tree *is* composition,
  mirroring SOVD's entity hierarchy, so the observed tree is a recursive walk of
  components → sub-entities. Paths carry the shape (`vehicle`, `vm1`,
  `vm1/sovd/myapp`); the parent of `a/b/c` is `a/b`.
- **Part** — an updatable unit on an entity `{ kind, id, content_hash }`. The
  unifying move: *everything* updatable is "a logical id + a content hash" — a
  bank file → `(vm1, file, "kernel", sha256)` (what `x-sumo-installed-manifest`
  gives); a container image → `(vm1/sovd/myapp, oci-image, "image", digest)`;
  vehicle parameterization → `(vehicle, param-blob, "params", sha256)`.
- **Release** — a desired snapshot of the tree (entities + parts), content-
  addressed + sw-authority-signed. **Channel** — a mutable pointer → a release.
- **Relations** — *composition* is the tree; *dependencies* are typed edges
  (`vm1/sovd/myapp depends-on vm1 ≥ 1.0.0`, `params configures vm1`), stored as
  data, driving ordering/validation later.

**The diff** walks observed + desired, aligns entities by path, compares parts by
`(id, content_hash)` → added / changed / removed, plus entity added / removed.
It is "what an update would touch" — uniform across files, containers, and blobs.

**Delta & bank isolation.** Flashing is **per-component A/B**: an update writes a
component's *inactive* bank, then the device copies every file the update did not
carry from that **same component's active bank** (vm-mgr's `seed_target_from_active`,
by slot). So the orchestrator's delta job is only to compute each component's
**ship-set** — the parts whose content differs from (or is absent in) that
component's *own* active bank; the rest the device reuses bank-to-bank.
`flash_plan(observed, desired)` does exactly that, classifying each desired part
`Ship` or `Reuse`, scoped strictly per component — **a component is never sourced
from another's bank** (no cross-component data flow), even when two components hold
byte-identical content (e.g. a shared CA bundle). Content addressing still earns
its keep at Tower 2: when a part *is* shipped, encrypt-once de-dups storage and the
build step's existence check (`GET /admin/artifacts/{inner}`) skips re-uploads.

**Update mode & the no-mix guard.** The device reports each component's update
capability (`x-sumo-update-mode`: `banked`/rollbackable vs `singleshot`/
irreversible — the HSM keystore). `read_rig_state` syncs it onto the twin
(`Entity.update_mode`, the device is the source of truth), and `apply_plan`
**rejects a campaign that mixes rollbackable with irreversible** components — a
rollback would leave the device undefined, so the HSM keystore flashes as its own
campaign. Unknown (older firmware that doesn't serve it) degrades gracefully.

**Public vs private.** The model + SQL schema + diff are public and generic; the
real entities/parts/releases are *rows*, seeded from the internal-workspace
example — nothing fleet-specific touches the engine.

---

## 5. The orchestrator

The reconcile loop:
1. **report** — read the rig's state, `PUT /rigs/{id}/twin`.
2. **set channel** — `PUT /rigs/{id}/channel`.
3. **ask if needed** — `GET /rigs/{id}/updates?channel=…`; T2 computes the diff
   server-side and returns a per-node signed manifest or "nothing."
4. **apply** — drive the flash over SOVD (unlocking via the security helper),
   pulling shared blobs from T2.
5. **report** — write the new twin back.

### Self-healing, not a resumable transcript
The loop reconciles, so after any reboot or revert the orchestrator **re-observes
and re-diffs** — it never replays a transcript and never has to *detect* "I was
reverted," it reads reality and recomputes. The only durable state is **intent**
(which channel, which campaign is in flight, am I inside a trial window), and even
that defers to the rig as source of truth. *Re-observe beats remember.*

### Two drivers, one core
The orchestration core is a shared library with two thin drivers:
- **Now — a tester CLI (off-rig).** Authenticates to the towers as a developer.
- **Later — a daemon on the rig.** Auto-reconciles, authenticates as the device.
  It is a **T2-only client**: keeping a rig current on a channel needs only T2;
  enrollment / re-key are inherently external, tester-time operations against an
  empty rig. So **T2 self-drives, T1 stays in the tester's hands.**

### The self-update problem
A reconciler running *on* a rig cannot cleanly update the guest it runs in (when
that guest reboots into its trial slot, the reconciler dies with it). The dev
answer is to (a) persist intent durably so the restarted reconciler resumes, and
(b) rely on the host's existing per-component auto-rollback as the backstop, and
(c) host the reconciler in the **least-churny** guest so the hard case is rare.

---

## 6. Trust & crypto model

### Authorities — where each half lives
| Authority | Private half | Public half | Signs |
|---|---|---|---|
| **key-authority** | Tower 1's HSM | provisioned into rig HSM | identity / keystore envelopes |
| **sw-authority** | **Tower 2's** HSM | **registered with T1**, provisioned into rig HSM | per-node software manifests |

The rule the whole design hangs on: **T1 holds the sw-authority's public key,
never its private half.** T1 signs key material that *names* the software trust
anchor; T2 *is* the software signer. Keep T2's signing key in **T2's own** HSM —
if T2 ever called T1 to sign software, T1 would be back in the software path and
the boundary leaks.

### End to end
```
publish:   plaintext ──encrypt once(CEK)──▶ ciphertext
           keep {CEK, inner_hash(plaintext), outer_hash(ciphertext)}
           push ciphertext → /blobs/{outer_hash};  CEK,hashes → T2 index

dispatch:  diff(twin.inner_hashes, channel.inner_hashes) → parts that differ
           per-node manifest = {parts:[{inner_hash, outer_hash, blob_uri}],
                                CEK wrapped to rig pubkey}  signed by sw-authority

on-rig:    fetch /blobs/{outer_hash} (shared) → verify outer_hash
           unwrap CEK with device key (in HSM) → decrypt → verify inner_hash
           secure boot re-verifies on-disk content against the signed inner_hash
```

### `kid` now, rotation later
Key rotation is deferred — soundly, on one condition: **put a key id (`kid`) on
every signature and every trust-anchor slot now.** The pain of no rotation is the
verifier-chain break, not the missing mechanism. With a `kid` on everything,
rotation later is purely additive: provision `kid2` beside `kid1`, sign with
`kid2`, retire `kid1` once no rig references it — no retrofit. The dev safety net
that makes this extra-deferrable: factory-reset + re-enroll is rotation of last
resort.

### Personas → signing surface
- **Testers** consume tagged releases — pre-signed by T2; they need **zero**
  signing capability.
- **Developers** want base channel + local override; their builds are published to
  T2 and signed by T2.

The day a developer wants to sign **without** the T2 round-trip is the day to add
**delegated trust** — a second sw-authority slot in the rig's HSM holding that
developer's public key, so the rig trusts central + developer at once. Additive,
and deferred.

---

## 7. Stack & deployment

- **Language:** Rust across the board (reuses the stack's SUIT/COSE/SOVD tooling).
- **Deployment:** Docker; a `docker-compose` brings up the full local environment
  in one command — T1, T2, Postgres, and an S3-compatible object store (MinIO).
- **Postgres — metadata/index only.** Channel pointers, the twin, the artifact
  index (CEK references + inner/outer hashes + versions), the identity roster.
  **T1 and T2 use separate databases + roles** so a Tower 2 compromise cannot read
  Tower 1's identity data — the crown-jewel/software split enforced at the DB
  boundary.
- **Object store — blobs.** Ciphertext blobs, content-addressed by outer hash.
  MinIO locally, S3 in a hosted deployment. Never in Postgres.
- **Soft-HSM keystores — key material.** Key-authority (T1) and sw-authority (T2),
  each behind the `HsmProvider` abstraction in its own keystore. Never in Postgres.
  The abstraction means "real HSM later" is a backend swap, not a refactor.

### Dependency hygiene (this is a public repo)
Integrate with the rest of the sumo stack **over the wire** (SOVD/SUIT HTTP), not
via internal crate links where avoidable, so the public repo doesn't drag private
crates in. For each reused capability (SOVD client, SUIT signing, the HSM
provider, the crypto primitives) we decide, as we build, whether it is published
as a public crate or integrated at the wire. Track those decisions here.

---

## 8. Repository layout

```
sumo-provision/
├── architecture.md          ← this document (keep current)
├── README.md
├── docker-compose.yml        ← local: T1 + T2 + Postgres + MinIO
├── Cargo.toml                ← workspace
├── crates/
│   ├── wire/                 ← shared types: manifest, hash pair, channel, twin
│   ├── identity-tower/       ← T1 service (binary: sumo-ca)
│   ├── software-tower/       ← T2 service (binary: sumo-hub)
│   ├── client/               ← typed T1/T2 clients (the orchestrator links these)
│   └── cli/                  ← tester/admin CLI (publish, channels, register, reconcile)
├── migrations/               ← Postgres (per-tower)
└── docker/                   ← Dockerfiles per service
```

Crates are named by function so the repository name is not woven into package
names.

---

## 9. Status

### Locked
- Dev/test only; production stays on the offline signing path.
- Two towers on the **identity vs software** axis; T1 blind to software.
- **T2 is the single software signer** and holds the sw-authority key.
- **Encrypt-once + dual-hash**; diff on the **inner (plaintext) hash**;
  content-address ciphertext by the outer hash.
- **Towers passive; the orchestrator is the only dual-homed component.**
- The twin lives in T2; updates are diffs between twin and channel.
- A `kid` on every signature and trust anchor from day one.

### Deferred
- Per-developer **delegated trust** (a second sw-authority slot).
- Key **rotation** mechanism (the `kid` makes it additive later).
- **Push** notifications (pull-only for now).
- The **on-rig reconciler daemon** (build the off-rig CLI first; same core).
- Multi-tenant / multi-fleet isolation.
- Shareable **named personal channels** (override is overlay-only for now).

### Open questions
1. Promotion mechanics — precise shape of "git decides, T2 records."
2. Orchestrator cadence — one-shot CLI vs standing reconciler (likely split by
   persona).
3. Who drives a rig's *own* self-update across its reboot.
4. The soft-HSM backend and the path to a real HSM without an artifact-format
   change.
5. Confirming the rig persists the plaintext image hash for O(1) twin reporting.

---

## 10. Roadmap (rough; subject to the open questions)
1. **T2 content core** — *done.* `POST /admin/artifacts` (encrypt-once via
   `sumo-offboard`, AES-128-GCM) + `GET /blobs/{outer}`; filesystem blob store + Postgres index
   (CEK kept out of the blob store). Manifests deferred to land with channels.
2. **Client lib + CLI** — *done.* Reusable `client` crate (`SoftwareClient` for
   T2, `IdentityClient` for T1, same pattern) + the `sumo-provision` CLI (`hub`
   publish/get/ping, `ca` ping). Next: the orchestrator's `FirmwareResolver`
   builds on `client` to fetch a package and flash a rig.
3. **Channels + twin + diff** — *in progress.* Done: the schema-agnostic vehicle
   model + `wire::diff` (§4.6); the channel storage (L2 `component_releases`, L1
   `vehicle_releases` = the desired whole-vehicle state, `channels` pointer;
   `GET /channels/{name}/tree` resolves to the desired `wire::Tree`); content
   existence (`GET /admin/artifacts/{inner}`) so a build step skips re-uploads;
   twin reporting (the orchestrator reads the rig's observed tree over SOVD); a
   build/publish step that mints releases and advances a channel (the private
   `seed-bleeding.sh`); `sumo-provision rig diff --channel <name>` diffs the rig
   against a channel, and `--plan` emits the per-component delta
   (`wire::flash_plan` → ship vs reuse; each component reuses only its own active
   bank, never another's, mirroring the device's `seed_target_from_active`);
   `sumo-provision rig apply --channel <name>` (`orchestrator::apply_plan`)
   resolves the ship-set against Tower 2 — confirming Tower 2 can serve every
   shipped part, flagging any it can't, and totalling the transfer;
   `sumo-provision rig flash --channel <name> --device <id>`
   (`orchestrator::flash_bundle`) assembles the per-device flash bundle — a
   signed SUIT envelope per component (Tower 2 builds it, CEK re-wrapped to the
   device's Tower 1 key) plus payload refs — *dry* by default, exactly what would
   be uploaded over SOVD, without touching the rig. `--execute --token <jwt>`
   drives the *wet* flash (`orchestrator::flash_execute` → `FlashClient`:
   open_update → upload manifest + payloads → prepare → execute, with the JWT as a
   `Bearer` header), staging banked components to awaiting-verdict; the
   no-mix guard runs first. Next: the verdict (ECU reset when safe → commit /
   rollback) and minting the JWT from `sovd-token-helper`. (In-vehicle UDS unlock
   happens after the JWT auth, device-side.)
4. **T2 per-node signer** — *done.* A sw-authority ES256 key (persisted via
   `--signing-key`, generated on first run); `build_envelope` re-wraps each
   part's stored CEK to a device's key (`rewrap_cek_ecdh`, no re-encryption) and
   signs a per-device multi-component SUIT manifest via `sumo-offboard`. Exposed
   as `GET /admin/signer/pubkey` (the trust anchor) + `POST /admin/envelope`
   (resolve parts from the index → signed envelope). Proven by an encrypt-once →
   re-wrap → build → validate → decrypt roundtrip. `kid` deferred (the trust
   anchor is the pinned sw-authority public key).
5. **T1 (`sumo-ca`)** — *in progress.* The device identity roster
   (`POST /admin/devices`, `GET /devices`; its own `sumo_ca` DB so its
   migrations stay independent of Tower 2's) + `ca register` is done. Next:
   keystore minting, wired to the factory-reset + CSR enrollment flow.
6. **CI importer** — job-token publish + channel advance.
7. **Collapse the per-rig scripts** to a registration + a channel subscription.
8. **(Later)** on-rig reconciler daemon; delegated trust; rotation.

---

## 11. Going public (later)
Before this repo is published: add a LICENSE, a CONTRIBUTING guide, CI, and a
security policy; scrub any internal references; confirm every dependency is a
public crate or wire-level integration (§7).
