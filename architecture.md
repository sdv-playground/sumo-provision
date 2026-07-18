# sumo-provision — architecture

> **Status:** living document. Keep it current as the code evolves.
> **Last updated:** 2026-07-18
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
- **Tower 2 — Software & Signing.** Owns content, channels/targets, and the
  software signing key.
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
(T2)**. "Software" includes the mutable parts — channels/targets, the security
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
        ▼                                           │  channel targets,       │ (never
  ┌──────────────┐   state + channel target ───────▶│  per-device signer      │  dials
  │ Orchestrator │◀── signed L1 campaign ──────────│  (sw-authority key)     │  a rig)
  │  the only    │                                  └─────────────────────────┘
  │  dual-homed  │   CSR + enrol + keystore ───────▶┌─────────────────────────┐
  │  component   │◀── signed keystore envelope ─────│  T1  Identity Tower     │ passive
  └──────┬───────┘                                  │  enrol, key-authority   │
         │                                          │  CA, trust anchors,     │
         │ SOVD (JWT bearer): flash, read state,    │  identity roster        │
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

Binary: `sumo-ca`.

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
software is on a rig is observed from the rig itself (§4.4) — never stored
in T1.**

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

### API (as built — `crates/identity-tower`)
```
POST   /admin/devices               register a CSR → identity record
GET    /devices    /devices/{id}    roster: identity + metadata (NOT software state)
POST   /admin/devices/{id}/enroll   mint the signed+encrypted HSM keystore envelope
GET    /admin/ca/cert               the key-authority (CA) certificate
GET    /admin/ca/trust-bundle       trust anchors to provision into a rig
GET    /healthz   /version
```
CLI: `ca register / device / enroll / mint-keystore / ca-cert / trust-bundle`;
the rig side installs with `rig install-keystore` (relayed, as designed — T1
never touches the rig).

---

## 4. Tower 2 — Software & Signing

Binary: `sumo-hub`. Owns content, channels/targets, the security-version
semantics, **and the software (sw-authority) signing key**.

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
  content against it at boot). Secure-boot identity, reported-state identity,
  and delta key are one value, not three.
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
  truth for *what gets built*; T2 holds a thin pointer table — a channel target
  keyed `(channel, device, architecture) → vehicle release` — over immutable,
  content-addressed releases. T2 **records** what CI and tags resolved to; it
  does not **decide** what is blessed. Governance (audit, blessing) sits at the
  promotion boundary; the vehicle just executes signed manifests.
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

### 4.4 Observed state & delta dispatch
The stored per-rig twin never materialized — better: **T2 keeps no per-rig
state at all**. The orchestrator reads the rig's observed tree over SOVD each
run (ground truth, always fresh — the rig persists plaintext digests in its
installed manifest, so this is a read, not a re-hash) and supplies it **with
the request** (`current_state` on the L1 endpoint). Delta happens at three
layers, outermost first:

- **Tower-side skip:** `channel_target_l1` omits components whose plaintext
  digest already matches, so the signed L1 carries only what differs or is
  unknown; nothing differs → `204 No Content` and the orchestrator
  short-circuits.
- **Orchestrator push-diff (fallback):** components the vehicle already holds
  are pushed **manifest-only** (an L2 with no payload bytes), matched by
  digest so bank remaps can't fool it.
- **Device copy-forward (the safety):** for every component the update did not
  carry bytes for, the device copies its **own active bank** forward,
  verifying the copied plaintext digest against the signed manifest —
  mismatch is an error. The orchestrator's delta is the *optimization*; the
  device's digest check at copy time is the *authority*.

The security version is a manifest field; the **rig** enforces the
anti-rollback floor. T2 knows the numbers and can pre-warn "the rig will
reject this downgrade," but T1 never counts. Dev downgrade = factory-reset
(wipes the floor) then diff-from-empty.

### 4.5 Per-device campaign signing
T2 is the **single software signer**. At dispatch it builds a **per-device L1
campaign**: the L1 names one L2 per component with content-addressed payload
URIs (`sha256:<outer>`), each component's CEK wrapped to the rig's device
public key (supplied by the orchestrator with the request — public, so T1
stays out of the software path), the whole thing signed by the **sw-authority
private key T2 holds**. The orchestrator *relays* the device pubkey and *fans
out* the signed result; it never wraps or signs anything itself. Because T2
signs, developers route local builds through T2's signer and no per-developer
signing key is needed.

### API (as built — `crates/software-tower`)
```
# dispatch surface (orchestrator)
POST   /channel-targets/l1        state-in → signed-L1-out: resolve the
                                  (channel, device, architecture) target,
                                  skip components current_state already has,
                                  sign per-device; all-agreed → 204
GET    /channel-targets/tree      the desired wire::Tree (operator preview/diff)
GET    /blobs/{outer}             ciphertext blob, content-addressed, cacheable
# publish + admin surface
POST   /admin/artifacts           publish: ciphertext blob + CEK + hashes
GET    /admin/artifacts/{inner}   existence check (build steps skip re-uploads)
POST   /admin/component-releases  mint an L2 (component release)
POST   /admin/vehicle-releases    mint an L1 tree (whole-vehicle release)
PUT    /admin/channel-targets     point (channel, device, architecture) → release
POST   /admin/channels            advance a channel pointer (CI / importer)
POST   /admin/envelope            per-component signed envelope (re-wrap CEK)
GET    /admin/signer/pubkey       the sw-authority trust anchor
GET    /healthz   /version
```

A CI importer is just a publisher: it pulls CI artifacts with a CI job token and
calls the publish surface.

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
carry from that **same component's active bank** (component-mgr's
`seed_target_from_active`, by slot; digest-verified copy-forward, §4.4). So the
delta's job is only to compute each component's **ship-set** — the parts whose
content differs from (or is absent in) that component's *own* active bank; the
rest the device reuses bank-to-bank. The authoritative version of that decision
is the tower-side skip + push-diff (§4.4); the client-side
`flash_plan(observed, desired)` (`Ship`/`Reuse` per part) survives as the
**read-only operator preview** (`rig diff --plan` / `rig apply`). Both are
scoped strictly per component — **a component is never sourced from another's
bank** (no cross-component data flow), even when two components hold
byte-identical content (e.g. a shared CA bundle). Content addressing still earns
its keep at Tower 2: when a part *is* shipped, encrypt-once de-dups storage and the
build step's existence check (`GET /admin/artifacts/{inner}`) skips re-uploads.

**Update mode & the no-mix guard.** The device reports each component's update
capability (`x-sumo-update-mode`: `banked`/rollbackable vs `singleshot`/
irreversible — the HSM keystore). `read_rig_state` carries it on the observed
tree (`Entity.update_mode`, the device is the source of truth), and the guard
**rejects a campaign that mixes rollbackable with irreversible** components — a
rollback would leave the device undefined, so the HSM keystore flashes as its own
campaign. Unknown (older firmware that doesn't serve it) degrades gracefully.

**Public vs private.** The model + SQL schema + diff are public and generic; the
real entities/parts/releases are *rows*, seeded from the internal-workspace
example — nothing fleet-specific touches the engine.

---

## 5. The orchestrator

The campaign loop (`orchestrator::campaign_execute`, driven by
`rig campaign --channel <name> --device <id> --architecture <arch>`):
1. **observe** — `read_rig_state` walks the rig's SOVD entity tree into a
   `wire::Tree` (plaintext digests from the installed manifest).
2. **ask** — `POST /channel-targets/l1` with the observed state; T2 resolves the
   `(channel, device, architecture)` target, skips agreed components, and
   returns a per-device **signed L1 campaign** — or `204`, done.
3. **fan out** — decode the L1 into per-component L2s; fetch each shipped
   ciphertext from the blob store by content address; unchanged components get
   their L2 manifest-only.
4. **drive** — group by the device-reported update mode
   (banked vs singleshot, the no-mix guard first), then run the shared flash
   engine's campaign lifecycle per step: stage → reset → health-gate →
   commit/rollback, on one committed baseline.
5. **authorize** — every SOVD write carries a JWT bearer. The token comes from
   `--token` or is minted on demand from the workshop minter
   (`client::MinterClient`; `RigToken` re-mints when the rig's boot id moves,
   since reset routes are boot-bound). In-vehicle UDS unlock is **transparent
   and device-side** after token auth — never an orchestrator step.

### Self-healing, not a resumable transcript
The loop reconciles, so after any reboot or revert the orchestrator **re-observes
and re-diffs** — it never replays a transcript and never has to *detect* "I was
reverted," it reads reality and recomputes. The only durable state is **intent**
(which channel, which campaign is in flight, am I inside a trial window), and even
that defers to the rig as source of truth. *Re-observe beats remember.*

### Two drivers, one core
The orchestration core is a shared library (`crates/orchestrator`) with thin
drivers:
- **The tester CLI** (`sumo-provision rig …`) — authenticates to the towers as
  a developer; campaigns, previews, verdicts, enrollment relay.
- **The workshop autoloader** (external repo) — embeds the orchestrator crate
  as a library (no CLI shelling) and supervises the composed tower stack for
  pull-and-run delivery.
- **Later — onboard.** An in-vehicle orchestrator consuming the same signed
  campaigns (pull), exposed as a SOVD `update` operation. Inherently a
  **T2-only client**: keeping a rig current needs only T2; enrollment / re-key
  stay tester-time operations against an empty rig. **T2 self-drives, T1 stays
  in the tester's hands.**

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
| **sw-authority** | **Tower 2's** HSM | **registered with T1**, provisioned into rig HSM | per-device L1/L2 campaign manifests |

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

dispatch:  T2 skips parts whose inner_hash the supplied observed state
           already holds (state-in) → signed per-device L1 campaign
           = per-component L2s {inner_hash, outer_hash, sha256: blob uri,
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
- **Deployment:** three rungs. Dev loop: root `docker-compose.yml` brings up the
  backing services (Postgres, MinIO) and `start.sh` runs both towers as host
  processes (rebuild with cargo, no image rebuild). Packaging: the repo
  `Dockerfile` builds one runtime image carrying both binaries. The composed
  pull-and-run stack (towers + the workshop minter + per-tower Postgres + MinIO)
  lives in a separate internal integration repo that submodules this one — see
  the README's "Container image" section.
- **Postgres — metadata/index only.** Channel targets and releases, the artifact
  index (CEK references + inner/outer hashes), the identity roster. **T1 and T2
  use separate databases** (independent migration sets under each tower crate)
  so a Tower 2 compromise cannot read Tower 1's identity data — the
  crown-jewel/software split enforced at the DB boundary. No per-rig state (§4.4).
- **Object store — blobs.** Ciphertext blobs, content-addressed by outer hash.
  MinIO locally, S3 in a hosted deployment. Never in Postgres.
- **Key material — on-disk key files, never in Postgres.** Key-authority (T1,
  `SUMO_CA_KEY`) and sw-authority (T2, `SUMO_HUB_SIGNING_KEY`) are
  auto-generated on first run at env-configured paths. Moving them behind an
  HSM-provider abstraction is a deferred backend swap, not a format change.

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
├── docker-compose.yml        ← local backing services: Postgres + MinIO
├── Dockerfile                ← one runtime image, both tower binaries
├── start.sh                  ← dev loop: towers as host processes
├── Cargo.toml                ← workspace
└── crates/
    ├── wire/                 ← shared types: vehicle model (Entity/Part/Tree),
    │                            diff, flash_plan, hash pair, releases
    ├── identity-tower/       ← T1 service (binary: sumo-ca) + its migrations/
    ├── software-tower/       ← T2 service (binary: sumo-hub) + its migrations/
    ├── orchestrator/         ← the campaign core (embedded by drivers)
    ├── client/               ← typed T1/T2/minter clients
    └── cli/                  ← tester CLI (binary: sumo-provision)
```

Crates are named by function so the repository name is not woven into package
names.

---

## 9. Status

### Locked
- Dev/test only; production stays on the offline signing path.
- Two towers on the **identity vs software** axis; T1 blind to software.
- **T2 is the single software signer** and holds the sw-authority key.
- **Encrypt-once + dual-hash**; delta on the **inner (plaintext) hash**;
  content-address ciphertext by the outer hash.
- **Towers passive; the orchestrator is the only dual-homed component.**
- **State-in → signed-L1-out**: T2 keeps no per-rig state; observed state
  rides the dispatch request; delta = tower skip → manifest-only push →
  device digest-verified copy-forward (§4.4).
- **JWT bearer** authorizes every SOVD write (workshop minter); UDS unlock is
  transparent and device-side — never an orchestrator step.
- The **no-mix guard**: rollbackable and irreversible components never share
  a campaign.

### Deferred
- A `kid` on signatures/trust anchors + key **rotation** (today the trust
  anchor is the pinned sw-authority public key; factory-reset + re-enroll is
  rotation of last resort).
- Per-developer **delegated trust** (a second sw-authority slot).
- **Push** notifications (pull-only for now).
- The **onboard orchestrator** (same signed campaigns, consumed in-vehicle as
  a SOVD `update` operation).
- Multi-tenant / multi-fleet isolation.
- Shareable **named personal channels** (override is overlay-only for now).

### Open questions
1. CI importer shape (job-token publish + channel advance).
2. Who drives a rig's *own* self-update across its reboot (the onboard case).
3. The path from on-disk key files to a real HSM backend (format is ready;
   the swap is deferred).

---

## 10. Roadmap

### Built (the load-bearing path)
1. **T2 content core** — encrypt-once publish (`POST /admin/artifacts`,
   AES-128-GCM via `sumo-offboard`) + content-addressed `GET /blobs/{outer}`;
   blob store + Postgres index, CEK never in the blob store.
2. **Releases + channel targets** — L2 `component-releases`, L1
   `vehicle-releases`, `(channel, device, architecture)` targets;
   `GET /channel-targets/tree` for previews.
3. **Per-device signing** — sw-authority ES256 key; `POST /channel-targets/l1`
   returns the delta L1 campaign signed per device (CEK re-wrapped via ECDH, no
   re-encryption); `POST /admin/envelope` + `GET /admin/signer/pubkey`.
4. **The campaign loop** — `orchestrator::campaign_execute` (§5): observe over
   SOVD → signed L1 → fan out L2s → shared flash-engine lifecycle
   (stage → reset → health-gate → commit/rollback), no-mix guard, manifest-only
   push for unchanged components, boot-aware JWT re-mint. Verdict commands
   (`rig reset/commit/rollback[/‑trials]`) wired. Validated end-to-end on a rig
   via the embedding workshop driver.
5. **Operator previews** — `rig state / diff [--plan] / apply / flash` (dry by
   default): client-side `wire::diff`/`flash_plan` as the read-only view of what
   the tower-side dispatch will decide.
6. **T1 enrollment** — roster (`POST /admin/devices`), keystore minting
   (`/admin/devices/{id}/enroll`, CA cert + trust bundle endpoints), relayed
   install (`rig install-keystore`), per-key device certs.
7. **Auth** — JWT bearer on every SOVD write; minted on demand from the
   workshop minter (`client::MinterClient`) or passed with `--token`.

### Next
- CI importer (job-token publish + channel advance).
- Collapse remaining per-rig scripts into registration + channel subscription
  (the composed stack + autoloader already cover pull-and-run delivery).
- Onboard orchestrator; delegated trust; `kid` + rotation (see Deferred).

---

## 11. Going public (later)
Before this repo is published: add a LICENSE, a CONTRIBUTING guide, CI, and a
security policy; scrub any internal references; confirm every dependency is a
public crate or wire-level integration (§7).
