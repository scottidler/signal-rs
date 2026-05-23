# Design Document: Per-identity prekey and identity-keypair storage

**Author:** Scott Idler
**Date:** 2026-05-23
**Status:** Implemented
**Review Passes Completed:** 5/5

## Summary

Signal accounts carry two cryptographic identities (ACI and PNI), each
with its own keypair and its own prekey pool on the server.
signal-rs's local SQLite store keys prekeys by `id` alone, so the ACI
and PNI batches generated at link time collide. The fix is to scope
local prekey storage and the local identity-keypair lookup by
`identity_kind`, mirroring signal-cli's per-identity store pattern.
This doc describes the schema, types, and call-site changes required;
the smoke test for the receive path is the acceptance criterion.

## Problem Statement

### Background

`libsignal-protocol`'s `PreKeyStore`, `SignedPreKeyStore`, and
`KyberPreKeyStore` traits all take a `key_id: u32` and nothing else.
There is no identity discriminator in the trait surface. signal-rs's
current implementation persists records to three SQLite tables keyed
by `id` alone:

- `prekeys(id, record)`
- `signed_prekeys(id, record)`
- `kyber_prekeys(id, record, used)`

The `identity` table is a flat key/value table:

- `identity(key TEXT PRIMARY KEY, value BLOB)`

ACI's identity keypair is stored under `key = 'identity_keypair'`; PNI's
under `key = 'pni_identity_keypair'`. The `IdentityKeyStore` trait impl
on `SqliteStore` (and the `get_identity_key_pair_impl` in `TxStore`)
unconditionally reads `'identity_keypair'`, so it always returns the
ACI keypair regardless of which identity the caller is operating
against.

signal-cli's `lib/.../storage/prekeys/PreKeyStore.java` solves the
prekey side by keeping one row per `(account_id_type, key_id)` in each
prekey table with `UNIQUE(account_id_type, key_id)` and a separate
`PreKeyStore` instance per `ServiceIdType`. The identity-keypair lookup
is also scoped per instance.

### Problem

The link flow generates one prekey batch per identity in
`src/link.rs::finalize_after_persist`, both starting at `next_id = 1`.
With single-id-keyed tables the PNI batch overwrites the ACI batch in
storage. When a peer fetches our ACI bundle from the server
(`signedPreKey.keyId = 101`) and encrypts using the ACI signed prekey,
`libsignal-protocol` asks the local store for `id = 101` and gets the
PNI private key back. MAC verification fails:

```
libsignal_protocol::session_management: invalid PreKey message:
MAC verification failed
```

The same structural problem exists in the identity-keypair lookup. If
a peer initiates a PNI-addressed PreKeyMessage, libsignal's session
machinery asks `IdentityKeyStore::get_identity_key_pair` for the local
private key; the current impl returns the ACI keypair; PQXDH derives
the wrong shared secret; decrypt fails.

A third instance of the same shape sits in `IdentityKeyStore::get_local_registration_id`.
`src/link.rs:331` currently has `let pni_registration_id =
aci_registration_id`, with a comment claiming signal-cli does the same.
That claim is false. `~/repos/AsamK/signal-cli/lib/.../storage/SignalAccount.java`
lines 247-248 (and again at 277-278 in `createLinkedAccount`) call
`KeyHelper.generateRegistrationId(false)` twice, producing independent
ACI and PNI registration ids. Signal-Server's `DeviceAttributes.java:27`
accepts `@JsonProperty("pniRegistrationId")` as a distinct field on
`/v1/devices/link`. Sharing a registration id across identities risks
session-state collisions for peers who communicate with both our ACI
and PNI; this must be fixed in the same pass.

Two tactical patches are currently in tree and must be reverted:

- `src/link.rs::finalize_after_persist`: `const PNI_ID_OFFSET: u32 = 1
  << 23` shifts PNI prekey ids into a disjoint range.
- `src/client.rs::maybe_replenish_prekeys`: same offset, used to split
  `SELECT MAX(id) FROM prekeys` for the per-identity next-id
  computation.

These avoid the collision for the prekey tables only. They leave the
identity-keypair issue unaddressed and they push two unrelated
constants into orchestration code that has no business knowing about
SQL row layout.

### Goals

1. Local prekey storage keyed by `(identity_kind, id)`, not by `id`
   alone.
2. Local identity-keypair lookup keyed by `identity_kind`.
3. Distinct ACI and PNI registration ids: generate two independent
   values at link time, persist both, and have
   `IdentityKeyStore::get_local_registration_id` return the one
   matching the scope.
4. One `IdentityScopedStore` instance per identity at runtime, each
   implementing `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`,
   and `IdentityKeyStore` against the same `SqlitePool`, filtered by
   its bound `identity_kind`.
5. The decrypt path (`Client::process_envelope`) selects the correct
   scoped stores and the correct `local_address` based on the envelope's
   `destination_service_id`.
6. The link, send, and replenishment paths name the identity they are
   operating against at every call site; no implicit ID-range
   conventions, no shared `MAX(id)` queries.
7. Delete `PNI_ID_OFFSET` and the associated query splits.

### Non-Goals

- Migrating data in an existing populated store. The new schema
  drops and recreates the prekey tables; any caller with persisted
  state from before this change must re-link. v0.1 release notes
  must call this out.
- `sessions` table refactor. Sessions are keyed by `ProtocolAddress`,
  which already encodes the service id; ACI peer rows and PNI peer
  rows do not collide.
- `identities` table refactor (the per-peer trusted-key store, separate
  from the singleton-style `identity` KV table). Same reasoning:
  address-keyed, naturally scoped.
- Kyber last-resort handling. v0.1 still treats every kyber prekey as
  one-time (the `used` column is set but `mark_kyber_pre_key_used`
  deletes the row). Last-resort handling is a separate v0.2 item.
- Encrypted device-name display. Cosmetic; a separate v0.2 item.
- A `migrations/test_data/` fixture verifying schema upgrades apply
  cleanly. With only `0001_initial.sql` in tree (the per-identity
  scoping was folded into 0001 rather than added as a separate
  migration), the failure modes are covered by the existing
  in-memory store tests; add the fixture when `migrations/` grows
  past three files.

## Proposed Solution

### Overview

Mirror signal-cli's pattern. Add an `identity_kind` column with a
composite primary key to each prekey table. Introduce an
`IdentityScopedStore` wrapper that clones the `SqlitePool`, carries an
`IdentityKind`, and implements the four libsignal storage traits
(`PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`,
`IdentityKeyStore`) with that kind in every WHERE clause and in every
identity-keypair row lookup. Drop the corresponding direct impls on
`SqliteStore`. Construct two instances at runtime (ACI and PNI); thread
the right one into every libsignal call site by reading the envelope's
destination service id.

### Architecture

```
                    ACI
                    PNI
                     |
                     v
+---------------------------------------------+
|                  SqliteStore                |
|  pool: SqlitePool                           |
|  impl SessionStore                          |
|  identity-singleton helpers (set/get_aci..) |
+---------------------------------------------+
                     |  for_kind(ACI) / for_kind(PNI)
                     v
+---------------------------------------------+
|              IdentityScopedStore            |
|  pool: SqlitePool                           |
|  identity_kind: IdentityKind                |
|                                             |
|  impl PreKeyStore        WHERE identity_kind = ? AND id = ?
|  impl SignedPreKeyStore  WHERE identity_kind = ? AND id = ?
|  impl KyberPreKeyStore   WHERE identity_kind = ? AND id = ?
|  impl IdentityKeyStore   reads `identity_keypair`     for ACI
|                           reads `pni_identity_keypair` for PNI
+---------------------------------------------+
```

`TxStore`'s sub-store constructors gain an `IdentityKind` parameter and
the four `*_impl` free functions gain the corresponding filter. The
in-flight transaction is still shared via `Arc<Mutex<...>>` exactly as
today; the only change is that the SQL gains a `WHERE identity_kind =
?` clause and the identity-keypair lookup branches on the kind.

### Data Model

**As shipped:** the new schema was folded directly into
`migrations/0001_initial.sql` rather than added as a separate `0002`
migration. signal-rs is pre-v0.1, every smoke run wipes state via
`bin/relink`, so the additional migration file had no operational
value. The `identity` table needs no DDL change: it is already a flat
KV. The PNI registration id is persisted as a new KV row keyed
`'pni_registration_id'`, alongside the existing `'identity_keypair'`,
`'pni_identity_keypair'`, and `'registration_id'` rows. The scoping
for both the keypair lookup and the registration-id lookup is purely
in the trait impl.

The final schema (with `(identity_kind, id)` composite primary key
and CHECK constraint) is exactly what the original 0002 design
described, just landed in 0001:

```sql
-- migrations/0001_initial.sql (relevant excerpt)

CREATE TABLE prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    PRIMARY KEY (identity_kind, id)
);

CREATE TABLE signed_prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    PRIMARY KEY (identity_kind, id)
);

CREATE TABLE kyber_prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identity_kind, id)
);
```

`identity_kind` is `TEXT` (not INTEGER) to match the existing
convention used by `link_status` rows and to keep the table
self-describing in the sqlite shell. The `CHECK` constraint enforces
the enum at the DB layer.

`STRICT` mode is NOT added. The existing tables do not use it and
adopting it is an unrelated decision.

### API Design

#### `src/crypto/prekeys.rs`

`IdentityKind` already exists here. Add a method to map to the textual
column value used in SQL:

```rust
impl IdentityKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            IdentityKind::Aci => "aci",
            IdentityKind::Pni => "pni",
        }
    }
}
```

`persist_batch` and `persist_batch_in_tx` take `identity_kind` and
operate on the scoped store:

```rust
pub async fn persist_batch(
    store: &SqliteStore,
    batch: &GeneratedBatch,
    identity_kind: IdentityKind,
) -> Result<(), PrekeyError>;

async fn persist_batch_in_tx(
    tx_store: &TxStore,
    batch: &GeneratedBatch,
    identity_kind: IdentityKind,
) -> Result<(), PrekeyError>;
```

`generate_upload_persist` already carries `identity_kind`; it passes
that through to `persist_batch_in_tx`.

#### `src/storage/sqlite.rs`

A new `IdentityScopedStore` type:

```rust
#[derive(Debug, Clone)]
pub struct IdentityScopedStore {
    pool: SqlitePool,
    identity_kind: IdentityKind,
}

impl IdentityScopedStore {
    pub fn new(pool: SqlitePool, identity_kind: IdentityKind) -> Self {
        Self { pool, identity_kind }
    }
}

impl SqliteStore {
    pub fn scoped(&self, identity_kind: IdentityKind) -> IdentityScopedStore {
        IdentityScopedStore::new(self.pool.clone(), identity_kind)
    }
}
```

Construction is infallible. If the underlying identity row is missing
(e.g. PNI keypair before ProvisionMessage processing), the error
surfaces lazily on the first trait call that needs it. This matches
today's `IdentityKeyStore` impl, which errors lazily on
`get_identity_key_pair` rather than at construction; it also lets
construction sites like `process_envelope` stay infallible and
accommodates early-link bootstrap.

The four libsignal trait impls move from `SqliteStore` to
`IdentityScopedStore`:

- `impl PreKeyStore for IdentityScopedStore` filters on
  `identity_kind = self.identity_kind.as_db_str()` in every query.
- Same for `SignedPreKeyStore` and `KyberPreKeyStore`.
- `IdentityKeyStore` branches on `self.identity_kind`:
  - `get_identity_key_pair` reads `'identity_keypair'` for ACI scope,
    `'pni_identity_keypair'` for PNI scope.
  - `get_local_registration_id` reads `'registration_id'` for ACI
    scope, `'pni_registration_id'` for PNI scope. Both rows are
    populated at link time (see `src/link.rs` change below).

The existing libsignal-protocol impls on `SqliteStore` are deleted.
`impl SessionStore for SqliteStore` stays (sessions are
identity-agnostic at the row level).

#### `src/storage/tx.rs`

The sub-store constructors take `IdentityKind`:

```rust
impl TxStore {
    pub fn session_store(&self) -> TxSessionStore { /* unchanged */ }

    pub fn identity_store(&self, kind: IdentityKind) -> TxIdentityStore;
    pub fn pre_key_store(&self, kind: IdentityKind) -> TxPreKeyStore;
    pub fn signed_pre_key_store(&self, kind: IdentityKind) -> TxSignedPreKeyStore;
    pub fn kyber_pre_key_store(&self, kind: IdentityKind) -> TxKyberPreKeyStore;
}
```

Each sub-store holds its `IdentityKind` alongside the `Arc<Mutex<...>>`.
The four `*_impl` free functions for the prekey families take
`identity_kind: IdentityKind` and apply the filter. The two `*_impl`
functions for the identity store (`get_identity_key_pair_impl`,
`get_local_registration_id_impl`) take the kind and select the right
identity row name.

The blanket `impl PreKeyStore for TxStore` (and the three siblings)
are removed. The transactional decrypt path operates on per-trait
sub-stores anyway; the blanket impls are unused and become misleading
once scoping enters the picture.

#### `src/link.rs::finalize_after_persist`

Drop `PNI_ID_OFFSET`. Both batches start at `next_id = 1`.
`persist_batch` calls pass the matching `IdentityKind`:

```rust
crate::crypto::prekeys::persist_batch(store, &aci_batch, IdentityKind::Aci).await?;
crate::crypto::prekeys::persist_batch(store, &pni_batch, IdentityKind::Pni).await?;
```

Generate the PNI registration id independently of the ACI one and
persist it. Replace the current `let pni_registration_id =
aci_registration_id` line with:

```rust
let pni_registration_id: u32 = {
    use rand::Rng as _;
    // libsignal's KeyHelper.generateRegistrationId(false) range is 1..=16380.
    rand::rng().random_range(1..=16380)
};
store.set_pni_registration_id(pni_registration_id).await?;
```

Add `set_pni_registration_id` / `get_pni_registration_id` to
`SqliteStore` alongside the existing `set_pni_identity_keypair` /
`get_pni_identity_keypair` helpers. These write/read the
`'pni_registration_id'` KV row as 4 big-endian bytes, matching the
existing `'registration_id'` row encoding.

#### `src/client.rs::maybe_replenish_prekeys`

Drop `PNI_ID_OFFSET` and the split queries. Compute the per-identity
next-id from a kind-filtered MAX:

```rust
let aci_next: u32 = sqlx::query_scalar::<_, Option<i64>>(
    "SELECT MAX(id) FROM prekeys WHERE identity_kind = 'aci'",
)
.fetch_one(&pool)
.await
.map_err(StoreError::from)?
.map(|v| v as u32)
.unwrap_or(0)
.saturating_add(1);
// Same for pni.
```

The server-authoritative count (currently fetched via
`get_available_prekey_count` in `maybe_replenish_one_identity`)
remains the trigger for whether to replenish. The local `MAX(id)` is
only used to pick the next id when we do replenish. The previous doc
conflated the two; they are independent concerns and both stay.

#### `src/client.rs::process_envelope`

The envelope carries `destination_service_id` (envelope.proto tag 13).
Parse it; classify as ACI or PNI by comparing against the persisted
strings from `store.get_aci()` and `store.get_pni()`; select the
scoped sub-stores; construct `local_address` from the matching service
id:

```rust
let dest = wire.destination_service_id.as_deref();
let local_aci = self.inner.store.get_aci().await?
    .ok_or(ReceiveError::MissingCredential("aci"))?;
let local_pni = self.inner.store.get_pni().await?;

let (kind, local_service_id) = match dest {
    Some(d) if Some(d) == local_pni.as_deref() => (IdentityKind::Pni, d.to_string()),
    _ => (IdentityKind::Aci, local_aci.clone()),
};
let local_address = ProtocolAddress::new(
    local_service_id,
    device_id_from_u32(self.inner.identity.device_id)?,
);

let pool = self.inner.store.pool().clone();
let tx = pool.begin().await.map_err(StoreError::from)?;
let tx_store = TxStore::new(tx);
let mut session = tx_store.session_store();
let mut identity = tx_store.identity_store(kind);
let mut pre_key = tx_store.pre_key_store(kind);
let signed = tx_store.signed_pre_key_store(kind);
let mut kyber = tx_store.kyber_pre_key_store(kind);
// ... message_decrypt ... commit ...
```

Routing rules:

- Missing or unrecognised `destination_service_id`: route to ACI.
  This preserves today's behavior for any pre-multi-identity envelopes
  in flight and matches the assumption that legacy / non-PNI servers
  address ACI exclusively.
- `destination_service_id` matches the persisted PNI string: route to
  PNI.
- Anything else (matches ACI explicitly, or a string we do not
  recognise): route to ACI.

`run_receive_loop`'s pre-loop `local_address` construction goes away;
`process_envelope` is the only place that needs the address and the
right one depends on the envelope.

The rule is forward-compatible to sealed sender. Signal-Server's
`service/.../grpc/MessagesAnonymousGrpcService.java` sets
`destinationServiceId` as a server-authoritative wire field on every
delivery (it lives on the outer `Envelope`, not inside the sealed
ciphertext). When v0.2 enables `proto::envelope::Type::UNIDENTIFIED_SENDER`
handling, the existing routing logic applies unchanged; the only
required edit is removing the `other` skip arm at `src/client.rs:763`.

### Implementation Plan

#### Phase 1: Schema and the scoped store
**Model:** sonnet

- Update `migrations/0001_initial.sql` to define the prekey tables
  with the `(identity_kind, id)` composite PK directly. (Originally
  planned as a separate `0002` migration; consolidated into 0001
  because signal-rs is pre-v0.1 and every smoke wipes state.)
- Add `IdentityKind::as_db_str()` in `src/crypto/prekeys.rs`.
- Add `IdentityScopedStore` in `src/storage/sqlite.rs` with the four
  libsignal trait impls.
- Add `SqliteStore::scoped(kind)`.
- Delete `impl PreKeyStore for SqliteStore`, `impl SignedPreKeyStore
  for SqliteStore`, `impl KyberPreKeyStore for SqliteStore`,
  `impl IdentityKeyStore for SqliteStore`.
- Add `SqliteStore::set_pni_registration_id` /
  `get_pni_registration_id` (4-byte BE encoding, mirroring the
  existing `registration_id` row).
- Update `src/storage/sqlite/tests.rs`:
    - Add `aci_and_pni_prekey_at_same_id_round_trip_independently`,
      `aci_and_pni_signed_prekey_at_same_id_round_trip_independently`,
      and `aci_and_pni_kyber_prekey_at_same_id_round_trip_independently`.
    - Add `identity_scoped_store_aci_returns_aci_keypair_and_reg_id`
      and `identity_scoped_store_pni_returns_pni_keypair_and_reg_id`
      (split by identity rather than by field; each test covers both
      the keypair and the registration id for its scope).
    - Adapt or remove existing tests that exercised the deleted
      `SqliteStore` impls so they go through the scoped store.

Acceptance: `otto ci` green.

#### Phase 2: TxStore scoping
**Model:** sonnet

- Add `IdentityKind` parameter to `pre_key_store`,
  `signed_pre_key_store`, `kyber_pre_key_store`, and
  `identity_store` on `TxStore`. Carry the kind in each sub-store
  struct.
- Update each prekey `*_impl` to filter by `identity_kind`. Update
  the identity `*_impl` functions to branch on the kind for both
  the keypair row name and the registration-id row name.
- Hoist the per-table SQL strings to module-level `const` (e.g.
  `SELECT_PREKEY_SQL`) so the pool-backed `IdentityScopedStore` and
  the transaction-backed `Tx*Store` use bit-identical queries and
  cannot drift.
- Delete the blanket `impl PreKeyStore for TxStore` and three
  siblings; they are unused and become misleading.
- Update `src/storage/tx/tests.rs`:
    - Add `tx_pre_key_consumption_respects_identity_kind`.
    - Add `tx_identity_keypair_returns_pni_when_scoped_pni` (combined:
      asserts both keypair and registration id come back correctly
      from each scope's TxStore sub-store).

Acceptance: `otto ci` green.

#### Phase 3: Call-site rewiring
**Model:** sonnet

- `src/crypto/prekeys.rs::persist_batch` and `persist_batch_in_tx`
  take `identity_kind`; route through the scoped store and the
  identity-scoped sub-stores respectively.
- `src/link.rs::finalize_after_persist`: drop `PNI_ID_OFFSET`; pass
  `IdentityKind::Aci` / `IdentityKind::Pni` to the two `persist_batch`
  calls; both batches start at id 1. Generate a distinct PNI
  registration id (range `1..=16380`, matching
  `KeyHelper.generateRegistrationId(false)`); persist it via
  `store.set_pni_registration_id`; pass it as the
  `pniRegistrationId` to `link_device`.
- `src/client.rs::maybe_replenish_prekeys`: drop `PNI_ID_OFFSET`;
  switch to kind-filtered `MAX(id)` queries; preserve the
  server-authoritative count as the replenish trigger.
- `src/client.rs::process_envelope`: derive `IdentityKind` and
  `local_address` from `envelope.destination_service_id`; route the
  sub-store construction accordingly.
- `src/client.rs::run_receive_loop`: drop the pre-loop `local_address`
  construction.

Acceptance: `otto ci` green; `cargo install --path .`.

#### Phase 4: Integration tests
**Model:** opus

- Add `src/link/tests.rs::link_persists_aci_and_pni_batches_without_collision`:
  exercises the prekey-persistence sub-sequence of
  `finalize_after_persist` end to end (the design originally called
  for a fake-server harness; the live `/v1/devices/link` PUT cannot
  be unit-tested, so the test calls the same `generate_batch` /
  `set_pni_registration_id` / `persist_batch` sequence the production
  function does and asserts both signed-prekey rows at id=101 survive
  with the correct private halves, plus that the two registration
  ids are independently generated). The full server round-trip is
  covered by the Phase 5 smoke.
- Add `src/crypto/prekeys/tests.rs::generate_persist_load_round_trip_per_identity`:
  generate ACI batch with `next_id=1`, generate PNI batch with
  `next_id=1`, persist both, load `id=101` through each scoped store,
  assert each matches the right batch's `signed_record`.
- Add unit-level coverage for `process_envelope`'s destination-based
  routing decision. The original plan called for synthesising a
  CIPHERTEXT envelope and driving it through `process_envelope` with
  a recording fake. That requires a full pre-established session
  fixture (libsignal-protocol's `process_prekey_bundle` +
  `message_encrypt` against scoped sub-stores) which is substantial
  fixture work. As shipped, the routing decision was extracted into
  a pure free function `route_envelope_to_identity` in `client.rs`
  and exhaustively tested in `src/client/tests.rs`:
    - `route_pni_destination_routes_to_pni_scope`
    - `route_aci_destination_routes_to_aci_scope`
    - `route_missing_destination_defaults_to_aci`
    - `route_unknown_destination_defaults_to_aci`
    - `route_pni_destination_without_local_pni_falls_through_to_aci`
    - `route_aci_destination_works_without_local_pni`

  Combined with `tx_pre_key_consumption_respects_identity_kind` (which
  proves the scoped sub-stores filter correctly under a real
  transaction) and `tx_identity_keypair_returns_pni_when_scoped_pni`
  (which proves the identity-keypair branch), the wiring between
  envelope-to-kind decision and prekey-row consumption is covered at
  both sides; the only uncovered link is the inline
  `tx_store.pre_key_store(kind)` call inside `process_envelope` itself.
  That call is a 1-line passthrough of `identity_kind`; the design
  accepts this as a remaining test gap to be revisited if a regression
  appears.

Acceptance: all the above tests fail before the structural fix lands
and pass after.

#### Phase 5: Smoke and ship
**Model:** opus

- `bin/relink` to wipe state, link, scp QR; user scans on phone.
- Phone sends an inbound; verify `process_envelope` decrypts
  successfully and the decoded envelope prints to stdout via the
  broadcast subscriber.
- If decrypt still fails, capture the failing envelope (destination
  service id, prekey id, message type) before changing anything.

Caveat: typical primary-to-linked traffic (text messages,
SyncMessages from the primary device) is ACI-addressed. A passing
smoke shows the ACI path works; it does NOT prove the PNI path
works. The PNI path's correctness is established by the Phase 4
`route_*` tests in `src/client/tests.rs` plus the tx-level
identity-scoping tests, not by Phase 5.

Acceptance: phone-to-signal-rs message round-trip works without MAC
failure, AND the Phase 4 routing tests pass.

## Alternatives Considered

### Alternative 1: Keep single-id-keyed tables; allocate ACI and PNI from disjoint id ranges (current tactical patch)

- **Description:** `PNI_ID_OFFSET = 1 << 23` shifts PNI prekey ids
  into `8388609..`. The id-range split lives in `finalize_after_persist`
  and in `maybe_replenish_prekeys`.
- **Pros:** Zero schema change, smallest diff.
- **Cons:** Leaks SQL row layout into orchestration code. Does not
  address the `IdentityKeyStore` collision (PNI decrypts still pull
  the ACI keypair). The constant must be remembered at every new call
  site. The id space is halved per identity (4M ids each instead of
  16M, still plenty but a permanent ceiling). Drifts away from
  signal-cli's pattern; future maintainers comparing the two
  implementations will be confused.
- **Why not chosen:** It is what is in tree now; this design exists to
  replace it.

### Alternative 2: Separate per-identity tables (e.g. `aci_prekeys`, `pni_prekeys`)

- **Description:** Six tables instead of three, no `identity_kind`
  column.
- **Pros:** Slightly simpler SQL (no WHERE clause on
  `identity_kind`); the table name carries the discriminator.
- **Cons:** Doubles the number of tables and migrations. Diverges
  from signal-cli's pattern, which uses a single table with a
  discriminator column. Adding a third identity (hypothetical) is a
  three-table addition instead of an enum-variant addition.
- **Why not chosen:** signal-cli's pattern is the reference
  implementation; matching it is worth more than the marginal SQL
  simplification.

### Alternative 3: Push the identity discriminator into libsignal-protocol's trait surface

- **Description:** Fork libsignal-protocol; add an `identity` argument
  to `PreKeyStore::get_pre_key` and friends.
- **Pros:** Eliminates the wrapper layer.
- **Cons:** Forks an upstream dependency for a purely local concern
  upstream has no intention of supporting. The wrapper layer is small
  and well-localised; the cost is not high enough to justify a fork.
- **Why not chosen:** Out of proportion to the problem.

## Technical Considerations

### Dependencies

No new crates. `sqlx`, `libsignal-protocol`, `tokio`, `log`,
`thiserror`, `async-trait` are already in tree.

### Performance

Per-query cost: one extra equality predicate on a column that is
part of the primary key, so the existing PK index covers it. No
table scans introduced. The `IdentityScopedStore` clones the
`SqlitePool` (an `Arc` clone), so constructing a per-identity store
per decrypt is free.

### Security

The change reduces a confused-deputy hazard: today a PNI-addressed
PreKey message can incidentally consume an ACI prekey row because
the store cannot tell them apart. After the change, each identity's
key material is isolated at the row level. No other security-relevant
surfaces change.

The CHECK constraint on `identity_kind` is enforced by SQLite and
prevents accidental writes with an unrecognised kind. It is not a
security boundary against a compromised process, but it does prevent
silent data corruption from a bug in code that constructs the kind
string.

### Testing Strategy

- Unit-level: per-identity round-trip tests for all three prekey
  families (`src/storage/sqlite/tests.rs`) and for the identity
  keypair (`src/storage/sqlite/tests.rs`).
- Transactional: per-identity round-trip and consumption tests under
  the `TxStore` sub-stores (`src/storage/tx/tests.rs`).
- Integration: a `finalize_after_persist` test that drives both
  identities through the link path and asserts both batches survive
  (`src/link/tests.rs`).
- Crypto: a generate-persist-load round trip with overlapping ids
  across identities (`src/crypto/prekeys/tests.rs`).
- E2E: phone-to-signal-rs message decrypt via the broadcast
  subscriber, after `bin/relink`. This is the acceptance test that
  the bug is gone.

The integration test is the one that, in retrospect, would have
caught the original collision at unit-test layer; it is the most
important new test.

### Rollout Plan

- No production deployment to roll back to. signal-rs is pre-v0.1.
  The state directory on the dev machine is wiped on every `bin/relink`
  invocation, so the migration's drop-and-recreate is operationally
  invisible.
- Document in v0.1 release notes: "this release re-keys local prekey
  storage; any existing state directory must be wiped before
  upgrading."

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Decrypt still fails after the schema fix (other unrelated bug, e.g. session-state corruption from the offset-hack era) | Medium | High | Phase 5 captures the failing envelope's destination service id and prekey id before mutating state, so the next diagnostic step has data to work with. The fix is decoupled per phase; Phase 4 tests pin down the scope of any residual issue. |
| `destination_service_id` is absent or malformed on real envelopes | Low | Medium | Routing rule defaults to ACI for missing/unknown destinations, matching pre-multi-identity behaviour. Add a `warn!` log when this branch is taken so unusual envelopes show up at DEBUG. |
| Drop-and-recreate migration runs against a populated state dir we did not anticipate | Low | Medium | Documented in release notes. The dev machine wipes via `bin/relink` every cycle. No production users yet. |
| `IdentityKeyStore` scoping breaks ACI flows we have not exercised (e.g. send-to-PNI peer) | Medium | Medium | Phase 4's integration test exercises both identities through link; Phase 5's smoke covers the receive path; the send path's prekey-bundle fetch (`session_device_ids_for_service_id`) already operates against an explicit service id and is unchanged. |
| Smoke test (Phase 5) silently passes on the ACI happy path, masking a residual PNI bug | High | Medium | Phase 4 ships six `route_*` tests in `src/client/tests.rs` plus identity-scoped tx tests as the unit-level proxy for the PNI receive path; Phase 5 acceptance requires both those tests and the user smoke to pass. |
| Pool-backed and transaction-backed scoped impls drift over time | Low | Medium | Phase 2 hoists each SQL query to a module-level `const` so both impls reference the same string; a future query change must touch both call sites at once. |
| Composite PK changes alter index plans in sqlite enough to slow a hot query | Very low | Low | The hot query is point lookup by `(identity_kind, id)`, which is the PK; sqlite uses the PK index trivially. |


## References

Code:

- `~/repos/scottidler/signal-rs/src/storage/sqlite.rs` (current
  `SqliteStore` and the four libsignal trait impls being moved)
- `~/repos/scottidler/signal-rs/src/storage/tx.rs` (current `TxStore`
  and the `*_impl` free functions)
- `~/repos/scottidler/signal-rs/src/crypto/prekeys.rs` (`IdentityKind`,
  `generate_batch`, `persist_batch`, `generate_upload_persist`)
- `~/repos/scottidler/signal-rs/src/link.rs::finalize_after_persist`
  (tactical patch site)
- `~/repos/scottidler/signal-rs/src/client.rs::maybe_replenish_prekeys`
  and `process_envelope` (tactical patch site, decrypt entry point)
- `~/repos/scottidler/signal-rs/src/proto/envelope.proto` (the wire
  envelope; `destination_service_id` is tag 13)
- `~/repos/scottidler/signal-rs/migrations/0001_initial.sql` (current
  schema for the three prekey tables and the `identity` KV table)

signal-cli pattern (local checkouts):

- `~/repos/AsamK/signal-cli/lib/src/main/java/org/asamk/signal/manager/storage/prekeys/PreKeyStore.java`
- `~/repos/AsamK/signal-cli/lib/src/main/java/org/asamk/signal/manager/storage/prekeys/SignedPreKeyStore.java`
- `~/repos/AsamK/signal-cli/lib/src/main/java/org/asamk/signal/manager/storage/prekeys/KyberPreKeyStore.java`

Signal-Server reference (local checkout):

- `~/repos/signalapp/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/controllers/DeviceController.java`
- `~/repos/signalapp/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/entities/LinkDeviceRequest.java`

libsignal-protocol traits (local checkout):

- `~/repos/signalapp/libsignal/rust/protocol/src/storage/`
