# Rung 4 — ProVerif SSH-channel model

[← formalisation roadmap](../../docs/formalisation-roadmap.md) · [threat model](../../docs/threat-model.md) · [assurance case](../../docs/assurance-case.md)

A ProVerif symbolic (Dolev-Yao) model of sudo-proxy's SSH-tunnel path. It
discharges **Rung 4** (SSH half) of the
[formalisation roadmap](../../docs/formalisation-roadmap.md): it makes assumption
**A4** load-bearing and *explicit* by **deriving** the **first-contact MITM**
(attack-tree leaf **4.2**) from the attacker substituting its own host key —
rather than *assuming* a secure channel under pinning. It also states the
**separation theorem**: a privileged exec at the honest remote requires a human
keypress *even when the channel is fully attacker-controlled*.

ProVerif was chosen over Tamarin: the model's job is one binary toggle
(key-acceptance) plus producing an attack derivation, which ProVerif's
applied-pi calculus expresses with least ceremony and proves fully
automatically. Tamarin's strengths (unbounded mutable state, AC reasoning,
inductive lemmas) aren't needed here.

## What changed from the earlier version

The earlier model toggled the SSH tunnel between a **private** and a **public**
channel. That *declared* the channel secure when pinned — it assumed the
conclusion instead of showing *why* pinning produces it. This version models the
real **key material**: the remote has a host keypair, the local daemon **accepts
a host key** (the known-good one when pinned; whatever the network offers on
first contact), and encrypts the request to the accepted key. ProVerif then
**derives** the MITM from the attacker substituting its own key.

Modelling only the host key while ignoring client authentication would
misrepresent the system — it would paint the honest remote as accepting forged
commands even when pinned, which the remote's `authorized_keys` check actually
prevents. So the model captures the **real mutual-authentication structure** of
the SSH use case:

- **host key** (server → client): pinning + payload confidentiality — **A4**;
- **client key** (client → server): `authorized_keys`, request integrity.

The payoff is that the model **disentangles which assumption protects what**:

| Property | Rides on |
|----------|----------|
| Payload **confidentiality** (and you're-talking-to-the-real-remote) | **host-key pinning** (A4) |
| **Command authenticity** at the remote (only genuinely-issued commands run) | **client auth** (`authorized_keys`) — so it holds *even on first contact* |
| **Separation** (channel compromise can't fabricate approvals) | the private TTY (A1) |

## The toggle

`ssh-channel.m4.pv` is an `m4` template. The `PINNED` macro flips only **which
host key the daemon accepts** — the channel is the public Dolev-Yao network in
**both** configurations:

- **`PINNED`** → `pkAccepted = pkR`, the known-good host key from `known_hosts`.
- **unpinned** → `in(pub, pkAccepted)`, accept whatever the network offers; the
  attacker answers with its own key.

```sh
# pinned (known_hosts populated): expect the channel guarantees to hold
m4 -DPINNED ssh-channel.m4.pv > /tmp/pinned.pv   && proverif /tmp/pinned.pv

# first contact (no pinning): expect the secrecy MITM to surface
m4          ssh-channel.m4.pv > /tmp/unpinned.pv && proverif /tmp/unpinned.pv
```

(ProVerif is installed with `opam install proverif`; run via `opam exec --
proverif …`.)

## The four queries and expected outcomes

| # | Query | Pinned | First contact | Rides on |
|---|-------|--------|---------------|----------|
| **(a)** | Authenticity/integrity: the honest remote accepts only a request the local daemon actually sent. `RemoteAccept ⟹ RequestSent`. | `true` | `true` | **client auth** |
| **(b)** | Replay resistance (injective): each accept maps to a *distinct* send. | `false` | `false` | app-layer dedup¹ |
| **(c)** | Secrecy of the forwarded-agent secret / tunnelled payload. `not attacker(agentSecret)`. | `true` | **`false`** + key-substitution MITM derivation | **host-key pinning (A4)** |
| **(d)** | Separation: the remote execs a command only after a human keypress for it. `RemoteExec ⟹ Keypress`. | `true` | `true` | private TTY (A1) |

The **first-contact `(c)` = `false`** is the *derived, surfaced gap* — the
mechanically-exhibited leaf 4.2. ProVerif's derivation is exactly the
key-substitution MITM: the attacker mints its own host key `pk(k)`, the daemon
(first contact) accepts it and encrypts the payload to it, and the attacker
decrypts with `k` to recover `agentSecret`. A non-`true` result in the unpinned
run is therefore expected, not a CI failure (the workflow is non-gating and not
gated on ProVerif's exit code).

The honest, valuable result is that **`(a)` holds in *both* columns**: command
authenticity at the remote rides on **client authentication** (the signature the
remote checks against `authorized_keys`), so the first-contact MITM — which
breaks confidentiality — still **cannot forge or alter a command** the honest
remote will run. The earlier model's "authenticity holds *iff* pinned" was an
artifact of the assumed-private channel; the key-level model corrects it.

The **`(d)`** row holding in *both* columns is the reassuring result: an SSH
channel compromise does not fabricate approvals — the local human gate
(assumption A1, the private TTY) is not reachable by a network attacker.

¹ **On (b) — stated plainly.** The model has no application-layer dedup, so a
captured ciphertext can be replayed and the remote re-accepts it: injective
`(b)` is genuinely `false` in **both** configurations, with a replay trace. (The
earlier private-channel model reported (b) "cannot be proved" when pinned — a
known ProVerif over-approximation of private-channel linearity; with everything
now on the public channel that artifact is **gone**, and the result is a real,
honest replay.) Application-layer injective replay-resistance is discharged by
the other rungs: the daemon's UUID dedup is the TLA+
[`ReplayImpossible`](../tla/) invariant (Rung 4), and freshness monotonicity is
the Kani `ymd_hms_to_epoch_is_monotone` proof (Rung 3). The threat model already
states that replay protection "rides on SSH transport integrity (A4)", so
locating app-layer dedup in those rungs rather than here is faithful to the
model.

## Negative controls (teeth)

Documented mutations that each turn a passing query red, confirming the model
*sees* the property it claims. Apply by hand to the expanded `.pv`; never
committed.

- **NC1 — client auth is load-bearing for (a).** Delete the
  `let (=id, =c) = checksign(sg, pkL) in` line in `RemoteDaemon` (accept without
  verifying the client signature) ⇒ `(a)` `RemoteAccept ⟹ RequestSent` turns
  **`false`** *even pinned*: the attacker, knowing the public host key `pkR`,
  encrypts a forged request to the honest remote. (Confidentiality `(c)` stays
  `true` — pinning still protects it — which shows the two guarantees are
  orthogonal.)
- **NC2 — pinning is load-bearing for (c).** The **first-contact run is this
  control**: dropping pinning turns `(c)` `false` with the key-substitution
  derivation above. (Equivalently, forcing `pkAccepted` to an attacker key under
  `PINNED` breaks `(c)` too.)
- **NC3 — the private TTY is load-bearing for (d).** Change
  `free ttyAck:channel [private].` to a public `free ttyAck:channel.` ⇒ `(d)`
  `RemoteExec ⟹ Keypress` can no longer be proved: the attacker forges the
  acknowledgement and the remote execs without a keypress — reproducing
  "channel compromise bypasses the human gate" were the TTY not private (A1).

All three were run and produce the expected result.

## Scope (what this model abstracts away)

Stated plainly, as the Kani "Scope" note and the TLA+ faithfulness ledger do:

- **Symbolic Dolev-Yao, not computational.** Cryptographic *primitives* are
  assumed perfect (keys unguessable, `aenc`/`sign` unbreakable, no
  algebraic/padding side channels). We prove what holds *given* sound crypto.
- **SSH is a black box.** We model the authentication *structure* SSH realises —
  a confidential channel to whoever's host key was accepted, plus client
  authentication by key — and the *condition* for it (pinning). We do not
  re-verify SSH's transport, key-exchange, or authentication internals; that is
  established work.
- **Two modelled assumptions.** Host-key pinning (**A4**) and client
  authentication (the remote's `authorized_keys`, previously implicit). The
  model makes the second explicit because command authenticity rides on it, not
  on pinning.
- **Time is abstracted** to nonce uniqueness + event ordering. The 60 s
  freshness and 120 s dedup windows are not modelled numerically (that
  arithmetic is Rung 3 Kani's domain, `ymd_hms_to_epoch`); application-layer
  replay dedup is the TLA+ `ReplayImpossible` invariant's domain.
- **The human keypress is a trusted local action** (assumption A1): the approval
  channel is private and not attacker-injectable. This assumption is precisely
  what yields the separation theorem (d).
- **DoS, traffic analysis, and side channels are out of scope** (DoS is covered
  by the resource-cap controls, not here).

What it *does* establish: A4 is now a mechanically-**derived** dependency —
confidentiality holds iff the host key is pinned, with a concrete first-contact
key-substitution MITM trace for leaf 4.2 — the disentanglement attributes
command authenticity to client auth instead, and the separation theorem (d)
bounds the blast radius of an SSH compromise: it does not reach the local
approval gate.

## Why no committed generated `.pv`

Unlike the TLA+ artifact (where the `pcal.trans` output is committed), the m4
expansion is trivial and deterministic, so only the `.m4.pv` template is checked
in; CI regenerates both `.pv` files with `m4`.
