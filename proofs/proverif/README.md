# Rung 4 — ProVerif SSH-channel model

[← formalisation roadmap](../../docs/formalisation-roadmap.md) · [threat model](../../docs/threat-model.md) · [assurance case](../../docs/assurance-case.md)

A ProVerif symbolic (Dolev-Yao) model of sudo-proxy's SSH-tunnel path. It
discharges **Rung 4** (SSH half) of the
[formalisation roadmap](../../docs/formalisation-roadmap.md): it makes assumption
**A4** load-bearing and *explicit* — the channel guarantees hold **iff** the
remote host key is pinned (`known_hosts` populated) — and exhibits the
**first-contact MITM** (attack-tree leaf **4.2**) when it is not. It also states
the **separation theorem**: a privileged exec at the honest remote requires a
human keypress *even when the channel is fully attacker-controlled*.

ProVerif was chosen over Tamarin: the model's job is one binary toggle (secure
iff pinned) plus producing an attack derivation, which ProVerif's applied-pi
calculus expresses with least ceremony and proves fully automatically. Tamarin's
strengths (unbounded mutable state, AC reasoning, inductive lemmas) aren't needed
here.

## The toggle

`ssh-channel.m4.pv` is an `m4` template. The `PINNED` macro flips the SSH tunnel
between a **private** channel (the authenticated+confidential channel SSH gives
once the host key is pinned) and a **public** channel (first contact, fully
under the Dolev-Yao attacker as man-in-the-middle). The *same* process bodies are
reused under both.

```sh
# pinned (known_hosts populated): expect the channel guarantees to hold
m4 -DPINNED ssh-channel.m4.pv > /tmp/pinned.pv   && proverif /tmp/pinned.pv

# first contact (no pinning): expect the MITM gap to surface
m4          ssh-channel.m4.pv > /tmp/unpinned.pv && proverif /tmp/unpinned.pv
```

(ProVerif is installed with `opam install proverif`; run via `opam exec --
proverif …`.)

## The four queries and expected outcomes

| # | Query | Pinned | First contact |
|---|-------|--------|---------------|
| **(a)** | Authenticity/integrity: the honest remote accepts only a request the local daemon actually sent. `RemoteAccept ⟹ RequestSent`. | `true` | **`false`** + MITM injection trace |
| **(b)** | Replay resistance (injective): each accept maps to a *distinct* send. | *cannot be proved*¹ | **`false`** + replay trace |
| **(c)** | Secrecy of the forwarded-agent secret / tunnelled payload. `not attacker(agentSecret)`. | `true` | **`false`** + derivation |
| **(d)** | Separation: the remote execs a command only after a human keypress for it. `RemoteExec ⟹ Keypress`. | `true` | `true` |

The **first-contact** column is the *desired, surfaced gap* — query (a) returning
`false` with a derivation in which the attacker forges `(id, c, s)` and the
honest remote accepts a request the local daemon never sent *is* the
mechanically-exhibited leaf 4.2. So a non-`true` result in the unpinned run is
expected, not a CI failure (the workflow is non-gating and the run is not gated
on ProVerif's exit code).

The **(d)** row holding in *both* columns is the reassuring result: an SSH
channel compromise does not fabricate approvals — the local human gate (assumption
A1, the private TTY) is not on the toggled tunnel.

¹ **On (b) pinned — stated plainly.** ProVerif proves the *non-injective*
authenticity (a) `true` but reports the *injective* form "cannot be proved" — and
crucially emits **no attack trace**. This is a known over-approximation of
ProVerif's Horn-clause semantics for **private** channels (a single message is
not treated linearly, so the replicated receiver may "read" it twice in the
abstraction); it is not a real replay. On the **public** (unpinned) channel the
attacker genuinely *can* replay, and ProVerif reports (b) `false` with a trace —
which is the result we care about. Injective replay-resistance at the
application layer is discharged by the other rungs: the daemon's UUID dedup is
the TLA+ [`ReplayImpossible`](../tla/) invariant (Rung 4), and freshness
monotonicity is the Kani `ymd_hms_to_epoch_is_monotone` proof (Rung 3). The
threat model already states that replay protection "rides on SSH transport
integrity (A4)", so locating app-layer dedup in those rungs rather than here is
faithful to the model.

## Scope (what this model abstracts away)

Stated plainly, as the Kani "Scope" note and the TLA+ faithfulness ledger do:

- **Symbolic Dolev-Yao, not computational.** Cryptographic primitives are assumed
  perfect (keys unguessable, encryption unbreakable, no algebraic/padding side
  channels). We prove what holds *given* sound crypto.
- **SSH is a black box.** We model the *guarantee* SSH provides — an
  authenticated, confidential channel to whoever's host key was accepted — and
  the *condition* for it (pinning). We do not re-verify SSH's transport,
  key-exchange, or authentication internals; that is established work.
- **Time is abstracted** to nonce uniqueness + event ordering. The 60 s freshness
  and 120 s dedup windows are not modelled numerically (that arithmetic is Rung 3
  Kani's domain, `ymd_hms_to_epoch`).
- **The human keypress is a trusted local action** (assumption A1): the approval
  channel is private and not attacker-injectable. This assumption is precisely
  what yields the separation theorem (d).
- **DoS, traffic analysis, and side channels are out of scope** (DoS is covered by
  the resource-cap controls, not here).

What it *does* establish: A4 is now a mechanically-checked iff plus a concrete
first-contact MITM trace for leaf 4.2, and the separation theorem (d) bounds the
blast radius of an SSH compromise — it does not reach the local approval gate.

## Why no committed generated `.pv`

Unlike the TLA+ artifact (where the `pcal.trans` output is committed), the m4
expansion is trivial and deterministic, so only the `.m4.pv` template is checked
in; CI regenerates both `.pv` files with `m4`.
