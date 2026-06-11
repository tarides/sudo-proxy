-------------------------- MODULE ConcurrentHandlers --------------------------
(***************************************************************************)
(* Extended Rung 4 of the sudo-proxy formalisation roadmap: a TLA+/PlusCal *)
(* model of *concurrent* daemon connection handlers interleaving on the    *)
(* two pieces of state they share, model-checked by TLC.                   *)
(*                                                                         *)
(* The sibling `ApprovalStateMachine` and `ReplayWindow` models handle one *)
(* request to completion atomically, so they cannot see -- by construction *)
(* -- the two concurrency hazards that `server::handle_connection` guards   *)
(* against when many threads run at once:                                  *)
(*                                                                         *)
(*   1. the dedup TOCTOU. `SeenIds::try_insert` (server.rs:213) folds the   *)
(*      contains-check and the insert into ONE critical section under the   *)
(*      `seen_ids` mutex precisely so two threads racing the same id cannot  *)
(*      both pass dedup. This model interleaves handlers on `seen` and       *)
(*      checks that the atomic critical section is *sufficient*: no id ever  *)
(*      executes twice under any interleaving.                              *)
(*                                                                         *)
(*   2. the TTY-lock serialisation. The privileged prompt and the           *)
(*      foreground exec each take `tty_lock` (server.rs:555 / executor      *)
(*      ForegroundGuard) so two handlers never drive /dev/tty at once --     *)
(*      without it the daemon would sit in a background pgrp and EIO         *)
(*      (PR #22). This model checks the lock keeps the interactive region    *)
(*      mutually exclusive across all interleavings.                        *)
(*                                                                         *)
(* As in the sibling models, the PlusCal algorithm is the source of truth;  *)
(* the TLC-checkable translation between BEGIN/END TRANSLATION is generated  *)
(* by `pcal.trans` and committed alongside. If you edit the PlusCal, re-run  *)
(* `pcal.trans` and commit both. Properties are tracked either by a bounded  *)
(* witness counter (`ttyActive`) or a monitor flag (`vDoubleExec`) so every  *)
(* variable stays bounded and the reachable state space is finite and small. *)
(*                                                                         *)
(* Negative-control recipe and faithfulness ledger live in README.md.       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Handlers,    \* the set of concurrent handler threads, e.g. {h1, h2}
          Ids          \* the bounded set of request ids, e.g. {r1, r2}

\* Sentinel for "lock is free"; distinct from every handler id.
NoHolder == "none"

\* Keypress abstraction restricted to what matters for concurrency: "y"
\* approves (so the exec site is reached), "other" denies/times out (so the
\* TTY lock is released without executing). The full keypress decision table
\* and the confirm_unprivileged flip are the ApprovalStateMachine model's job;
\* here no "a" is offered, so confirmUnpriv is read-only.
Keys == {"y", "other"}

(* --algorithm ConcurrentHandlers

variables
    \* SeenIds: ids the daemon has accepted. Eviction is out of scope here
    \* (the ReplayWindow model owns the TTL); `seen` grows monotonically,
    \* which is sound for the concurrency properties. The mutex guarding it.
    seen = {},
    seenLock = NoHolder,

    \* The shared TTY lock (Arc<Mutex<()>>). Held across an interactive prompt
    \* and re-taken by ForegroundGuard for a privileged exec.
    ttyLock = NoHolder,

    \* The persisted policy flag (Arc<AtomicBool>). Free at init so both the
    \* confirm-on and no-confirm dispatch paths are covered; never flipped here.
    confirmUnpriv \in BOOLEAN,

    \* Ids that have actually executed -- the witness set for double-exec.
    executed = {},

    \* Witness counter: how many handlers are in the interactive TTY region
    \* (prompt or foreground exec) at once. The lock must keep this <= 1.
    ttyActive = 0,

    \* Monitor flag: raised at an exec site if this id already executed, i.e.
    \* the dedup let the same id through twice (the concurrent TOCTOU).
    vDoubleExec = FALSE;

\* Record an execution of `id`; raise the double-exec monitor if it ran before.
macro NoteExec(id) begin
    if id \in executed then
        vDoubleExec := TRUE;
    end if;
    executed := executed \union {id};
end macro;

\* One connection handler thread. Picks its request (id + privileged + key)
\* nondeterministically -- the gate chain (validate/freshness/env) is the
\* sibling model's job, so every request here is assumed past those gates and
\* the focus is the shared-state races. Single-shot: handles one request then
\* terminates, which bounds the state space.
process Handler \in Handlers
variables
    id   = CHOOSE i \in Ids : TRUE,
    priv = FALSE,
    key  = "y",
    dup  = FALSE;
begin
Pick:
    with i \in Ids, p \in BOOLEAN, k \in Keys do
        id := i; priv := p; key := k;
    end with;

\* ---- dedup critical section: the faithful ATOMIC try_insert ----
SeenAcq:
    await seenLock = NoHolder;     \* lock_recover(&seen_ids)
    seenLock := self;
TryInsert:
    \* evict_stale() is a no-op here (eviction = ReplayWindow's job). The
    \* contains-check and the insert are ONE atomic step under the lock --
    \* the single critical section that closes the TOCTOU. (To see the model
    \* has teeth, the README NC1 splits this into check / release / insert.)
    if id \in seen then
        dup := TRUE;
    else
        seen := seen \union {id};
        dup := FALSE;
    end if;
    seenLock := NoHolder;

Dispatch:
    if dup then
        goto Done;                 \* duplicate request id -> rejected, never execs
    elsif priv then
        goto PrivPrompt;
    elsif confirmUnpriv then
        goto ConfirmPrompt;
    else
        goto AutoExec;
    end if;

\* ---- privileged: TTY lock held across the prompt, released, re-taken to exec ----
PrivPrompt:
    await ttyLock = NoHolder;      \* blocking lock_recover(&tty_lock) for the prompt
    ttyLock := self;
    ttyActive := ttyActive + 1;
PrivPromptEnd:
    ttyActive := ttyActive - 1;
    ttyLock := NoHolder;           \* released before exec (server.rs:553)
    if key # "y" then goto Done; end if;   \* denied / timeout -> default deny
PrivExecAcq:
    await ttyLock = NoHolder;      \* ForegroundGuard::take re-acquires (blocking)
    ttyLock := self;
    ttyActive := ttyActive + 1;
PrivExec:
    NoteExec(id);                  \* exec_sudo
    ttyActive := ttyActive - 1;
    ttyLock := NoHolder;
    goto Done;

\* ---- unprivileged + confirm ON: blocking prompt, then exec_direct (no TTY) ----
ConfirmPrompt:
    await ttyLock = NoHolder;      \* blocking lock_recover(&tty_lock)
    ttyLock := self;
    ttyActive := ttyActive + 1;
ConfirmPromptEnd:
    ttyActive := ttyActive - 1;
    ttyLock := NoHolder;
    if key # "y" then goto Done; end if;
ConfirmExec:
    NoteExec(id);                  \* exec_direct -- takes NO tty_lock
    goto Done;

\* ---- unprivileged + confirm OFF: best-effort banner via try_lock, then exec ----
AutoExec:
    \* `if let Ok(_g) = tty_lock.try_lock() { display_banner }`: non-blocking
    \* and released immediately. Modelled as atomic with no lasting hold, so it
    \* never overlaps an interactive region -- skipped when the lock is busy.
    if ttyLock = NoHolder then
        skip;                      \* banner under a momentary try_lock
    end if;
    NoteExec(id);                  \* exec_direct
    goto Done;                     \* "Done" is PlusCal's implicit terminal label
end process;

end algorithm; *)

\* BEGIN TRANSLATION
VARIABLES seen, seenLock, ttyLock, confirmUnpriv, executed, ttyActive, 
          vDoubleExec, pc, id, priv, key, dup

vars == << seen, seenLock, ttyLock, confirmUnpriv, executed, ttyActive, 
           vDoubleExec, pc, id, priv, key, dup >>

ProcSet == (Handlers)

Init == (* Global variables *)
        /\ seen = {}
        /\ seenLock = NoHolder
        /\ ttyLock = NoHolder
        /\ confirmUnpriv \in BOOLEAN
        /\ executed = {}
        /\ ttyActive = 0
        /\ vDoubleExec = FALSE
        (* Process Handler *)
        /\ id = [self \in Handlers |-> CHOOSE i \in Ids : TRUE]
        /\ priv = [self \in Handlers |-> FALSE]
        /\ key = [self \in Handlers |-> "y"]
        /\ dup = [self \in Handlers |-> FALSE]
        /\ pc = [self \in ProcSet |-> "Pick"]

Pick(self) == /\ pc[self] = "Pick"
              /\ \E i \in Ids:
                   \E p \in BOOLEAN:
                     \E k \in Keys:
                       /\ id' = [id EXCEPT ![self] = i]
                       /\ priv' = [priv EXCEPT ![self] = p]
                       /\ key' = [key EXCEPT ![self] = k]
              /\ pc' = [pc EXCEPT ![self] = "SeenAcq"]
              /\ UNCHANGED << seen, seenLock, ttyLock, confirmUnpriv, executed, 
                              ttyActive, vDoubleExec, dup >>

SeenAcq(self) == /\ pc[self] = "SeenAcq"
                 /\ seenLock = NoHolder
                 /\ seenLock' = self
                 /\ pc' = [pc EXCEPT ![self] = "TryInsert"]
                 /\ UNCHANGED << seen, ttyLock, confirmUnpriv, executed, 
                                 ttyActive, vDoubleExec, id, priv, key, dup >>

TryInsert(self) == /\ pc[self] = "TryInsert"
                   /\ IF id[self] \in seen
                         THEN /\ dup' = [dup EXCEPT ![self] = TRUE]
                              /\ seen' = seen
                         ELSE /\ seen' = (seen \union {id[self]})
                              /\ dup' = [dup EXCEPT ![self] = FALSE]
                   /\ seenLock' = NoHolder
                   /\ pc' = [pc EXCEPT ![self] = "Dispatch"]
                   /\ UNCHANGED << ttyLock, confirmUnpriv, executed, ttyActive, 
                                   vDoubleExec, id, priv, key >>

Dispatch(self) == /\ pc[self] = "Dispatch"
                  /\ IF dup[self]
                        THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                        ELSE /\ IF priv[self]
                                   THEN /\ pc' = [pc EXCEPT ![self] = "PrivPrompt"]
                                   ELSE /\ IF confirmUnpriv
                                              THEN /\ pc' = [pc EXCEPT ![self] = "ConfirmPrompt"]
                                              ELSE /\ pc' = [pc EXCEPT ![self] = "AutoExec"]
                  /\ UNCHANGED << seen, seenLock, ttyLock, confirmUnpriv, 
                                  executed, ttyActive, vDoubleExec, id, priv, 
                                  key, dup >>

PrivPrompt(self) == /\ pc[self] = "PrivPrompt"
                    /\ ttyLock = NoHolder
                    /\ ttyLock' = self
                    /\ ttyActive' = ttyActive + 1
                    /\ pc' = [pc EXCEPT ![self] = "PrivPromptEnd"]
                    /\ UNCHANGED << seen, seenLock, confirmUnpriv, executed, 
                                    vDoubleExec, id, priv, key, dup >>

PrivPromptEnd(self) == /\ pc[self] = "PrivPromptEnd"
                       /\ ttyActive' = ttyActive - 1
                       /\ ttyLock' = NoHolder
                       /\ IF key[self] # "y"
                             THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "PrivExecAcq"]
                       /\ UNCHANGED << seen, seenLock, confirmUnpriv, executed, 
                                       vDoubleExec, id, priv, key, dup >>

PrivExecAcq(self) == /\ pc[self] = "PrivExecAcq"
                     /\ ttyLock = NoHolder
                     /\ ttyLock' = self
                     /\ ttyActive' = ttyActive + 1
                     /\ pc' = [pc EXCEPT ![self] = "PrivExec"]
                     /\ UNCHANGED << seen, seenLock, confirmUnpriv, executed, 
                                     vDoubleExec, id, priv, key, dup >>

PrivExec(self) == /\ pc[self] = "PrivExec"
                  /\ IF id[self] \in executed
                        THEN /\ vDoubleExec' = TRUE
                        ELSE /\ TRUE
                             /\ UNCHANGED vDoubleExec
                  /\ executed' = (executed \union {id[self]})
                  /\ ttyActive' = ttyActive - 1
                  /\ ttyLock' = NoHolder
                  /\ pc' = [pc EXCEPT ![self] = "Done"]
                  /\ UNCHANGED << seen, seenLock, confirmUnpriv, id, priv, key, 
                                  dup >>

ConfirmPrompt(self) == /\ pc[self] = "ConfirmPrompt"
                       /\ ttyLock = NoHolder
                       /\ ttyLock' = self
                       /\ ttyActive' = ttyActive + 1
                       /\ pc' = [pc EXCEPT ![self] = "ConfirmPromptEnd"]
                       /\ UNCHANGED << seen, seenLock, confirmUnpriv, executed, 
                                       vDoubleExec, id, priv, key, dup >>

ConfirmPromptEnd(self) == /\ pc[self] = "ConfirmPromptEnd"
                          /\ ttyActive' = ttyActive - 1
                          /\ ttyLock' = NoHolder
                          /\ IF key[self] # "y"
                                THEN /\ pc' = [pc EXCEPT ![self] = "Done"]
                                ELSE /\ pc' = [pc EXCEPT ![self] = "ConfirmExec"]
                          /\ UNCHANGED << seen, seenLock, confirmUnpriv, 
                                          executed, vDoubleExec, id, priv, key, 
                                          dup >>

ConfirmExec(self) == /\ pc[self] = "ConfirmExec"
                     /\ IF id[self] \in executed
                           THEN /\ vDoubleExec' = TRUE
                           ELSE /\ TRUE
                                /\ UNCHANGED vDoubleExec
                     /\ executed' = (executed \union {id[self]})
                     /\ pc' = [pc EXCEPT ![self] = "Done"]
                     /\ UNCHANGED << seen, seenLock, ttyLock, confirmUnpriv, 
                                     ttyActive, id, priv, key, dup >>

AutoExec(self) == /\ pc[self] = "AutoExec"
                  /\ IF ttyLock = NoHolder
                        THEN /\ TRUE
                        ELSE /\ TRUE
                  /\ IF id[self] \in executed
                        THEN /\ vDoubleExec' = TRUE
                        ELSE /\ TRUE
                             /\ UNCHANGED vDoubleExec
                  /\ executed' = (executed \union {id[self]})
                  /\ pc' = [pc EXCEPT ![self] = "Done"]
                  /\ UNCHANGED << seen, seenLock, ttyLock, confirmUnpriv, 
                                  ttyActive, id, priv, key, dup >>

Handler(self) == Pick(self) \/ SeenAcq(self) \/ TryInsert(self)
                    \/ Dispatch(self) \/ PrivPrompt(self)
                    \/ PrivPromptEnd(self) \/ PrivExecAcq(self)
                    \/ PrivExec(self) \/ ConfirmPrompt(self)
                    \/ ConfirmPromptEnd(self) \/ ConfirmExec(self)
                    \/ AutoExec(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in Handlers: Handler(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

\* ===================== invariants & properties =====================

\* Modeling-hygiene type invariant.
TypeOK ==
    /\ seen \subseteq Ids
    /\ executed \subseteq Ids
    /\ seenLock \in Handlers \cup {NoHolder}
    /\ ttyLock  \in Handlers \cup {NoHolder}
    /\ confirmUnpriv \in BOOLEAN
    /\ ttyActive \in 0..Cardinality(Handlers)
    /\ vDoubleExec \in BOOLEAN

\* C1: no request id ever executes twice, under ANY interleaving of the
\* concurrent handlers. This is the closure of the dedup TOCTOU: the atomic
\* `try_insert` critical section is *sufficient* to serialise the same-id race.
\* (leaf 1.1 / G2.1 -- the concurrent half of ReplayImpossible.)
NoDoubleExec == ~vDoubleExec

\* C2: at most one handler is in the interactive TTY region (prompt or
\* foreground exec) at any time -- the `tty_lock` serialises /dev/tty across
\* all interleavings, so the daemon never drives the TTY from two handlers at
\* once (the PR #22 background-pgrp / EIO hazard). (leaf Sn5.x / G6)
TtyMutualExclusion == ttyActive <= 1

=============================================================================
