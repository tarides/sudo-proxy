-------------------------- MODULE ApprovalStateMachine --------------------------
(***************************************************************************)
(* Rung 4 of the sudo-proxy formalisation roadmap: a TLA+/PlusCal model of *)
(* the approval state machine, model-checked by TLC.                       *)
(*                                                                         *)
(* It pins the privileged invariant (G1: an unconditional human gate on    *)
(* privileged exec) AND the second invariant (G7: no unprivileged command  *)
(* runs unattended except behind two barriers -- an immutable eligibility  *)
(* policy and a session-scoped `a` keypress -- with the grant never         *)
(* persisted). This is the model form of audit findings F2 (closed) and    *)
(* attack-tree leaves 1.4 / 4.4.                                           *)
(*                                                                         *)
(* The PlusCal algorithm below is the source of truth; the TLC-checkable   *)
(* TLA+ translation between BEGIN/END TRANSLATION is generated from it by   *)
(* `pcal.trans` and committed alongside (see README.md). If you edit the   *)
(* PlusCal, re-run `pcal.trans` and commit both.                           *)
(*                                                                         *)
(* The properties are tracked by bounded *monitor* variables (a standard   *)
(* TLC idiom): a violation flag is raised at the exact site a bad thing    *)
(* would happen, and the invariant asserts the flag stays FALSE. This      *)
(* keeps every variable bounded, so the reachable state space is finite    *)
(* and small with no history-length constraint -- processing more requests *)
(* only revisits states (once `seen` is full, further requests are         *)
(* rejected as replays).                                                   *)
(*                                                                         *)
(* Faithfulness ledger and the negative-control recipe that demonstrates   *)
(* the model has teeth live in proofs/tla/README.md.                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Ids          \* the bounded set of request ids, e.g. {r1, r2}

\* The entire input domain of tui::classify_key, abstracted: a keypress 'y',
\* an 'a' (approve + grant this session), any other key, or a poll timeout.
KeyChoice == {"y", "a", "other", "timeout"}

\* A request as seen by the daemon. Every gate is abstracted to the boolean
\* "does this request pass that gate"; the contents the gate inspects (clock,
\* env strings, dangerous chars) are out of scope here -- see the ledger.
Requests == [ id           : Ids,
              privileged    : BOOLEAN,
              forwardAgent  : BOOLEAN,
              wellFormed    : BOOLEAN,   \* passes ValidatedRequest::validate
              fresh         : BOOLEAN,   \* passes the freshness gate (<=60s)
              envOk         : BOOLEAN ]  \* passes the env allowlist

\* A placeholder request for the initial state; never handled (busy = FALSE at
\* init), so its field values are irrelevant.
NoReq == [ id           |-> CHOOSE i \in Ids : TRUE,
           privileged   |-> FALSE,
           forwardAgent |-> FALSE,
           wellFormed   |-> FALSE,
           fresh        |-> FALSE,
           envOk        |-> FALSE ]

(* --algorithm ApprovalStateMachine

variables
    \* Barrier 1 (G7): the per-daemon `unattended_eligible` policy. Read once
    \* from hosts.json at startup and IMMUTABLE at runtime -- no transition below
    \* writes it. Init is a free boolean so both an eligible and a non-eligible
    \* daemon are covered. A mutation that wires this from the wire trips
    \* EligibilityImmutable.
    eligible \in BOOLEAN,

    \* Barrier 2 (G7): the in-memory, session-scoped unattended grant. Starts
    \* FALSE (fail-closed), flips to TRUE only via an 'a' keypress on an
    \* unprivileged request when the daemon is eligible, and is reset to FALSE at
    \* a session boundary (SessionEnd below) -- never persisted.
    grant = FALSE,

    \* Replay dedup (SeenIds): ids the daemon has accepted (whether the dispatch
    \* then executed, denied, or timed out). Modelled as a monotonically growing
    \* set -- eviction is dropped, which is conservative for ReplayImpossible
    \* (see the ledger).
    seen = {},

    \* Ids that have actually been executed -- the witness set for replay.
    executed = {},

    \* The request currently on the wire and the operator's keypress for it.
    \* Read by the daemon only while `busy`.
    req = NoReq,
    key = "timeout",
    busy = FALSE,

    \* ---- monitor (violation) flags; each invariant asserts its flag is FALSE ----
    \* A privileged exec happened on a keypress other than 'y'.
    vNoExec = FALSE,
    \* An exec happened for an id that was already executed (a replayed exec).
    vReplay = FALSE,
    \* The session grant was set other than by an 'a' keypress on an
    \* unprivileged request while the daemon was eligible.
    vGrant = FALSE,
    \* An unprivileged command ran unattended (no keypress consulted this
    \* request) while the daemon was NOT eligible -- i.e. an unattended exec that
    \* the two barriers should have made unreachable.
    vUnattended = FALSE;

define
    \* A direct transcription of tui::classify_key(key, privileged).
    \* ApprovedAlways is emitted iff key = "a" AND the request is unprivileged.
    Classify(k, priv) ==
        IF   k = "timeout"        THEN "Timeout"
        ELSE IF k = "y"           THEN "Approved"
        ELSE IF k = "a" /\ ~priv  THEN "ApprovedAlways"
        ELSE                           "Denied"
end define;

\* Bookkeeping at every *attended* execution site (a keypress was consulted for
\* this request). `isPriv` says whether this is the privileged (exec_sudo) path.
\* Raises the replay flag if this id already ran, and -- on the privileged path
\* -- the no-approval flag if the executing keypress was not 'y'.
macro NoteExec(isPriv) begin
    if req.id \in executed then
        vReplay := TRUE;
    end if;
    if isPriv /\ key # "y" then
        vNoExec := TRUE;
    end if;
    executed := executed \union {req.id};
end macro;

\* Bookkeeping at the *unattended* execution site: an unprivileged command that
\* ran via the session grant, with no keypress consulted for this request. It is
\* legitimate only when the daemon is eligible (the grant was established earlier
\* by an 'a' keypress). Raise the unattended flag if it ever fires while not
\* eligible -- the backstop that makes G7 sound even if a mutation sets `grant`.
macro NoteUnattended() begin
    if ~eligible then
        vUnattended := TRUE;
    end if;
    if req.id \in executed then
        vReplay := TRUE;
    end if;
    executed := executed \union {req.id};
end macro;

\* The single primitive that sets the session grant. Any grant must go through
\* it; it raises the grant-provenance flag unless the writer is an 'a' keypress
\* on an unprivileged request AND the daemon is eligible -- so wiring a grant
\* into any other branch, or granting without eligibility, trips the monitor.
macro GrantSession() begin
    grant := TRUE;
    if req.privileged \/ key # "a" \/ ~eligible then
        vGrant := TRUE;
    end if;
end macro;

\* The environment / attacker: either submits an arbitrary request (every field
\* free, including an id already in `seen` -- a replay) with an arbitrary operator
\* keypress, OR ends the session (the SSH tunnel / daemon drops), which discards
\* the in-memory grant. TLC's exhaustive search universally quantifies the
\* properties over all attacker forgeries / replays, operator choices, and
\* session boundaries.
process Env = "env"
begin
EnvLoop:
    while TRUE do
        await ~busy;
        either
            with r \in Requests, k \in KeyChoice do
                req  := r;
                key  := k;
                busy := TRUE;
            end with;
        or
            \* Session boundary: the grant is in-memory only, so it is lost.
            \* Models "not longer than the MCP session / SSH tunnel".
            grant := FALSE;
        end either;
    end while;
end process;

\* The daemon: runs the gate chain in the SAME order as handle_connection (so a
\* reordering mutation is observable), then dispatches. One request is handled
\* to completion atomically (concurrency / TTY-lock interleavings are out of
\* scope for these properties -- see the ledger).
process Daemon = "daemon"
begin
Handle:
    while TRUE do
        await busy;
        if ~req.wellFormed then
            skip;                                       \* ValidatedRequest::validate -> reject
        elsif req.forwardAgent /\ req.privileged then
            skip;                                       \* forward_agent + privileged -> reject
        elsif ~req.fresh then
            skip;                                       \* freshness gate -> reject
        elsif ~req.envOk then
            skip;                                       \* env allowlist -> reject
        elsif req.id \in seen then
            skip;                                       \* replay dedup (try_insert -> false)
        else
            \* Accept (try_insert -> true), then dispatch.
            seen := seen \union {req.id};
            if req.privileged then
                \* PRIVILEGED PATH -- never consults eligible or grant.
                \* ApprovedAlways is impossible here (Classify guards on ~priv)
                \* and the real code defensively folds it to Denied anyway.
                if Classify(key, TRUE) = "Approved" then
                    NoteExec(TRUE);                     \* exec_sudo
                elsif Classify(key, TRUE) = "Timeout" then
                    skip;                               \* timeout, default deny
                else
                    skip;                               \* denied
                end if;
            elsif grant then
                \* UNPRIVILEGED + session granted: run unattended, no prompt.
                \* Reachable only after an 'a' keypress on an eligible daemon.
                NoteUnattended();                       \* exec_direct + reliable log
            else
                \* UNPRIVILEGED + not (yet) granted: prompt for this command.
                if Classify(key, FALSE) = "Approved" then
                    NoteExec(FALSE);                    \* exec_direct
                elsif Classify(key, FALSE) = "ApprovedAlways" then
                    \* 'a': approve THIS command regardless; grant the session
                    \* only when eligible (barrier 1 gates barrier 2).
                    if eligible then
                        GrantSession();
                    end if;
                    NoteExec(FALSE);                    \* exec_direct
                elsif Classify(key, FALSE) = "Timeout" then
                    skip;
                else
                    skip;                               \* denied
                end if;
            end if;
        end if;
        busy := FALSE;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES eligible, grant, seen, executed, req, key, busy, vNoExec, vReplay, 
          vGrant, vUnattended

(* define statement *)
Classify(k, priv) ==
    IF   k = "timeout"        THEN "Timeout"
    ELSE IF k = "y"           THEN "Approved"
    ELSE IF k = "a" /\ ~priv  THEN "ApprovedAlways"
    ELSE                           "Denied"


vars == << eligible, grant, seen, executed, req, key, busy, vNoExec, vReplay, 
           vGrant, vUnattended >>

ProcSet == {"env"} \cup {"daemon"}

Init == (* Global variables *)
        /\ eligible \in BOOLEAN
        /\ grant = FALSE
        /\ seen = {}
        /\ executed = {}
        /\ req = NoReq
        /\ key = "timeout"
        /\ busy = FALSE
        /\ vNoExec = FALSE
        /\ vReplay = FALSE
        /\ vGrant = FALSE
        /\ vUnattended = FALSE

Env == /\ ~busy
       /\ \/ /\ \E r \in Requests:
                  \E k \in KeyChoice:
                    /\ req' = r
                    /\ key' = k
                    /\ busy' = TRUE
             /\ grant' = grant
          \/ /\ grant' = FALSE
             /\ UNCHANGED <<req, key, busy>>
       /\ UNCHANGED << eligible, seen, executed, vNoExec, vReplay, vGrant, 
                       vUnattended >>

Daemon == /\ busy
          /\ IF ~req.wellFormed
                THEN /\ TRUE
                     /\ UNCHANGED << grant, seen, executed, vNoExec, vReplay, 
                                     vGrant, vUnattended >>
                ELSE /\ IF req.forwardAgent /\ req.privileged
                           THEN /\ TRUE
                                /\ UNCHANGED << grant, seen, executed, vNoExec, 
                                                vReplay, vGrant, vUnattended >>
                           ELSE /\ IF ~req.fresh
                                      THEN /\ TRUE
                                           /\ UNCHANGED << grant, seen, 
                                                           executed, vNoExec, 
                                                           vReplay, vGrant, 
                                                           vUnattended >>
                                      ELSE /\ IF ~req.envOk
                                                 THEN /\ TRUE
                                                      /\ UNCHANGED << grant, 
                                                                      seen, 
                                                                      executed, 
                                                                      vNoExec, 
                                                                      vReplay, 
                                                                      vGrant, 
                                                                      vUnattended >>
                                                 ELSE /\ IF req.id \in seen
                                                            THEN /\ TRUE
                                                                 /\ UNCHANGED << grant, 
                                                                                 seen, 
                                                                                 executed, 
                                                                                 vNoExec, 
                                                                                 vReplay, 
                                                                                 vGrant, 
                                                                                 vUnattended >>
                                                            ELSE /\ seen' = (seen \union {req.id})
                                                                 /\ IF req.privileged
                                                                       THEN /\ IF Classify(key, TRUE) = "Approved"
                                                                                  THEN /\ IF req.id \in executed
                                                                                             THEN /\ vReplay' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vReplay
                                                                                       /\ IF TRUE /\ key # "y"
                                                                                             THEN /\ vNoExec' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vNoExec
                                                                                       /\ executed' = (executed \union {req.id})
                                                                                  ELSE /\ IF Classify(key, TRUE) = "Timeout"
                                                                                             THEN /\ TRUE
                                                                                             ELSE /\ TRUE
                                                                                       /\ UNCHANGED << executed, 
                                                                                                       vNoExec, 
                                                                                                       vReplay >>
                                                                            /\ UNCHANGED << grant, 
                                                                                            vGrant, 
                                                                                            vUnattended >>
                                                                       ELSE /\ IF grant
                                                                                  THEN /\ IF ~eligible
                                                                                             THEN /\ vUnattended' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vUnattended
                                                                                       /\ IF req.id \in executed
                                                                                             THEN /\ vReplay' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vReplay
                                                                                       /\ executed' = (executed \union {req.id})
                                                                                       /\ UNCHANGED << grant, 
                                                                                                       vNoExec, 
                                                                                                       vGrant >>
                                                                                  ELSE /\ IF Classify(key, FALSE) = "Approved"
                                                                                             THEN /\ IF req.id \in executed
                                                                                                        THEN /\ vReplay' = TRUE
                                                                                                        ELSE /\ TRUE
                                                                                                             /\ UNCHANGED vReplay
                                                                                                  /\ IF FALSE /\ key # "y"
                                                                                                        THEN /\ vNoExec' = TRUE
                                                                                                        ELSE /\ TRUE
                                                                                                             /\ UNCHANGED vNoExec
                                                                                                  /\ executed' = (executed \union {req.id})
                                                                                                  /\ UNCHANGED << grant, 
                                                                                                                  vGrant >>
                                                                                             ELSE /\ IF Classify(key, FALSE) = "ApprovedAlways"
                                                                                                        THEN /\ IF eligible
                                                                                                                   THEN /\ grant' = TRUE
                                                                                                                        /\ IF req.privileged \/ key # "a" \/ ~eligible
                                                                                                                              THEN /\ vGrant' = TRUE
                                                                                                                              ELSE /\ TRUE
                                                                                                                                   /\ UNCHANGED vGrant
                                                                                                                   ELSE /\ TRUE
                                                                                                                        /\ UNCHANGED << grant, 
                                                                                                                                        vGrant >>
                                                                                                             /\ IF req.id \in executed
                                                                                                                   THEN /\ vReplay' = TRUE
                                                                                                                   ELSE /\ TRUE
                                                                                                                        /\ UNCHANGED vReplay
                                                                                                             /\ IF FALSE /\ key # "y"
                                                                                                                   THEN /\ vNoExec' = TRUE
                                                                                                                   ELSE /\ TRUE
                                                                                                                        /\ UNCHANGED vNoExec
                                                                                                             /\ executed' = (executed \union {req.id})
                                                                                                        ELSE /\ IF Classify(key, FALSE) = "Timeout"
                                                                                                                   THEN /\ TRUE
                                                                                                                   ELSE /\ TRUE
                                                                                                             /\ UNCHANGED << grant, 
                                                                                                                             executed, 
                                                                                                                             vNoExec, 
                                                                                                                             vReplay, 
                                                                                                                             vGrant >>
                                                                                       /\ UNCHANGED vUnattended
          /\ busy' = FALSE
          /\ UNCHANGED << eligible, req, key >>

Next == Env \/ Daemon

Spec == Init /\ [][Next]_vars

\* END TRANSLATION

\* ===================== invariants & properties =====================

\* Modeling-hygiene type invariant.
TypeOK ==
    /\ eligible \in BOOLEAN
    /\ grant \in BOOLEAN
    /\ seen \subseteq Ids
    /\ executed \subseteq Ids
    /\ req \in Requests
    /\ key \in KeyChoice
    /\ busy \in BOOLEAN
    /\ vNoExec \in BOOLEAN
    /\ vReplay \in BOOLEAN
    /\ vGrant \in BOOLEAN
    /\ vUnattended \in BOOLEAN

\* P1: a privileged exec happens only on a 'y' keypress -- never on timeout,
\* denial, replay, or any policy state. (leaf 1.4 / G5)
NoExecWithoutApproval == ~vNoExec

\* P2: the same request id never causes two executions. (leaf 1.1 / G2.1)
ReplayImpossible == ~vReplay

\* P3: the session grant is set only via an 'a' keypress on an unprivileged
\* request AND only when the daemon is eligible -- never a request field, replay,
\* MCP flag, timeout, or a non-eligible daemon. (G7 / C4, C8)
GrantOnlyByKeypressWhenEligible == ~vGrant

\* P4: no privileged exec without a 'y' keypress, for ANY eligibility/grant
\* state. The privileged branch structurally never reads them, so this is the
\* "independent of policy" reading of the same witness as P1; stated separately
\* for assurance-case traceability (G5.1) and tripped by a mutation that wires
\* the policy into the privileged path. (leaf 4.4 / G5.1)
PrivilegedGateIndependentOfPolicy == ~vNoExec

\* P5 (G7, the second invariant): no unprivileged command runs unattended unless
\* the daemon is eligible. Combined with P3 (the grant's 'a'-keypress provenance)
\* and the session-reset in Env (the grant never outlives a session), this is the
\* model form of "no unprivileged command runs with less scrutiny than the Bash
\* tool". (leaf 1.4 / 4.4 / F2)
NoUnattendedUnprivilegedExec == ~vUnattended

\* P6: eligibility is a runtime-immutable input -- no transition ever changes it
\* (barrier 1 can only be set out-of-band, at startup, from hosts.json). Tripped
\* by any mutation that writes `eligible` from a request field. (G7 / C4)
EligibilityImmutable == [][eligible' = eligible]_eligible

=============================================================================
