-------------------------- MODULE ApprovalStateMachine --------------------------
(***************************************************************************)
(* Rung 4 of the sudo-proxy formalisation roadmap: a TLA+/PlusCal model of *)
(* the approval state machine, model-checked by TLC.                       *)
(*                                                                         *)
(* It pins the two accepted residuals the Rung 0 threat model routed here  *)
(* (attack-tree leaves 1.4 / 4.4, finding F2): the `confirm_unprivileged`  *)
(* policy transition and the unconditional human gate on privileged exec.  *)
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
\* an 'a' (always-allow), any other key, or a poll timeout (no keypress).
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
    \* The persisted/in-memory policy flag (Arc<AtomicBool>), daemon-lifetime.
    \* Init is a free boolean so both the default and `--no-confirm-unprivileged`
    \* startup are covered.
    confirmUnpriv \in BOOLEAN,

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
    \* The policy flag was flipped other than by an 'a' keypress on an
    \* unprivileged request.
    vFlip = FALSE;

define
    \* A direct transcription of tui::classify_key(key, privileged).
    \* ApprovedAlways is emitted iff key = "a" AND the request is unprivileged.
    Classify(k, priv) ==
        IF   k = "timeout"        THEN "Timeout"
        ELSE IF k = "y"           THEN "Approved"
        ELSE IF k = "a" /\ ~priv  THEN "ApprovedAlways"
        ELSE                           "Denied"
end define;

\* Bookkeeping at every execution site. `isPriv` says whether this is the
\* privileged (exec_sudo) path. Raises the replay flag if this id already ran,
\* and -- on the privileged path -- the no-approval flag if the executing
\* keypress was not 'y'. So if any mutation routes a privileged exec onto a
\* non-'y' key, or lets an id execute twice, the monitor catches it here.
macro NoteExec(isPriv) begin
    if req.id \in executed then
        vReplay := TRUE;
    end if;
    if isPriv /\ key # "y" then
        vNoExec := TRUE;
    end if;
    executed := executed \union {req.id};
end macro;

\* The single primitive that writes the policy flag. Any flip must go through
\* it; it raises the flip-provenance flag unless the writer is an 'a' keypress
\* on an unprivileged request -- so wiring a flip into any other branch (a
\* request field, a timeout, the privileged path) trips the monitor.
macro FlipFlag() begin
    confirmUnpriv := FALSE;
    if req.privileged \/ key # "a" then
        vFlip := TRUE;
    end if;
end macro;

\* The environment / attacker: submits an arbitrary request (every field free,
\* including an id already in `seen` -- a replay) and an arbitrary operator
\* keypress. TLC's exhaustive search universally quantifies the properties over
\* all attacker forgeries / replays AND all operator choices.
process Env = "env"
begin
EnvLoop:
    while TRUE do
        await ~busy;
        with r \in Requests, k \in KeyChoice do
            req  := r;
            key  := k;
            busy := TRUE;
        end with;
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
                \* PRIVILEGED PATH -- never consults confirmUnpriv.
                \* ApprovedAlways is impossible here (Classify guards on ~priv)
                \* and the real code defensively folds it to Denied anyway.
                if Classify(key, TRUE) = "Approved" then
                    NoteExec(TRUE);                     \* exec_sudo
                elsif Classify(key, TRUE) = "Timeout" then
                    skip;                               \* timeout, default deny
                else
                    skip;                               \* denied
                end if;
            elsif confirmUnpriv then
                \* UNPRIVILEGED + confirmation ON.
                if Classify(key, FALSE) = "Approved" then
                    NoteExec(FALSE);                    \* exec_direct
                elsif Classify(key, FALSE) = "ApprovedAlways" then
                    FlipFlag();                         \* the ONLY flag writer
                    NoteExec(FALSE);                    \* exec_direct
                elsif Classify(key, FALSE) = "Timeout" then
                    skip;
                else
                    skip;                               \* denied
                end if;
            else
                \* UNPRIVILEGED + confirmation OFF: no prompt, exec directly.
                NoteExec(FALSE);                        \* exec_direct
            end if;
        end if;
        busy := FALSE;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "5576622c" /\ chksum(tla) = "3c1dd0ad")
VARIABLES confirmUnpriv, seen, executed, req, key, busy, vNoExec, vReplay, 
          vFlip

(* define statement *)
Classify(k, priv) ==
    IF   k = "timeout"        THEN "Timeout"
    ELSE IF k = "y"           THEN "Approved"
    ELSE IF k = "a" /\ ~priv  THEN "ApprovedAlways"
    ELSE                           "Denied"


vars == << confirmUnpriv, seen, executed, req, key, busy, vNoExec, vReplay, 
           vFlip >>

ProcSet == {"env"} \cup {"daemon"}

Init == (* Global variables *)
        /\ confirmUnpriv \in BOOLEAN
        /\ seen = {}
        /\ executed = {}
        /\ req = NoReq
        /\ key = "timeout"
        /\ busy = FALSE
        /\ vNoExec = FALSE
        /\ vReplay = FALSE
        /\ vFlip = FALSE

Env == /\ ~busy
       /\ \E r \in Requests:
            \E k \in KeyChoice:
              /\ req' = r
              /\ key' = k
              /\ busy' = TRUE
       /\ UNCHANGED << confirmUnpriv, seen, executed, vNoExec, vReplay, vFlip >>

Daemon == /\ busy
          /\ IF ~req.wellFormed
                THEN /\ TRUE
                     /\ UNCHANGED << confirmUnpriv, seen, executed, vNoExec, 
                                     vReplay, vFlip >>
                ELSE /\ IF req.forwardAgent /\ req.privileged
                           THEN /\ TRUE
                                /\ UNCHANGED << confirmUnpriv, seen, executed, 
                                                vNoExec, vReplay, vFlip >>
                           ELSE /\ IF ~req.fresh
                                      THEN /\ TRUE
                                           /\ UNCHANGED << confirmUnpriv, seen, 
                                                           executed, vNoExec, 
                                                           vReplay, vFlip >>
                                      ELSE /\ IF ~req.envOk
                                                 THEN /\ TRUE
                                                      /\ UNCHANGED << confirmUnpriv, 
                                                                      seen, 
                                                                      executed, 
                                                                      vNoExec, 
                                                                      vReplay, 
                                                                      vFlip >>
                                                 ELSE /\ IF req.id \in seen
                                                            THEN /\ TRUE
                                                                 /\ UNCHANGED << confirmUnpriv, 
                                                                                 seen, 
                                                                                 executed, 
                                                                                 vNoExec, 
                                                                                 vReplay, 
                                                                                 vFlip >>
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
                                                                            /\ UNCHANGED << confirmUnpriv, 
                                                                                            vFlip >>
                                                                       ELSE /\ IF confirmUnpriv
                                                                                  THEN /\ IF Classify(key, FALSE) = "Approved"
                                                                                             THEN /\ IF req.id \in executed
                                                                                                        THEN /\ vReplay' = TRUE
                                                                                                        ELSE /\ TRUE
                                                                                                             /\ UNCHANGED vReplay
                                                                                                  /\ IF FALSE /\ key # "y"
                                                                                                        THEN /\ vNoExec' = TRUE
                                                                                                        ELSE /\ TRUE
                                                                                                             /\ UNCHANGED vNoExec
                                                                                                  /\ executed' = (executed \union {req.id})
                                                                                                  /\ UNCHANGED << confirmUnpriv, 
                                                                                                                  vFlip >>
                                                                                             ELSE /\ IF Classify(key, FALSE) = "ApprovedAlways"
                                                                                                        THEN /\ confirmUnpriv' = FALSE
                                                                                                             /\ IF req.privileged \/ key # "a"
                                                                                                                   THEN /\ vFlip' = TRUE
                                                                                                                   ELSE /\ TRUE
                                                                                                                        /\ vFlip' = vFlip
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
                                                                                                             /\ UNCHANGED << confirmUnpriv, 
                                                                                                                             executed, 
                                                                                                                             vNoExec, 
                                                                                                                             vReplay, 
                                                                                                                             vFlip >>
                                                                                  ELSE /\ IF req.id \in executed
                                                                                             THEN /\ vReplay' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vReplay
                                                                                       /\ IF FALSE /\ key # "y"
                                                                                             THEN /\ vNoExec' = TRUE
                                                                                             ELSE /\ TRUE
                                                                                                  /\ UNCHANGED vNoExec
                                                                                       /\ executed' = (executed \union {req.id})
                                                                                       /\ UNCHANGED << confirmUnpriv, 
                                                                                                       vFlip >>
          /\ busy' = FALSE
          /\ UNCHANGED << req, key >>

Next == Env \/ Daemon

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

\* ===================== invariants & properties =====================

\* Modeling-hygiene type invariant.
TypeOK ==
    /\ confirmUnpriv \in BOOLEAN
    /\ seen \subseteq Ids
    /\ executed \subseteq Ids
    /\ req \in Requests
    /\ key \in KeyChoice
    /\ busy \in BOOLEAN
    /\ vNoExec \in BOOLEAN
    /\ vReplay \in BOOLEAN
    /\ vFlip \in BOOLEAN

\* P1: a privileged exec happens only on a 'y' keypress -- never on timeout,
\* denial, replay, or any policy state. (leaf 1.4 / G5)
NoExecWithoutApproval == ~vNoExec

\* P2: the same request id never causes two executions. (leaf 1.1 / G2.1)
ReplayImpossible == ~vReplay

\* P3: the policy flag flips only via an ApprovedAlways ('a') keypress on an
\* unprivileged request -- never a request field, replay, MCP flag, or timeout.
\* (leaf 1.4 / 4.4 / F2)
PolicyFlipsOnlyOnKeypress == ~vFlip

\* P4: no privileged exec without a 'y' keypress, for ANY value the policy flag
\* took. The privileged branch structurally never reads confirmUnpriv, so this
\* is the "independent of policy" reading of the same witness as P1; stated
\* separately for assurance-case traceability (G5.1) and tripped by the NC2
\* mutation that wires the flag into the privileged path. (leaf 4.4 / G5.1)
PrivilegedGateIndependentOfPolicy == ~vNoExec

\* P3 (temporal half): once the flag is FALSE it stays FALSE -- it only ever
\* moves true->false, and only via the single writer above.
FlagMonotone == [][confirmUnpriv' => confirmUnpriv]_confirmUnpriv

=============================================================================
