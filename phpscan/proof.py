"""The Proof Engine: explicit evidence checklists for gate decisions.

The Validation Gate decides WHAT a candidate is (validated, partial,
rejected).  This module answers the adjacent question: WHY is it that?
Every claim a finding carries is restated as a checkable question, each
question gets the concrete answer the analysis actually established,
and refutation attempts are recorded explicitly.  A reader should be
able to see what was *proved*, what is *probable*, and what remains
*unknown* -- and consequently what the next question would be.

The proof layer is strictly derived: it recomputes nothing, it only
restates gate stage results (and the facts that fed them) in
falsifiable form, so it cannot disagree with the gate it explains.
"""

from __future__ import annotations

# The disproof question each gate stage exists to answer.  Wording is
# intentionally falsifiable: one concrete experiment can defeat it, so a
# PASS here means "tried to disprove, could not".
STAGE_QUESTIONS = {
    "structural": "Is the reported location real, parseable code in this file?",
    "semantic": "Does the call at this location use an argument position that carries a security meaning?",
    "data-flow": "Does a concrete data path lead from attacker-controlled input to this argument?",
    "control-flow": "Is the sink reachable on at least one execution path that can occur at runtime?",
    "sanitizer": "Could sanitization applied on the path neutralize the value in this context?",
    "context": "Does the value actually reach the dangerous argument of this call?",
    "contradiction": "Do any recorded facts contradict the presence of the vulnerability?",
    "re-analysis": "Does an independent, stricter re-analysis reach the same result?",
}

# stages where a verdict carries the full proof for non-taint categories
NOTE_DOMAINS = ("Webshell / Backdoor",)


def build(cand, stages, notes, facts=None, corroboration=None):
    """Builds the proof record from raw components.

    stages: list of GateResult-like objects (needs .stage/.result/.note)
    notes:  textual caveat list gathered during validation
    facts:  dict of free-form, machine-checkable assertions the stage
            analysis established (e.g., level, guard count, sanitizer)
    corroboration: optional list of evidence-based claims produced by
            the fusion layer (live/host/history observations linked to
            this finding).  They are recorded as a separate section and
            do NOT change the gate verdict: the Validation Gate alone
            decides what the code is; corroboration says what was also
            seen about it in the world.
    """
    facts = dict(facts or {})
    claims = []
    for s in stages:
        stage = s.stage
        q = STAGE_QUESTIONS.get(stage, stage + "?")
        result = s.result
        refuted = False
        if result == "FAIL":
            refuted = True
        claims.append(
            {
                "stage": stage,
                "question": q,
                "result": result,
                "note": s.note or "",
                "refuted": refuted,
            }
        )
    verdict = _verdict(stages)
    open_q = _open_questions(claims, notes)
    record = {
        "verdict": verdict,
        "claims": claims,
        "assertions": facts,
        "notes": list(notes or ()),
        "open_questions": open_q,
    }
    if corroboration:
        record["corroboration"] = list(corroboration)
    return record


def _verdict(stages):
    results = [s.result for s in stages]
    if "FAIL" in results:
        return "disproven"
    if "PARTIAL" in results:
        return "probable"
    if "SKIP" in results:
        return "incomplete"
    return "verified"


def _open_questions(claims, notes):
    """RAE research queue input: what would need to be done next, per
    open evidence item.  Only realizes *actual* partial or skipped
    stages -- never invents uncertainty that the gate did not record."""
    qs = []
    for c in claims:
        if c["result"] == "PARTIAL":
            qs.append(
                {
                    "stage": c["stage"],
                    "question": c["question"],
                    "current": c["note"] or "partial evidence only",
                    "action": "strengthen evidence for: " + c["stage"],
                }
            )
        elif c["result"] == "SKIP":
            qs.append(
                {
                    "stage": c["stage"],
                    "question": c["question"],
                    "current": c["note"] or "not evaluated",
                    "action": "collect: " + c["stage"],
                }
            )
    return qs


def rejected_proof(cand, stages, reason):
    """Proof record for a gate-rejected candidate: one claim is
    refuted; the rest describe how far the evidence got."""
    p = build(cand, stages, [])
    p["verdict"] = "disproven"
    p["refutation"] = reason
    for c in p["claims"]:
        if c["result"] == "FAIL":
            c["refuted"] = True
    return p
