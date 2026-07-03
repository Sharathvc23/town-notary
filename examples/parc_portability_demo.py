"""Portable reputation, proven end to end: Chapter A -> Town Notary -> Chapter B.

The skills already composing with the Notary attest *events* (e.g. a contract
hash registered as a conformance badge at signing time). This demo proves the
missing rung: an agent's ACCUMULATED STANDING crossing a trust-domain border.

  1. An agent earns corroborated ARP receipts in **Chapter A** (each receipt
     issuer-signed by the agent and co-signed by a distinct counterparty).
  2. Chapter A builds a nanda-rep/0.2 Receipts Ledger and mints a **PARC
     credential** (a W3C VC committing to the ledger's merkle root + scores).
  3. The **Town Notary** — a neutral rung-2 — verifies the issuer proof and
     RECOMPUTES the root and scores from the presented ledger, then counter-
     signs (`POST /countersign-parc`, method `verified-recomputed`).
  4. **Chapter B** — which has NEVER heard of Chapter A and talks to no server —
     admits the agent offline: it verifies the Notary's countersignature
     against the Notary's pinned did:key, then recomputes the ledger itself.

Two refusals prove the stamp means something:

  * an issuer-INFLATED credential (score bumped, genuinely re-signed by
    Chapter A — the signature verifies!) is refused: recomputation catches it;
  * an UNCORROBORATED (self-dealing) agent's credential recomputes honestly to
    score 0 and is refused at the bar.

Run against the live Notary (default) or a local one:

    python examples/parc_portability_demo.py
    NOTARY_URL=http://127.0.0.1:8000 python examples/parc_portability_demo.py
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

import jcs
from sm_arp import Identity, issue_receipt, new_receipt_id, verify_receipt
from sm_arp.receipts import build_action
from sm_arp.vrp import build_ledger, cosign_receipt, did_from_sk
from sm_conformance import parse_did_key
from sm_parc import (
    AdmissionPolicy,
    admit,
    build_reputation_credential,
    did_from_private_key,
    verify_credential_proof,
)

NOTARY_URL = os.environ.get("NOTARY_URL", "https://town-notary-production.up.railway.app")

# Deterministic cast (demo keys — never reuse for anything real).
AGENT_SK = hashlib.sha256(b"portability-demo:agent").digest()
AGENT = Identity.from_seed(AGENT_SK)
CP_SKS = [hashlib.sha256(f"portability-demo:counterparty-{i}".encode()).digest()
          for i in range(3)]
WASH_SK = hashlib.sha256(b"portability-demo:wash-agent").digest()
WASH = Identity.from_seed(WASH_SK)
CHAPTER_A_SK = hashlib.sha256(b"portability-demo:chapter-a").digest()
CHAPTER_A_DID = did_from_private_key(CHAPTER_A_SK)

# Chapter B's whole config: the Notary's pinned did:key (fetched once here for
# convenience; a real Chapter B pins it out of band) and its own admission bar.
CHAPTER_B_BAR = 0.5


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_valid(receipt: dict[str, Any]) -> bool:
    return verify_receipt(receipt).ok


def earn_receipt(agent: Identity, counterparty_sk: bytes, summary: str) -> dict[str, Any]:
    """One corroborated receipt: agent-signed, counterparty co-signed.

    The co-signature covers the receipt minus both signature carriers, and the
    agent's issuer signature covers everything including the co-signature — so
    the co-signature is attached to the draft BEFORE issuing.
    """
    rid, iso = new_receipt_id(), _now()
    action = build_action(
        category="purchase",
        human_summary=summary,
        outcome="completed",
        counterparty_did=did_from_sk(counterparty_sk),
    )
    draft: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": rid,
        "issuer_did": agent.did,
        "principal_did": agent.did,
        "issued_at": iso,
        "action": action,
    }
    cosig = cosign_receipt(draft, signing_key_bytes=counterparty_sk)
    return issue_receipt(
        agent,
        principal_did=agent.did,
        action=action,
        evidence={"witness_signatures": [cosig]},
        receipt_id=rid,
        issued_at=iso,
    )


def self_dealing_receipt(agent: Identity, summary: str) -> dict[str, Any]:
    """A valid-but-uncorroborated receipt: no distinct counterparty co-signed."""
    return issue_receipt(
        agent,
        principal_did=agent.did,
        action=build_action(category="purchase", human_summary=summary,
                            outcome="completed"),
    )


def mint(subject: Identity, receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Chapter A: build the nanda-rep/0.2 ledger and mint the PARC credential."""
    ledger = build_ledger(
        subject=subject.did,
        receipts=receipts,
        is_valid=_is_valid,
        as_of=_now(),
        method="nanda-rep/0.2",
    )
    vc = build_reputation_credential(
        ledger=ledger,
        issuer_sk=CHAPTER_A_SK,
        valid_from=_now(),
        valid_until=_in_days(30),
    )
    return {"ledger": ledger, "vc": vc}


def inflate_and_resign(vc: dict[str, Any]) -> dict[str, Any]:
    """Chapter A goes rogue: bump the score, RE-SIGN GENUINELY. Signature valid."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    inflated = json.loads(json.dumps(vc))
    inflated["credentialSubject"]["reputation_score"] = 999.0
    body = {k: v for k, v in inflated.items() if k != "proof"}
    inflated["proof"]["proofValue"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(CHAPTER_A_SK).sign(jcs.canonicalize(body))
    ).decode("ascii")
    return inflated


def notary(path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        f"{NOTARY_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def chapter_b_admit(stamped: dict[str, Any], ledger: dict[str, Any],
                    notary_did: str) -> None:
    """Chapter B, fully offline: verify the stamp, then recompute everything.

    B's trust anchors are exactly two: the Notary's pinned did:key, and its own
    arithmetic. It has no relationship with Chapter A and calls no server.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    payload = stamped["payload"]
    assert stamped["countersigned_by"] == notary_did, "stamp is not from the pinned Notary"
    Ed25519PublicKey.from_public_bytes(parse_did_key(notary_did)).verify(
        base64.b64decode(stamped["countersignature"]),
        jcs.canonicalize(payload),
    )
    print("  [B] notary countersignature verifies against the pinned did:key")
    assert payload["type"] == "parc-countersign/1", "wrong protocol under the notary key"
    assert payload["method"] == "verified-recomputed"
    print(f"  [B] stamp is domain-tagged and timestamped inside the signature "
          f"({payload['countersigned_at']})")

    vc = payload["credential"]
    assert verify_credential_proof(vc), "issuer proof failed"
    print("  [B] issuer proof verifies (Chapter A's own signature)")

    res = admit(
        vc,
        policy=AdmissionPolicy(
            # Trust in this issuer is CONFERRED BY THE STAMP for the demo's B;
            # a stricter B could still maintain its own issuer allowlist here.
            trusted_issuers={vc["issuer"]},
            min_reputation_score=CHAPTER_B_BAR,
        ),
        ledger=ledger,
        is_valid=_is_valid,
        now=_now(),
    )
    assert res.ok, f"B refused: {res.stage} — {res.detail}"
    print(f"  [B] recomputed ledger + scores itself: ADMITTED "
          f"(bar={CHAPTER_B_BAR}, stage={res.stage})")


def main() -> None:
    print(f"Notary: {NOTARY_URL}")
    info = json.loads(urllib.request.urlopen(f"{NOTARY_URL}/", timeout=30).read())
    notary_did = info["notary_did"]
    print(f"Pinned notary did:key: {notary_did}\n")

    # 1-2. Earn in Chapter A, mint the credential.
    receipts = [earn_receipt(AGENT, CP_SKS[i], f"consulting engagement #{i + 1}")
                for i in range(3)]
    minted = mint(AGENT, receipts)
    score = minted["vc"]["credentialSubject"]["reputation_score"]
    print(f"[A] agent earned {len(receipts)} corroborated receipts; "
          f"minted PARC credential (nanda-rep/0.2 score={score})")

    # 3. The Notary recomputes and stamps.
    status, stamped_resp = notary("/countersign-parc", {
        "credential": minted["vc"],
        "ledger": minted["ledger"],
        "min_reputation_score": CHAPTER_B_BAR,
    })
    assert status == 200, f"notary refused the honest credential: {stamped_resp}"
    print(f"[N] notary recomputed the ledger and countersigned "
          f"(method={stamped_resp['method']})")

    # 4. Chapter B admits offline.
    print("[B] chapter B (offline, has never heard of Chapter A):")
    chapter_b_admit(stamped_resp["credential"], minted["ledger"], notary_did)

    # 5a. Refusal: inflated-but-genuinely-re-signed score.
    inflated = inflate_and_resign(minted["vc"])
    assert verify_credential_proof(inflated), "attack premise: signature must verify"
    status, resp = notary("/countersign-parc", {
        "credential": inflated,
        "ledger": minted["ledger"],
        "min_reputation_score": CHAPTER_B_BAR,
    })
    assert status == 422, f"notary must refuse the inflated credential: {resp}"
    stage = resp["detail"]["assessment"]["stage"]
    print(f"\n[N] REFUSED inflated credential (signature was VALID): stage={stage}")

    # 5b. Refusal: self-dealing agent recomputes honestly to ~0.
    wash = mint(WASH, [self_dealing_receipt(WASH, f"self-report #{i}") for i in range(3)])
    status, resp = notary("/countersign-parc", {
        "credential": wash["vc"],
        "ledger": wash["ledger"],
        "min_reputation_score": CHAPTER_B_BAR,
    })
    assert status == 422, f"notary must refuse the wash credential: {resp}"
    stage = resp["detail"]["assessment"]["stage"]
    print(f"[N] REFUSED self-dealing credential (uncorroborated -> score 0): stage={stage}")

    print("\nPortability proven: reputation earned in A, stamped by a neutral notary")
    print("that recomputed it, admitted in B offline — no server trusted, twice checked.")


if __name__ == "__main__":
    main()
