"""Shared builders for the Town Notary tests: keys, badges, receipts, PARC.

Every key is derived from a fixed label, so test runs are deterministic. These
seeds are public: never reuse them for anything real.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp import Identity, issue_receipt, new_receipt_id, verify_receipt
from sm_arp.receipts import build_action
from sm_arp.vrp import build_ledger, cosign_receipt, did_from_sk
from sm_conformance import counter_sign, derive_did_key
from sm_conformance.badge import build_badge
from sm_parc import build_reputation_credential


def seed(label: str) -> bytes:
    return hashlib.sha256(f"town-notary-test:{label}".encode()).digest()


def did(sk: bytes) -> str:
    pub = Ed25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
    return derive_did_key(pub)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


NOTARY_SK = seed("notary")
LAB_SK = seed("lab")
SUITE_03 = digest("suite-0.3")


def now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_badge(sk: bytes, *, runtime: str = "test-runtime", suite: str = SUITE_03,
               protocols: tuple[str, ...] = ("0.3",), failed: int = 0,
               completed_at: str | None = None) -> dict[str, Any]:
    return build_badge(runtime, signing_key32=sk, suite_digest=suite,
                       protocol_versions=list(protocols),
                       completed_at=completed_at or now_z(), passed=10, failed=failed)


def lab_sign(badge: dict[str, Any], lab_sk: bytes = LAB_SK,
             method: str = "verified") -> dict[str, Any]:
    return counter_sign(badge, lab_sk, now_z(), method=method)


# --- PARC: corroborated receipts, ledger, credential (as in the demo) --------
def _is_valid(receipt: dict[str, Any]) -> bool:
    return verify_receipt(receipt).ok


def earn_receipt(agent: Identity, counterparty_sk: bytes, summary: str) -> dict[str, Any]:
    """A receipt issued by `agent` and co-signed by `counterparty_sk`."""
    rid, iso = new_receipt_id(), now_z()
    action = build_action(category="purchase", human_summary=summary,
                          outcome="completed",
                          counterparty_did=did_from_sk(counterparty_sk))
    draft = {"version": "arp/0.1", "receipt_id": rid, "issuer_did": agent.did,
             "principal_did": agent.did, "issued_at": iso, "action": action}
    cosig = cosign_receipt(draft, signing_key_bytes=counterparty_sk)
    return issue_receipt(agent, principal_did=agent.did, action=action,
                         evidence={"witness_signatures": [cosig]},
                         receipt_id=rid, issued_at=iso)


def mint(subject: Identity, receipts: list[dict[str, Any]],
         issuer_sk: bytes) -> dict[str, Any]:
    ledger = build_ledger(subject=subject.did, receipts=receipts, is_valid=_is_valid,
                          as_of=now_z(), method="nanda-rep/0.2")
    vc = build_reputation_credential(ledger=ledger, issuer_sk=issuer_sk,
                                     valid_from=now_z(), valid_until=in_days(30))
    return {"ledger": ledger, "vc": vc}


def corroborated_history(agent_label: str, counterparty_sks: list[bytes],
                         issuer_label: str = "chapter") -> dict[str, Any]:
    agent = Identity.from_seed(seed(agent_label))
    receipts = [earn_receipt(agent, sk, f"deal #{i}")
                for i, sk in enumerate(counterparty_sks)]
    return mint(agent, receipts, issuer_sk=seed(issuer_label))


def parc_body(minted: dict[str, Any], bar: float = 0.5) -> dict[str, Any]:
    return {"credential": minted["vc"], "ledger": minted["ledger"],
            "min_reputation_score": bar}
