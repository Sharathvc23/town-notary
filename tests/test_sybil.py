"""The anchor rule cannot be satisfied by registering a key you minted yourself."""
from __future__ import annotations

import pytest
from notary_helpers import (
    NOTARY_SK, corroborated_history, did, make_badge, parc_body, seed,
)

ROOT = did(seed("root-anchor"))  # a configured root anchor the attacker never touches


def _sybil_history(attacker_sk: bytes) -> dict:
    """Receipts co-signed by the attacker's registered key plus two fresh keys."""
    return corroborated_history(
        "sybil-agent", [attacker_sk, seed("sybil-cp-1"), seed("sybil-cp-2")],
        issuer_label="attacker-chapter")


def test_self_registered_key_cannot_anchor_its_own_receipts(start_notary, client_for):
    module = start_notary(anchors=[ROOT])
    c = client_for(module)
    attacker_sk = seed("attacker")

    # Step 1: the attacker registers a key it just minted. Listing succeeds...
    r = c.post("/register", json={"badge": make_badge(attacker_sk, runtime="totally-real")})
    assert r.status_code == 200, r.text
    assert r.json()["standing"] == "listed"
    # ...but the key does not become an anchor.
    assert did(attacker_sk) not in module._anchor_set()

    # Step 2: the attacker's agent presents receipts co-signed by that key.
    minted = _sybil_history(attacker_sk)
    for path in ("/verify-parc", "/countersign-parc"):
        r = c.post(path, json=parc_body(minted))
        a = r.json() if path == "/verify-parc" else r.json()["detail"]["assessment"]
        assert a["certified"] is False
        assert a["anchored"] is False
        assert a["stage"] == "anchor_absent"
    assert r.status_code == 422


def test_refusal_is_the_anchor_rule_not_the_recomputation(start_notary, client_for):
    # Control: the same history IS stamped when the co-signer is a real anchor,
    # so the refusal above comes from anchor status alone.
    attacker_sk = seed("attacker")
    c = client_for(start_notary(anchors=[did(attacker_sk)]))
    r = c.post("/countersign-parc", json=parc_body(_sybil_history(attacker_sk)))
    assert r.status_code == 200, r.text


def test_notary_stamp_does_not_promote_to_anchor(start_notary, client_for):
    module = start_notary(anchors=[ROOT])
    c = client_for(module)
    attacker_sk = seed("attacker")

    stamped = c.post("/countersign", json={"badge": make_badge(attacker_sk)})
    assert stamped.status_code == 200, stamped.text
    assert stamped.json()["badge"]["countersigned_by"] == did(NOTARY_SK)

    r = c.post("/register", json={"badge": stamped.json()["badge"]})
    assert r.status_code == 200, r.text
    assert r.json()["standing"] == "listed"
    assert did(attacker_sk) not in module._anchor_set()


def test_empty_anchor_set_stamps_nothing(start_notary, client_for):
    # No root anchors and no lab-promoted keys: the rule refuses, it does not
    # switch off.
    c = client_for(start_notary(anchors=()))
    r = c.post("/countersign-parc", json=parc_body(_sybil_history(seed("attacker"))))
    assert r.status_code == 422
    a = r.json()["detail"]["assessment"]
    assert a["stage"] == "anchor_absent"
    assert a["anchor_count"] == 0


def test_notary_own_key_is_refused_as_a_lab(start_notary):
    with pytest.raises(RuntimeError, match="NOTARY_LAB_DIDS"):
        start_notary(labs=[did(NOTARY_SK)])
