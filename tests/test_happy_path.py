"""The intended flow: pinned badge -> listed; lab-countersigned -> anchor -> stamp."""
from __future__ import annotations

import base64

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from notary_helpers import (
    LAB_SK, NOTARY_SK, SUITE_03, corroborated_history, did, lab_sign, make_badge,
    parc_body, seed,
)
from sm_conformance import parse_did_key


def test_self_signed_pinned_badge_is_listed(start_notary, client_for):
    c = client_for(start_notary())
    runtime_sk = seed("runtime")
    badge = make_badge(runtime_sk, runtime="alpha-runtime")

    v = c.post("/verify", json={"badge": badge}).json()
    assert v["certified"] is True
    assert v["suite_pinned"] is True
    assert v["lab_countersigned"] is False

    r = c.post("/register", json={"badge": badge})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["key"] == did(runtime_sk)
    assert body["standing"] == "listed"
    assert c.get("/inspect", params={"did": did(runtime_sk)}).json()["standing"] == "listed"


def test_lab_countersigned_badge_anchors_and_parc_stamp_issues(start_notary, client_for):
    module = start_notary()
    c = client_for(module)
    cp_sk = seed("counterparty-0")

    # The runtime's badge, counter-signed by the configured lab.
    r = c.post("/register", json={"badge": lab_sign(make_badge(cp_sk))})
    assert r.status_code == 200, r.text
    assert r.json()["key"] == did(cp_sk)  # keyed by the INNER signer
    assert r.json()["standing"] == "anchor"
    assert did(cp_sk) in module._anchor_set()

    # An agent whose history includes a receipt co-signed by that anchor.
    minted = corroborated_history("agent", [cp_sk, seed("cp-1"), seed("cp-2")])
    r = c.post("/countersign-parc", json=parc_body(minted))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["assessment"]["anchored"] is True
    assert out["assessment"]["stage"] == "admitted"

    # The stamp verifies offline against the Notary's did:key.
    stamped = out["credential"]
    notary_did = c.get("/").json()["notary_did"]
    assert notary_did == did(NOTARY_SK) == stamped["countersigned_by"]
    Ed25519PublicKey.from_public_bytes(parse_did_key(notary_did)).verify(
        base64.b64decode(stamped["countersignature"]),
        jcs.canonicalize(stamped["payload"]))


def test_office_info_publishes_admission_config(start_notary, client_for):
    root = did(seed("root-anchor"))
    info = client_for(start_notary(anchors=[root])).get("/").json()
    assert info["admission"]["suite_pins"] == {"0.3": [SUITE_03]}
    assert info["admission"]["lab_dids"] == [did(LAB_SK)]
    assert info["admission"]["root_anchors"] == [root]
    assert set(info["register_head"]) == {"seq", "hash"}
