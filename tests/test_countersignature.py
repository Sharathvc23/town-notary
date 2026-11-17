"""Only a genuine counter-signature by a configured lab promotes to anchor."""
from __future__ import annotations

import copy

from notary_helpers import LAB_SK, did, lab_sign, make_badge, seed


def _count(c) -> int:
    return c.get("/register").json()["count"]


def test_forged_countersignature_claiming_the_lab_is_refused(start_notary, client_for):
    module = start_notary()
    c = client_for(module)
    runtime_sk = seed("runtime")
    # Signed by a key the attacker controls, then relabelled as the real lab.
    forged = lab_sign(make_badge(runtime_sk), lab_sk=seed("attacker-lab"))
    forged["countersigned_by"] = did(LAB_SK)

    before = _count(c)
    v = c.post("/verify", json={"badge": forged}).json()
    assert v["certified"] is False
    assert "counter-signature verification failed" in v["reasons"][0]
    r = c.post("/register", json={"badge": forged})
    assert r.status_code == 422
    assert _count(c) == before
    assert did(runtime_sk) not in module._anchor_set()


def test_tampered_countersigned_payload_is_refused(start_notary, client_for):
    c = client_for(start_notary())
    genuine = lab_sign(make_badge(seed("runtime")), method="verified")

    upgraded = copy.deepcopy(genuine)
    upgraded["payload"]["method"] = "lab-rerun"   # the method is signed
    edited = copy.deepcopy(genuine)
    edited["payload"]["badge"]["payload"]["passed"] = 999   # inner badge is signed too

    for badge in (upgraded, edited):
        r = c.post("/register", json={"badge": badge})
        assert r.status_code == 422, r.text


def test_countersignature_by_an_unconfigured_lab_only_lists(start_notary, client_for):
    module = start_notary()
    c = client_for(module)
    runtime_sk = seed("runtime")
    self_made = lab_sign(make_badge(runtime_sk), lab_sk=seed("attacker-lab"))

    r = c.post("/register", json={"badge": self_made})
    assert r.status_code == 200, r.text
    assert r.json()["entry"]["countersigned"] is True
    assert r.json()["entry"]["lab_countersigned"] is False
    assert r.json()["standing"] == "listed"
    assert did(runtime_sk) not in module._anchor_set()


def test_anchor_cannot_be_demoted_by_replaying_its_self_signed_badge(start_notary, client_for):
    c = client_for(start_notary())
    runtime_sk = seed("runtime")
    badge = make_badge(runtime_sk)
    envelope = lab_sign(badge)

    assert c.post("/register", json={"badge": envelope}).json()["standing"] == "anchor"
    # The inner self-signed badge is public (it is inside the envelope).
    r = c.post("/register", json={"badge": badge})
    assert r.status_code == 409
    assert c.get("/inspect", params={"did": did(runtime_sk)}).json()["standing"] == "anchor"

    # The same envelope again is a no-op; a newer lab-signed run is recorded.
    again = c.post("/register", json={"badge": envelope}).json()
    assert again["appended"] is False
    newer = lab_sign(make_badge(runtime_sk, completed_at="2099-01-01T00:00:00Z"))
    r = c.post("/register", json={"badge": newer})
    assert r.status_code == 200 and r.json()["appended"] is True
    assert r.json()["standing"] == "anchor"
