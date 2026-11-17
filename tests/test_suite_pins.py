"""A badge certifies only for a suite pinned for every protocol it claims."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from notary_helpers import SUITE_03, digest, lab_sign, make_badge, seed

SAMPLE_BADGE = Path(__file__).resolve().parent.parent / "examples" / "sample-badge.json"


@pytest.mark.parametrize("suite, protocols", [
    (digest("some-other-suite"), ("0.3",)),   # wrong suite for a pinned protocol
    (SUITE_03, ("0.9",)),                     # protocol with no pin at all
    (SUITE_03, ("0.3", "0.4")),               # one pinned protocol carrying an unpinned one
], ids=["wrong-suite", "unpinned-protocol", "mixed-protocols"])
def test_unpinned_suite_is_refused_everywhere(start_notary, client_for, suite, protocols):
    c = client_for(start_notary())
    badge = make_badge(seed("runtime"), suite=suite, protocols=protocols)

    v = c.post("/verify", json={"badge": badge}).json()
    assert v["certified"] is False
    assert v["suite_pinned"] is False
    assert any(r.startswith("suite not pinned") for r in v["reasons"])

    for path in ("/register", "/countersign"):
        r = c.post(path, json={"badge": badge})
        assert r.status_code == 422, (path, r.text)
    assert c.get("/register").json()["count"] == c.get("/").json()["registered"]
    assert c.get("/inspect", params={"runtime": "test-runtime"}).status_code == 404


def test_no_pins_configured_refuses_every_badge(start_notary, client_for):
    c = client_for(start_notary(pins={}))
    r = c.post("/register", json={"badge": make_badge(seed("runtime"))})
    assert r.status_code == 422
    reasons = r.json()["detail"]["assessment"]["reasons"]
    assert "no suite pins configured" in " ".join(reasons)


def test_lab_countersignature_does_not_bypass_the_pin(start_notary, client_for):
    c = client_for(start_notary())
    badge = lab_sign(make_badge(seed("runtime"), suite=digest("unpinned")))
    r = c.post("/register", json={"badge": badge})
    assert r.status_code == 422


def test_a_protocol_may_pin_several_suites(start_notary, client_for):
    old, new = digest("suite-v1"), digest("suite-v2")
    c = client_for(start_notary(pins={"0.3": [old, new]}))
    for i, suite in enumerate((old, new)):
        r = c.post("/register", json={"badge": make_badge(seed(f"rt-{i}"), suite=suite)})
        assert r.status_code == 200, r.text


def test_sample_badge_certifies_only_where_its_suite_is_pinned(start_notary, client_for):
    sample = json.loads(SAMPLE_BADGE.read_text())
    unpinned = client_for(start_notary()).post("/verify", json={"badge": sample}).json()
    assert unpinned["certified"] is False

    pins = {"0.3": sample["payload"]["suite_digest"]}
    pinned = client_for(start_notary(pins=pins)).post("/verify", json={"badge": sample}).json()
    assert pinned["certified"] is True, pinned["reasons"]


@pytest.mark.parametrize("raw", [
    "not json",
    '["sha256:00"]',
    '{"0.3": "md5:abc"}',
    '{"v0.3": "%s"}' % SUITE_03,
    '{"0.3": []}',
], ids=["not-json", "not-object", "bad-digest", "bad-protocol", "empty-list"])
def test_malformed_pins_stop_startup(start_notary, raw):
    with pytest.raises(RuntimeError, match="NOTARY_SUITE_PINS"):
        start_notary(pins=raw)
