"""The register is an append-only hash chain, verified on every start."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from notary_helpers import did, lab_sign, make_badge, seed

SEED_FILE = Path(__file__).resolve().parent.parent / "data" / "register-seed.json"
SEED_COUNT = len(json.loads(SEED_FILE.read_text()))


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _register(c, label: str, *, lab: bool = False) -> dict:
    badge = make_badge(seed(label), runtime=label)
    r = c.post("/register", json={"badge": lab_sign(badge) if lab else badge})
    assert r.status_code == 200, r.text
    return r.json()


def test_log_is_appended_never_rewritten_and_survives_restart(
        start_notary, client_for, register_path):
    module = start_notary()
    c = client_for(module)
    genesis = register_path.read_text()
    assert len(genesis.splitlines()) == SEED_COUNT  # grandfathered imports

    _register(c, "alpha", lab=True)
    after_one = register_path.read_text()
    _register(c, "beta")
    after_two = register_path.read_text()
    assert after_one.startswith(genesis) and after_two.startswith(after_one)

    records = _records(register_path)
    assert [r["seq"] for r in records] == list(range(SEED_COUNT + 2))
    assert records[0]["prev"] == "0" * 64
    for earlier, later in zip(records, records[1:]):
        assert later["prev"] == earlier["hash"]
    assert [r["op"] for r in records[-2:]] == ["register", "register"]

    head = dict(module._HEAD)
    standings = {k: e["standing"] for k, e in module.REGISTER.items()}
    restarted = start_notary()
    assert restarted._HEAD == head
    assert {k: e["standing"] for k, e in restarted.REGISTER.items()} == standings
    assert standings[did(seed("alpha"))] == "anchor"
    assert standings[did(seed("beta"))] == "listed"


def test_reregistering_the_same_badge_appends_nothing(start_notary, client_for, register_path):
    c = client_for(start_notary())
    badge = make_badge(seed("alpha"))
    assert c.post("/register", json={"badge": badge}).json()["appended"] is True
    before = register_path.read_text()
    assert c.post("/register", json={"badge": badge}).json()["appended"] is False
    assert register_path.read_text() == before


def _edit_field(lines):
    lines[-1] = lines[-1].replace('"runtime":"beta"', '"runtime":"gamma"')
    return lines


def _drop_middle(lines):
    del lines[len(lines) // 2]
    return lines


def _swap_last_two(lines):
    lines[-1], lines[-2] = lines[-2], lines[-1]
    return lines


def _reformat(lines):
    lines[-1] = json.dumps(json.loads(lines[-1]))  # same data, non-canonical spacing
    return lines


@pytest.mark.parametrize("tamper", [_edit_field, _drop_middle, _swap_last_two, _reformat])
def test_tampered_register_line_refuses_start(start_notary, client_for, register_path, tamper):
    c = client_for(start_notary())
    _register(c, "alpha")
    _register(c, "beta")
    lines = register_path.read_text().splitlines()
    register_path.write_text("\n".join(tamper(lines)) + "\n")

    with pytest.raises(RuntimeError, match="register line"):
        start_notary()


def test_torn_final_record_refuses_start(start_notary, client_for, register_path):
    c = client_for(start_notary())
    _register(c, "alpha")
    register_path.write_text(register_path.read_text()[:-40])
    with pytest.raises(RuntimeError, match="incomplete final record"):
        start_notary()


def test_rehashed_chain_cannot_mint_an_anchor(start_notary, client_for, register_path):
    # Someone with write access edits a listing into an anchor and recomputes
    # every hash. The chain verifies, but standing is recomputed from the badge.
    c = client_for(start_notary())
    _register(c, "alpha")
    records = _records(register_path)
    records[-1]["entry"]["standing"] = "anchor"
    prev = records[-2]["hash"]
    body = {k: v for k, v in records[-1].items() if k != "hash"}
    body["prev"] = prev
    body["hash"] = hashlib.sha256(_canon(body).encode()).hexdigest()
    records[-1] = body
    register_path.write_text("".join(_canon(r) + "\n" for r in records))

    module = start_notary()
    assert module.REGISTER[did(seed("alpha"))]["standing"] == "listed"
    assert did(seed("alpha")) not in module._anchor_set()


def test_removing_a_lab_reverts_its_anchors_on_restart(start_notary, client_for):
    c = client_for(start_notary())
    _register(c, "alpha", lab=True)
    module = start_notary(labs=[])
    assert module.REGISTER[did(seed("alpha"))]["standing"] == "listed"


def test_legacy_snapshot_is_converted_once_and_kept(start_notary, register_path):
    seed_entries = json.loads(SEED_FILE.read_text())
    legacy_badge = make_badge(seed("legacy"), runtime="legacy")
    legacy = dict(seed_entries)
    legacy[did(seed("legacy"))] = {"certified": True, "runtime": "legacy",
                                   "signer_did": did(seed("legacy")),
                                   "badge": legacy_badge}
    original = json.dumps(legacy, sort_keys=True)
    register_path.write_text(original)

    module = start_notary()
    backup = Path(str(register_path) + ".pre-chain.json")
    assert backup.read_text() == original
    records = _records(register_path)
    assert len(records) == SEED_COUNT + 1  # seed entries are not imported twice
    assert {r["op"] for r in records} == {"import"}
    entry = module.REGISTER[did(seed("legacy"))]
    assert entry["imported_from"] == "pre-chain-snapshot"
    assert all(e["standing"] == "listed" for e in module.REGISTER.values())

    converted = register_path.read_text()
    start_notary()
    assert register_path.read_text() == converted


def test_without_register_path_the_log_is_in_memory(start_notary, client_for, register_path):
    module = start_notary(path=None)
    _register(client_for(module), "alpha")
    assert module._HEAD["seq"] == SEED_COUNT
    assert not register_path.exists()
