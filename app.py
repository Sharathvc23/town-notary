"""
The Town Notary — the notary's office for Nanda Town.

Agents submit their signed conformance badge (sm-conformance). The Notary
verifies it OFFLINE against the embedded did:key, applies admission gates,
records passing runtimes in a public register, and — as a rung-2 lab — can
counter-sign a badge with its own key (the official stamp).

Wraps Sharath Chandra's `sm-conformance` (MIT). Endpoints below are exactly
the surface a SkillMD points an OpenClaw agent at.

Trusted base (threat model): every guarantee the Notary makes reduces to the
correctness of `verify_envelope` / `verify_countersigned` in `sm-conformance` —
that library is the trusted computing base, and this service only layers
admission gates on top of its signature + schema checks. The Notary holds no
agent private keys (only public did:keys), and its own lab seed is supplied via
the NOTARY_SEED secret, never written to disk.

Admission (see README "Configuration"): a badge certifies only if its
suite_digest is pinned for every protocol version it claims
(NOTARY_SUITE_PINS). A certifying self-signed badge is LISTED on the register;
only a badge counter-signed by a configured lab key (NOTARY_LAB_DIDS) makes its
signer an ANCHOR for the PARC anchor rule. The register is an append-only,
hash-chained JSON Lines log that is verified on every start.
"""
from __future__ import annotations

import os
import re
import json
import hashlib
import threading
import importlib.metadata
import base64
import socket
import ipaddress
import urllib.request
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from sm_conformance import (
    verify_envelope,
    verify_countersigned,
    is_countersigned,
    counter_sign,
    canonical_json,
    derive_did_key,
    parse_did_key,
    VerificationError,
    CountersignError,
)
import jcs

from sm_arp import verify_receipt
from sm_arp.vrp import is_corroborated
from sm_parc import AdmissionPolicy as ParcAdmissionPolicy
from sm_parc import AdmissionResult as ParcAdmissionResult
from sm_parc import admit as parc_admit

app = FastAPI(title="The Town Notary", version="0.2.0")


@app.middleware("http")
async def _limit_body(request, call_next):
    # Reject oversized inline bodies before parsing. (Chunked uploads without
    # Content-Length are not size-checked here — see THREATMODEL P3.)
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "bad content-length"}, status_code=400)
    return await call_next(request)

# --- The Notary's own lab key (rung-2 counter-signing) -----------------------
# Set NOTARY_SEED to 64 hex chars (32 bytes) in production so the Notary's
# did:key is stable across restarts. The dev fallback is loud and insecure.
_seed_hex = os.environ.get("NOTARY_SEED")
if _seed_hex:
    LAB_SEED = bytes.fromhex(_seed_hex)
else:
    print("WARNING: NOTARY_SEED unset — using insecure dev seed. Set it before hosting.")
    LAB_SEED = bytes(range(32))
assert len(LAB_SEED) == 32, "NOTARY_SEED must decode to exactly 32 bytes"

_priv = Ed25519PrivateKey.from_private_bytes(LAB_SEED)
_pub32 = _priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
NOTARY_DID = derive_did_key(_pub32)

# Cap inbound request bodies (inline credentials/ledgers/badges). The URL
# fetcher has its own 1 MB cap; this closes the inline path.
MAX_BODY_BYTES = 5_000_000

# --- Admission configuration -------------------------------------------------
# Every value is read once at startup; a malformed value stops the service
# from starting rather than silently weakening a gate.
_PROTOCOL_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _parse_suite_pins(raw: str) -> dict[str, frozenset[str]]:
    """NOTARY_SUITE_PINS: JSON {protocol_version: digest | [digest, ...]}.

    Example: '{"0.3": "sha256:<64 hex>"}'. A list allows more than one suite
    per protocol version (e.g. during a suite rotation).
    """
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"NOTARY_SUITE_PINS is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise RuntimeError("NOTARY_SUITE_PINS must be a JSON object "
                           '{"<protocol version>": "sha256:<hex>"}')
    pins: dict[str, frozenset[str]] = {}
    for proto, value in data.items():
        digests = [value] if isinstance(value, str) else value
        if (not _PROTOCOL_RE.match(proto) or not isinstance(digests, list)
                or not digests
                or not all(isinstance(d, str) and _DIGEST_RE.match(d) for d in digests)):
            raise RuntimeError(
                f"NOTARY_SUITE_PINS[{proto!r}] must map a protocol version like "
                f"'0.3' to a 'sha256:<64 lowercase hex>' digest or a non-empty "
                f"list of them")
        pins[proto] = frozenset(digests)
    return pins


def _parse_did_list(name: str) -> frozenset[str]:
    dids = frozenset(
        d.strip() for d in os.environ.get(name, "").split(",") if d.strip())
    for d in dids:
        try:
            parse_did_key(d)
        except ValueError as e:
            raise RuntimeError(f"{name}: {e}") from e
    return dids


SUITE_PINS = _parse_suite_pins(os.environ.get("NOTARY_SUITE_PINS", ""))
if not SUITE_PINS:
    print("WARNING: NOTARY_SUITE_PINS unset — no suite is pinned, so every badge "
          "is refused by /register and /countersign.")

# Labs whose counter-signature promotes a registered key to ANCHOR. This is
# sm-conformance's `verify_badge --require-countersigned --trusted-signer <did>`
# rule applied server-side: the envelope must be counter-signed, both
# signatures must verify (verify_countersigned), and `countersigned_by` must be
# one of these dids.
LAB_DIDS = _parse_did_list("NOTARY_LAB_DIDS")
if NOTARY_DID in LAB_DIDS:
    # POST /countersign stamps ANY badge that clears the gates, for anyone who
    # asks. If the Notary's own stamp promoted keys to anchor, every caller
    # could promote their own key in two requests.
    raise RuntimeError(
        "NOTARY_LAB_DIDS must not contain the Notary's own did:key: the open "
        "/countersign endpoint would let any caller promote its own key to anchor")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_z() -> str:
    # RFC 3339 UTC at second precision ("...Z") — the exact shape sm-parc's
    # validity-window comparison and sm-arp's issued_at validation expect.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_is_public(host: str) -> bool:
    """True only if EVERY address `host` resolves to is a public unicast IP.

    Blocks SSRF: loopback, RFC-1918/ULA private ranges, link-local (incl. the
    169.254.169.254 cloud-metadata endpoint), reserved, multicast, unspecified.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Refuse redirects: a 30x to http://localhost would otherwise bypass the
    # host allowlist (the redirect target is never re-checked by urlopen).
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch_badge(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "badge_url must be http(s)")
    host = parsed.hostname
    if not host or not _host_is_public(host):
        raise HTTPException(400, "badge_url must resolve to a public host")
    try:
        with _OPENER.open(url, timeout=8) as r:
            body = r.read(1_000_000)  # cap ~1 MB; a badge is a few KB
        return json.loads(body.decode("utf-8"))
    except HTTPException:
        raise
    except Exception:
        # Do not echo the underlying error — it can leak internal network shape.
        raise HTTPException(400, "could not fetch or parse badge_url")


def _suite_pin_problem(payload: dict[str, Any]) -> Optional[str]:
    """None if the badge's suite is pinned for EVERY protocol version it claims.

    One badge carries one suite_digest but may list several protocol versions;
    each claimed version must have a pin and the digest must be one of that
    version's pinned digests, so a badge cannot borrow a pinned version to
    carry an unpinned one.
    """
    if not SUITE_PINS:
        return "suite not pinned: this Notary has no suite pins configured"
    digest = payload.get("suite_digest")
    for version in payload.get("protocol_versions") or []:
        pinned = SUITE_PINS.get(version)
        if pinned is None:
            return f"suite not pinned: no suite_digest is pinned for protocol {version}"
        if digest not in pinned:
            return (f"suite not pinned: suite_digest {digest} is not a pinned "
                    f"suite for protocol {version}")
    return None


def _assess(badge: dict[str, Any],
            expected_suite_digest: Optional[str],
            max_age_days: Optional[int]) -> dict[str, Any]:
    """Verify a badge offline and apply civic admission gates.

    Returns a structured assessment. `verify_*` rejects tampered
    payloads/signatures and wrong signers — ASSUMING the trusted base
    (`sm-conformance`, see module docstring) is correct. It does NOT judge the
    run result, so the Notary adds the pass-gate (Gate 0), the configured suite
    pins (Gate 1), plus the caller's optional suite and freshness gates.
    """
    reasons: list[str] = []
    countersigned = is_countersigned(badge)
    try:
        payload = verify_countersigned(badge) if countersigned else verify_envelope(badge)
    except (VerificationError, CountersignError) as e:
        return {"certified": False, "countersigned": countersigned,
                "lab_countersigned": False,
                "reasons": [f"verification failed: {e}"]}
    # For a counter-signed envelope the runtime's own signature is on the
    # inner badge; the outer envelope carries the lab's.
    inner = badge["payload"]["badge"] if countersigned else badge
    countersigned_by = badge.get("countersigned_by") if countersigned else None

    ok = True
    # Gate 0: honest pass-gate. verify_* checks signature + schema but NOT the
    # run result, so the Notary enforces it: no failures, clean exit.
    if payload.get("failed", 0) != 0 or payload.get("exit_status", 0) != 0:
        ok = False
        reasons.append(
            f"run did not pass: failed={payload.get('failed')} "
            f"exit_status={payload.get('exit_status')}")
    # Gate 1: the Notary's own suite pins (NOTARY_SUITE_PINS). Proves WHICH
    # suite ran, not just that one did; a badge for an unpinned suite is refused.
    pin_problem = _suite_pin_problem(payload)
    if pin_problem:
        ok = False
        reasons.append(pin_problem)
    # Gate 1b: the caller's own pin, on top of the Notary's.
    if expected_suite_digest and payload.get("suite_digest") != expected_suite_digest:
        ok = False
        reasons.append(
            f"suite_digest mismatch: badge={payload.get('suite_digest')} "
            f"expected={expected_suite_digest}")
    # Gate 2: freshness — a certificate of conformance goes stale.
    if max_age_days is not None:
        try:
            completed = datetime.fromisoformat(payload["completed_at"])
            age = (datetime.now(timezone.utc) - completed).days
            if age > max_age_days:
                ok = False
                reasons.append(f"badge is {age}d old, exceeds max_age_days={max_age_days}")
        except Exception:
            ok = False
            reasons.append("completed_at missing or unparseable")

    if ok and not reasons:
        reasons.append("clean: signature, schema, pass-gate, suite pin, and "
                       "admission gates all OK")

    return {
        "certified": ok,
        "runtime": payload.get("runtime"),
        "signer_did": inner.get("signed_by"),
        "suite_digest": payload.get("suite_digest"),
        "suite_pinned": pin_problem is None,
        "protocol_versions": payload.get("protocol_versions"),
        "counts": {k: payload.get(k) for k in
                   ("passed", "failed", "skipped", "xfailed", "xpassed")},
        "completed_at": payload.get("completed_at"),
        "countersigned": countersigned,
        "countersigned_by": countersigned_by,
        # Both signatures verified above; this adds the trusted-signer check.
        "lab_countersigned": countersigned_by in LAB_DIDS,
        "reasons": reasons,
    }


def _standing(assessment: dict[str, Any]) -> str:
    """'anchor' only for a certifying badge counter-signed by a configured lab."""
    if assessment["certified"] and assessment["lab_countersigned"]:
        return "anchor"
    return "listed"


# --- The register: an append-only, hash-chained JSON Lines log --------------
# REGISTER_PATH names the log file (point it at a mounted volume, e.g.
# /data/register.json). Each line is one record:
#
#   {"seq": n, "prev": <hash of record n-1, or 64 zeros>, "at": <rfc3339>,
#    "op": "import" | "register", "key": <did:key>, "entry": {...},
#    "hash": sha256 hex over the record without "hash"}
#
# serialized as json.dumps(sort_keys=True, separators=(",", ":")) — the same
# bytes that are hashed, so each line must be exactly in that form. Records
# are only ever appended (open mode "a" + fsync); nothing rewrites a line.
#
# On start the whole chain is verified (canonical form, seq, prev link, hash);
# any mismatch raises RegisterChainError and the service does not start.
# The chain makes edits, deletions and reordering of existing lines
# detectable; it does not authenticate who wrote them (anyone able to write
# the file can recompute every hash) and cannot reveal records removed from
# the END of the file — compare against a register_head recorded elsewhere
# (GET / publishes it). Standing is never taken from the file: it is
# recomputed from each entry's stored badge against the CURRENT configuration
# on every start, so a rewritten file cannot create an anchor without a
# configured lab's signature.
#
# A new log starts with "import" records for the grandfathered entries in
# data/register-seed.json. A REGISTER_PATH still holding the earlier
# single-object JSON snapshot is converted once: the original bytes are kept
# at <REGISTER_PATH>.pre-chain.json and its entries become "import" records.
# Without REGISTER_PATH the log is kept in memory only.
REGISTER_PATH = os.environ.get("REGISTER_PATH", "")
_SEED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "data", "register-seed.json")
GENESIS_PREV = "0" * 64
_RECORD_KEYS = frozenset({"seq", "prev", "at", "op", "key", "entry", "hash"})
_OPS = ("import", "register")


class RegisterChainError(RuntimeError):
    """The register log failed verification; the service refuses to start."""


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canon(body).encode("ascii")).hexdigest()


def _make_record(seq: int, prev: str, op: str, key: str,
                 entry: dict[str, Any]) -> dict[str, Any]:
    record = {"seq": seq, "prev": prev, "at": _now(), "op": op,
              "key": key, "entry": entry}
    record["hash"] = _record_hash(record)
    return record


def _verify_chain(text: str) -> list[dict[str, Any]]:
    """Parse and verify the whole log; raise RegisterChainError on any break."""
    lines = text.split("\n")
    if lines.pop():  # text after the last newline: a partial (torn) record
        raise RegisterChainError(
            f"register line {len(lines) + 1}: incomplete final record")
    records: list[dict[str, Any]] = []
    prev = GENESIS_PREV
    for i, line in enumerate(lines):
        where = f"register line {i + 1}"
        try:
            record = json.loads(line)
            canonical = _canon(record)
        except ValueError as e:
            raise RegisterChainError(f"{where}: not a JSON record ({e})") from e
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise RegisterChainError(f"{where}: unexpected record fields")
        if canonical != line:
            raise RegisterChainError(f"{where}: not in canonical form (edited?)")
        if type(record["seq"]) is not int or record["seq"] != i:
            raise RegisterChainError(f"{where}: seq {record['seq']!r}, expected {i}")
        if record["prev"] != prev:
            raise RegisterChainError(f"{where}: prev does not match the hash of "
                                     f"the preceding record")
        if (record["op"] not in _OPS or not isinstance(record["key"], str)
                or not isinstance(record["entry"], dict)):
            raise RegisterChainError(f"{where}: malformed op/key/entry")
        if record["hash"] != _record_hash(record):
            raise RegisterChainError(f"{where}: hash does not match the record")
        prev = record["hash"]
        records.append(record)
    return records


def _legacy_snapshot(text: str) -> Optional[dict[str, Any]]:
    """The pre-chain format: ONE JSON object mapping key -> entry object."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
        return data
    return None


def _read_seed() -> dict[str, Any]:
    try:
        with open(_SEED_PATH, encoding="utf-8") as f:
            seed = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(seed, dict):
        raise RegisterChainError(f"{_SEED_PATH}: expected a JSON object")
    return seed


def _write_new_log(path: str, records: list[dict[str, Any]]) -> None:
    """Create a log in one step (tmp + rename) so it never exists half-written."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(_canon(r) + "\n" for r in records))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


REGISTER: dict[str, dict[str, Any]] = {}
_HEAD: dict[str, Any] = {"seq": -1, "hash": GENESIS_PREV}
_REGISTER_LOCK = threading.Lock()


def _apply(record: dict[str, Any]) -> None:
    """Fold one verified record into the in-memory view (latest record wins).

    Standing is recomputed here from the stored badge — never read from the
    file — so it always reflects the running configuration.
    """
    entry = dict(record["entry"])
    badge = entry.get("badge")
    entry["standing"] = (_standing(_assess(badge, None, None))
                         if isinstance(badge, dict) else "listed")
    entry["seq"] = record["seq"]
    REGISTER[record["key"]] = entry
    _HEAD.update(seq=record["seq"], hash=record["hash"])


def _append(op: str, key: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Append one record (file first, then memory). Caller holds the lock."""
    record = _make_record(_HEAD["seq"] + 1, _HEAD["hash"], op, key, entry)
    if REGISTER_PATH:
        with open(REGISTER_PATH, "a", encoding="utf-8") as f:
            f.write(_canon(record) + "\n")
            f.flush()
            os.fsync(f.fileno())
    _apply(record)
    return record


def _load_register() -> None:
    """Verify (or create) the log and replay it. Raises on a broken chain."""
    records: list[dict[str, Any]] = []
    legacy: Optional[dict[str, Any]] = None
    if REGISTER_PATH and os.path.exists(REGISTER_PATH):
        with open(REGISTER_PATH, encoding="utf-8", newline="") as f:
            text = f.read()
        legacy = _legacy_snapshot(text)
        if legacy is None:
            records = _verify_chain(text)
        else:
            backup = REGISTER_PATH + ".pre-chain.json"
            if os.path.exists(backup):
                with open(backup, encoding="utf-8", newline="") as f:
                    if f.read() != text:
                        raise RegisterChainError(
                            f"{backup} exists and differs from {REGISTER_PATH}; "
                            f"refusing to convert the legacy snapshot")
            else:
                with open(backup, "w", encoding="utf-8", newline="") as f:
                    f.write(text)
                    f.flush()
                    os.fsync(f.fileno())
            print(f"Converting legacy register snapshot {REGISTER_PATH} to an "
                  f"append-only log (original kept at {backup}).")
    if not records:
        seed = _read_seed()
        imports = [(k, {**v, "imported_from": "register-seed"})
                   for k, v in seed.items()]
        imports += [(k, {**v, "imported_from": "pre-chain-snapshot"})
                    for k, v in (legacy or {}).items() if seed.get(k) != v]
        prev = GENESIS_PREV
        for seq, (key, entry) in enumerate(imports):
            records.append(_make_record(seq, prev, "import", key, entry))
            prev = records[-1]["hash"]
        if REGISTER_PATH:
            _write_new_log(REGISTER_PATH, records)
    if not REGISTER_PATH:
        print("WARNING: REGISTER_PATH unset — the register log is in memory only "
              "and new registrations do not survive a restart.")
    for record in records:
        _apply(record)


_load_register()


# --- Request models ----------------------------------------------------------
class VerifyReq(BaseModel):
    badge: Optional[dict[str, Any]] = None
    badge_url: Optional[str] = None
    expected_suite_digest: Optional[str] = None
    max_age_days: Optional[int] = None


class CountersignReq(BaseModel):
    badge: Optional[dict[str, Any]] = None
    badge_url: Optional[str] = None
    expected_suite_digest: Optional[str] = None
    max_age_days: Optional[int] = None
    # "verified" is the honest default: the Notary VERIFIED the badge against its
    # gates — it does not re-run the suite. Use "lab-rerun" only if you actually
    # re-ran the suite out of band before stamping.
    method: str = "verified"


def _resolve(req) -> dict[str, Any]:
    if req.badge is not None:
        return req.badge
    if req.badge_url:
        return _fetch_badge(req.badge_url)
    raise HTTPException(400, "provide either `badge` (JSON) or `badge_url`")


# --- Portable reputation (PARC) -----------------------------------------------
# A conformance badge attests a point-in-time run; a PARC credential ports an
# agent's ACCUMULATED standing across trust domains. The Notary's role here is
# the neutral rung-2: it verifies the issuer's proof and — crucially — RECOMPUTES
# the nanda-rep/0.2 scores from the presented receipts ledger before stamping.
# A valid signature is not a stamp: an issuer-inflated, genuinely re-signed
# score fails recomputation and is refused.
#
# What the stamp attests (and only this): the credential's proof verifies under
# its embedded issuer did:key, the presented ledger recomputes exactly to the
# signed merkle root and scores, and the corroborated score clears the caller's
# bar. It is NOT an endorsement of the issuer — a relying party that wants
# issuer vetting applies its own trusted_issuers policy on top.

# Bound the SCC/recompute work a hostile ledger can demand from the service.
PARC_MAX_RECEIPTS = 5000

# The anchor rule: did:keys are free to mint, so a recomputable corroborated
# score alone can be produced by one party co-signing its own receipts with
# fresh "counterparties". A stamp therefore additionally requires the
# subject's history to TOUCH AT LEAST ONE ANCHOR: a receipt whose counterparty
# is an anchor did AND whose co-signature by that anchor actually verifies
# (a junk receipt merely naming an anchor does not count). The anchor set is
# NOTARY_ANCHORS (comma-separated dids, the configured root) plus every
# register key whose standing is "anchor" — i.e. registered with a badge
# counter-signed by a NOTARY_LAB_DIDS lab. A self-signed registration is
# listed but never enters the anchor set, since anyone can mint a key and
# register it. An EMPTY anchor set refuses every stamp (stage anchor_absent):
# with no anchors the Notary has nothing to tell real corroboration from
# self-corroboration. Residual (same as sm-parc's THREATMODEL): an attacker
# who obtains one genuine corroborated edge from an anchor passes the rule.
NOTARY_ANCHORS = frozenset(
    d.strip() for d in os.environ.get("NOTARY_ANCHORS", "").split(",") if d.strip()
)


def _anchor_set() -> set[str]:
    """Configured root anchors plus lab-promoted register keys."""
    # list() snapshots in one step; a concurrent /register may insert a key.
    return set(NOTARY_ANCHORS) | {
        k for k, e in list(REGISTER.items()) if e.get("standing") == "anchor"}


def _touches_anchor(ledger: dict[str, Any], anchors: set[str]) -> bool:
    """True iff some receipt's ANCHOR counterparty genuinely co-signed it."""
    receipts = ledger.get("receipts")
    if not isinstance(receipts, list):
        return False
    for r in receipts:
        if not isinstance(r, dict):
            continue
        counterparty = (r.get("action") or {}).get("counterparty_did")
        if counterparty in anchors and verify_receipt(r).ok and is_corroborated(r):
            return True
    return False


def _receipt_is_valid(receipt: dict[str, Any]) -> bool:
    """The ARP verifier the recompute path runs per receipt (strict mode)."""
    return verify_receipt(receipt).ok


class ParcReq(BaseModel):
    credential: Optional[dict[str, Any]] = None
    credential_url: Optional[str] = None
    # The subject's presented Receipts Ledger (travels alongside the VC; the
    # credential commits to it via behavioral_merkle_root).
    ledger: Optional[dict[str, Any]] = None
    ledger_url: Optional[str] = None
    # The bar the corroborated, recomputed score must clear for a stamp.
    min_reputation_score: float = 0.0


def _resolve_parc(req: ParcReq) -> tuple[dict[str, Any], dict[str, Any]]:
    if req.credential is not None:
        credential = req.credential
    elif req.credential_url:
        credential = _fetch_badge(req.credential_url)
    else:
        raise HTTPException(400, "provide either `credential` (JSON) or `credential_url`")
    if req.ledger is not None:
        ledger = req.ledger
    elif req.ledger_url:
        ledger = _fetch_badge(req.ledger_url)
    else:
        raise HTTPException(400, "provide either `ledger` (JSON) or `ledger_url`")
    receipts = ledger.get("receipts")
    if isinstance(receipts, list) and len(receipts) > PARC_MAX_RECEIPTS:
        raise HTTPException(413, f"ledger exceeds {PARC_MAX_RECEIPTS} receipts")
    return credential, ledger


def _assess_parc(credential: dict[str, Any], ledger: dict[str, Any],
                 min_reputation_score: float) -> dict[str, Any]:
    """Verify + RECOMPUTE a PARC credential against its presented ledger.

    The issuer set is `{the credential's own issuer}` on purpose: the stamp
    attests verification + recomputation, not issuer endorsement (mirrors the
    honest `method: verified` posture of badge counter-signing). Everything
    else is sm-parc's inline admission: proof, validity window, scoring method
    pin (nanda-rep/0.2 only), anti-withholding receipt count, merkle root
    recompute, score recompute, threshold.
    """
    issuer = credential.get("issuer", "")
    policy = ParcAdmissionPolicy(
        trusted_issuers={issuer} if isinstance(issuer, str) and issuer else set(),
        min_reputation_score=min_reputation_score,
    )
    try:
        res = parc_admit(credential, policy=policy, ledger=ledger,
                         is_valid=_receipt_is_valid, now=_now_z())
    except Exception:
        # A hostile credential/ledger must yield a typed refusal, never a 500
        # (and never a stack trace). The generic catch is deliberate: sm-parc
        # rejects malformed inputs with typed results, so anything that still
        # raises is by definition input we do not want to reason further about.
        res = ParcAdmissionResult(False, "malformed_credential",
                                  "credential or ledger not processable")
    subject = credential.get("credentialSubject") or {}
    certified = bool(res.ok)
    stage = res.stage
    reasons = [res.detail if res.detail else res.stage]
    anchors = _anchor_set()
    anchored: Optional[bool] = None
    if certified:
        anchored = bool(anchors) and _touches_anchor(ledger, anchors)
        if not anchored:
            certified = False
            stage = "anchor_absent"
            if not anchors:
                reasons = ["no anchors configured: with an empty anchor set "
                           "the Notary cannot tell corroboration from "
                           "self-corroboration, so it stamps nothing (set "
                           "NOTARY_ANCHORS or register a lab-countersigned badge)"]
            else:
                reasons = ["no verified corroboration from any anchor: a "
                           "recomputable score alone can be self-corroborated, "
                           "so the history must include at least one receipt "
                           "co-signed by an anchor did (a NOTARY_ANCHORS did, or "
                           "a key registered with a lab-countersigned badge)"]
    if certified:
        reasons = ["clean: proof, validity window, ledger recomputation, "
                   "score threshold, and anchor rule all OK"]
    return {
        "certified": certified,
        "stage": stage,
        "anchored": anchored,
        "anchor_count": len(anchors),
        "subject_did": subject.get("id"),
        "issuer_did": issuer,
        "scoring_method": subject.get("scoring_method"),
        "claimed": {k: subject.get(k) for k in
                    ("reputation_score", "validity_rate", "corroboration_rate",
                     "receipt_count")},
        "min_reputation_score": min_reputation_score,
        "attests": "proof verified + ledger recomputed; NOT issuer endorsement",
        "reasons": reasons,
    }


# --- Endpoints ---------------------------------------------------------------
@app.get("/skill.md")
def skill_md():
    """The SkillMD, served from the deployed tree — always matches the code."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skill.md")
    with open(path, encoding="utf-8") as f:
        return PlainTextResponse(f.read(), media_type="text/markdown")


@app.get("/")
def info():
    return {
        "office": "The Town Notary",
        "versions": {
            "service": app.version,
            "sm_parc": importlib.metadata.version("sm-parc"),
            "sm_conformance": importlib.metadata.version("sm-conformance"),
        },
        "purpose": "Verify and register agent conformance badges; issue lab counter-signatures.",
        "notary_did": NOTARY_DID,
        "registered": len(REGISTER),
        # The admission configuration in force, so a relying party can see
        # exactly what "certified", "listed" and "anchor" mean here.
        "admission": {
            "suite_pins": {p: sorted(d) for p, d in sorted(SUITE_PINS.items())},
            "lab_dids": sorted(LAB_DIDS),
            "root_anchors": sorted(NOTARY_ANCHORS),
            "anchors": len(_anchor_set()),
        },
        # Record this pair elsewhere to detect later removal of log records.
        "register_head": dict(_HEAD),
        "endpoints": ["POST /verify", "POST /register", "GET /register",
                      "GET /inspect", "POST /countersign",
                      "POST /verify-parc", "POST /countersign-parc",
                      "GET /skill.md"],
        "skill_md": "/skill.md",
    }


@app.post("/verify")
def verify(req: VerifyReq):
    """Verify a badge offline. Does NOT record it. Read-only check."""
    return _assess(_resolve(req), req.expected_suite_digest, req.max_age_days)


@app.post("/register")
def register(req: VerifyReq):
    """Verify, then enter a passing runtime in the public register.

    Standing: "listed" for a certifying self-signed badge; "anchor" only for a
    certifying badge counter-signed by a NOTARY_LAB_DIDS lab. The entry is
    keyed by the runtime's own did:key (the inner signer for a counter-signed
    envelope) and appended to the register log.
    """
    badge = _resolve(req)
    a = _assess(badge, req.expected_suite_digest, req.max_age_days)
    if not a["certified"]:
        raise HTTPException(422, {"refused": "badge did not certify", "assessment": a})
    key = a["signer_did"]
    standing = _standing(a)
    with _REGISTER_LOCK:
        existing = REGISTER.get(key)
        if existing is not None and existing.get("badge") == badge:
            # Same badge again: nothing new to record, so nothing is appended.
            return {"registered": True, "key": key, "standing": existing["standing"],
                    "appended": False, "entry": existing}
        if existing is not None and existing["standing"] == "anchor" and standing != "anchor":
            # Badges are public (GET /register), so without this anyone could
            # replay an anchor's older self-signed badge to demote it.
            raise HTTPException(409, {
                "refused": "this key is an anchor; a new registration for it "
                           "must also be counter-signed by a configured lab",
                "assessment": a,
            })
        # Keep the full badge: it makes entries re-verifiable and lets standing
        # be recomputed from it on every start.
        entry = {**a, "standing": standing, "registered_at": _now(), "badge": badge}
        record = _append("register", key, entry)
        entry = REGISTER[key]
    return {"registered": True, "key": key, "standing": entry["standing"],
            "appended": True, "seq": record["seq"], "entry": entry}


@app.get("/register")
def list_register():
    """The public roll of certified runtimes — the town's register of trusted scales."""
    entries = list(REGISTER.values())
    return {"count": len(entries),
            "anchors": sum(1 for e in entries if e.get("standing") == "anchor"),
            "head": dict(_HEAD),
            "register": entries}


@app.get("/inspect")
def inspect(runtime: Optional[str] = None, did: Optional[str] = None):
    """Look up one runtime's standing before you deal with it."""
    if did and did in REGISTER:
        return REGISTER[did]
    if runtime:
        for entry in REGISTER.values():
            if entry.get("runtime") == runtime:
                return entry
    raise HTTPException(404, "not on the register")


@app.post("/countersign")
def countersign(req: CountersignReq):
    """Rung-2: the Notary re-attests a badge under its own key — the official stamp.

    A stamp must mean AT LEAST as much as a register entry, so the badge has to
    clear the SAME admission gates as /register (valid signature + schema, the
    pass-gate, the configured suite pins, and any suite/freshness pins you
    supply). The Notary VERIFIES; it does not re-run the suite — `method`
    records which claim the stamp carries. Because this endpoint stamps for
    anyone, the Notary's own stamp never promotes a key to anchor (startup
    refuses NOTARY_LAB_DIDS containing NOTARY_DID).
    """
    badge = _resolve(req)
    a = _assess(badge, req.expected_suite_digest, req.max_age_days)
    if not a["certified"]:
        raise HTTPException(422, {
            "refused": "will not counter-sign a badge that does not certify",
            "assessment": a,
        })
    stamped = counter_sign(badge, LAB_SEED, _now(), method=req.method)
    return {"countersigned_by": NOTARY_DID, "method": req.method,
            "assessment": a, "badge": stamped}


@app.post("/verify-parc")
def verify_parc(req: ParcReq):
    """Verify + recompute a PARC reputation credential. Read-only, stamps nothing."""
    credential, ledger = _resolve_parc(req)
    return _assess_parc(credential, ledger, req.min_reputation_score)


@app.post("/countersign-parc")
def countersign_parc(req: ParcReq):
    """Rung-2 for portable reputation: recompute, then stamp under the Notary key.

    The envelope mirrors the sm-conformance counter-signed badge shape —
    `payload` (signed), `countersigned_by`, `countersigned_at`,
    `countersignature` = base64 Ed25519 over the RFC 8785 (JCS) canonical bytes
    of `payload` (the same canonical signing path as the credential's own
    proof; badges use the float-free `canonical_json`, credentials carry float
    scores so they sign under JCS) — with
    `credential` in place of `badge` and the honest method
    `verified-recomputed`: the Notary verified the proof AND re-derived the
    merkle root + nanda-rep/0.2 scores from the presented ledger. It did not
    witness the underlying interactions, and the stamp is not issuer
    endorsement. A relying party in another trust domain can verify the stamp
    offline against the Notary's published did:key, then recompute the ledger
    itself — trust the maths twice, no server ever.
    """
    credential, ledger = _resolve_parc(req)
    a = _assess_parc(credential, ledger, req.min_reputation_score)
    if not a["certified"]:
        raise HTTPException(422, {
            "refused": "will not counter-sign a credential that does not recompute",
            "assessment": a,
        })
    stamped_at = _now_z()
    payload = {
        # Domain separation: the Notary key signs two protocols (badge
        # counter-signatures and these); the explicit type tag prevents any
        # cross-protocol confusion regardless of schema quirks. The timestamp
        # lives INSIDE the signed payload — unlike the badge envelope's
        # advisory copy — because reputation decays and stamp age matters.
        "type": "parc-countersign/1",
        "schema_version": 1,
        "credential": credential,
        "method": "verified-recomputed",
        "countersigned_at": stamped_at,
    }
    signature = _priv.sign(jcs.canonicalize(payload))
    stamped = {
        "payload": payload,
        "countersigned_by": NOTARY_DID,
        "countersigned_at": stamped_at,  # display copy; the signed one governs
        "countersignature": base64.b64encode(signature).decode("ascii"),
    }
    return {"countersigned_by": NOTARY_DID, "method": "verified-recomputed",
            "assessment": a, "credential": stamped}
