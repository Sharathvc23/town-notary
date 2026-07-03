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
"""
from __future__ import annotations

import os
import json
import base64
import socket
import ipaddress
import urllib.request
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
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
    VerificationError,
    CountersignError,
)
import jcs

from sm_arp import verify_receipt
from sm_parc import AdmissionPolicy as ParcAdmissionPolicy
from sm_parc import admit as parc_admit

app = FastAPI(title="The Town Notary", version="0.1.0")

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

# In-memory public register. Non-persistent: a restart clears it. For a real
# deployment back this with sqlite/redis; the verification logic is unchanged.
REGISTER: dict[str, dict[str, Any]] = {}


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


def _assess(badge: dict[str, Any],
            expected_suite_digest: Optional[str],
            max_age_days: Optional[int]) -> dict[str, Any]:
    """Verify a badge offline and apply civic admission gates.

    Returns a structured assessment. `verify_*` rejects tampered
    payloads/signatures and wrong signers — ASSUMING the trusted base
    (`sm-conformance`, see module docstring) is correct. It does NOT judge the
    run result, so the Notary adds the pass-gate (Gate 0) plus the optional
    suite-pin and freshness gates below.
    """
    reasons: list[str] = []
    countersigned = is_countersigned(badge)
    try:
        payload = verify_countersigned(badge) if countersigned else verify_envelope(badge)
    except (VerificationError, CountersignError) as e:
        return {"certified": False, "countersigned": countersigned,
                "reasons": [f"verification failed: {e}"]}

    ok = True
    # Gate 0: honest pass-gate. verify_* checks signature + schema but NOT the
    # run result, so the Notary enforces it: no failures, clean exit.
    if payload.get("failed", 0) != 0 or payload.get("exit_status", 0) != 0:
        ok = False
        reasons.append(
            f"run did not pass: failed={payload.get('failed')} "
            f"exit_status={payload.get('exit_status')}")
    # Gate 1: pinned suite — proves WHICH suite ran, not just that one did.
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
        reasons.append("clean: signature, schema, pass-gate, and admission gates all OK")

    return {
        "certified": ok,
        "runtime": payload.get("runtime"),
        "signer_did": badge.get("signed_by"),
        "suite_digest": payload.get("suite_digest"),
        "protocol_versions": payload.get("protocol_versions"),
        "counts": {k: payload.get(k) for k in
                   ("passed", "failed", "skipped", "xfailed", "xpassed")},
        "completed_at": payload.get("completed_at"),
        "countersigned": countersigned,
        "reasons": reasons,
    }


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
    res = parc_admit(credential, policy=policy, ledger=ledger,
                     is_valid=_receipt_is_valid, now=_now_z())
    subject = credential.get("credentialSubject") or {}
    certified = bool(res.ok)
    reasons = [res.detail if res.detail else res.stage]
    if certified:
        reasons = ["clean: proof, validity window, ledger recomputation, "
                   "and score threshold all OK"]
    return {
        "certified": certified,
        "stage": res.stage,
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
@app.get("/")
def info():
    return {
        "office": "The Town Notary",
        "purpose": "Verify and register agent conformance badges; issue lab counter-signatures.",
        "notary_did": NOTARY_DID,
        "registered": len(REGISTER),
        "endpoints": ["POST /verify", "POST /register", "GET /register",
                      "GET /inspect", "POST /countersign",
                      "POST /verify-parc", "POST /countersign-parc"],
    }


@app.post("/verify")
def verify(req: VerifyReq):
    """Verify a badge offline. Does NOT record it. Read-only check."""
    return _assess(_resolve(req), req.expected_suite_digest, req.max_age_days)


@app.post("/register")
def register(req: VerifyReq):
    """Verify, then enter a passing runtime in the public register."""
    a = _assess(_resolve(req), req.expected_suite_digest, req.max_age_days)
    if not a["certified"]:
        raise HTTPException(422, {"refused": "badge did not certify", "assessment": a})
    key = a["signer_did"] or a["runtime"]
    entry = {**a, "registered_at": _now()}
    REGISTER[key] = entry
    return {"registered": True, "key": key, "entry": entry}


@app.get("/register")
def list_register():
    """The public roll of certified runtimes — the town's register of trusted scales."""
    return {"count": len(REGISTER), "register": list(REGISTER.values())}


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
    pass-gate, and any suite/freshness pins you supply). The Notary VERIFIES; it
    does not re-run the suite — `method` records which claim the stamp carries.
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
    payload = {
        "schema_version": 1,
        "credential": credential,
        "method": "verified-recomputed",
    }
    signature = _priv.sign(jcs.canonicalize(payload))
    stamped = {
        "payload": payload,
        "countersigned_by": NOTARY_DID,
        "countersigned_at": _now(),
        "countersignature": base64.b64encode(signature).decode("ascii"),
    }
    return {"countersigned_by": NOTARY_DID, "method": "verified-recomputed",
            "assessment": a, "credential": stamped}
