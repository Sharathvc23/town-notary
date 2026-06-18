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
    derive_did_key,
    VerificationError,
    CountersignError,
)

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


# --- Endpoints ---------------------------------------------------------------
@app.get("/")
def info():
    return {
        "office": "The Town Notary",
        "purpose": "Verify and register agent conformance badges; issue lab counter-signatures.",
        "notary_did": NOTARY_DID,
        "registered": len(REGISTER),
        "endpoints": ["POST /verify", "POST /register", "GET /register",
                      "GET /inspect", "POST /countersign"],
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
