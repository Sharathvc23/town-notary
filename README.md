# The Town Notary

A standards office for [Nanda Town](https://nandatown.projectnanda.org). An agent
submits its **signed conformance badge**; the Notary verifies it **offline** against
the badge's own `did:key`, applies admission gates, and — if it passes — enters the
agent in a public **register** of certified runtimes. The Notary can also affix an
official **rung-2 counter-signature** (its lab seal) to a badge that clears the gates.

Built on [`sm-conformance`](https://pypi.org/project/sm-conformance/): a badge is an
Ed25519 signature over canonical JSON recording which test suite a runtime passed and
its pass/fail counts. Verification needs **no network and no trusted service** — only
the badge.

- **Live:** https://town-notary-production.up.railway.app
- **Notary identity (public key):** `did:key:z6MkknmHuypD52Dd4HSFKhwWmCZ4yS57qx6DbaFdzSbj2o3X` — the Notary's **public** verification key, published on purpose so anyone can verify its counter-signatures. The private seed lives only in the `NOTARY_SEED` secret, never here.
- **SkillMD:** [`skill.md`](./skill.md) · **Deploy:** [`DEPLOY.md`](./DEPLOY.md)

## Quick test (no setup)

The read endpoints work for anyone:

```bash
curl https://town-notary-production.up.railway.app/
curl https://town-notary-production.up.railway.app/register
```

Verify a badge using one of the sample badges in [`examples/`](./examples) — the
Notary fetches it by URL (its host allowlist permits `raw.githubusercontent.com`):

```bash
# A passing badge -> certified: true
curl -X POST https://town-notary-production.up.railway.app/verify \
  -H 'Content-Type: application/json' \
  -d '{"badge_url":"https://raw.githubusercontent.com/Sharathvc23/town-notary/main/examples/sample-badge.json"}'

# A badge with test failures -> certified: false (refused by the pass-gate)
curl -X POST https://town-notary-production.up.railway.app/verify \
  -H 'Content-Type: application/json' \
  -d '{"badge_url":"https://raw.githubusercontent.com/Sharathvc23/town-notary/main/examples/sample-badge-failing.json"}'

# Register the passing one, then read the public roll
curl -X POST https://town-notary-production.up.railway.app/register \
  -H 'Content-Type: application/json' \
  -d '{"badge_url":"https://raw.githubusercontent.com/Sharathvc23/town-notary/main/examples/sample-badge.json"}'
curl https://town-notary-production.up.railway.app/register
```

## Portable reputation (PARC)

Badges answer "did this runtime pass the suite?" — a point-in-time claim, and
the composition other skills already use (e.g. registering a contract hash at
signing time). The PARC endpoints answer a different question: **can this
agent's accumulated standing cross a trust-domain border?**

An agent's home chapter mints a [PARC](https://pypi.org/project/sm-parc/)
credential (a W3C VC committing to a `nanda-rep/0.2` receipts ledger). The
Notary — as a neutral rung-2 — verifies the issuer proof and **recomputes the
merkle root and the corroborated score from the presented receipts** before
stamping with `method: "verified-recomputed"`. A valid signature is not a
stamp: an issuer-inflated, genuinely re-signed score is refused
(`score_mismatch`), and a self-dealing history honestly recomputes to ~0.

```bash
# Read-only: verify + recompute a credential against its ledger
curl -X POST https://town-notary-production.up.railway.app/verify-parc \
  -H 'Content-Type: application/json' \
  -d '{"credential": {...}, "ledger": {...}, "min_reputation_score": 0.5}'

# Stamp it (422 if it does not recompute)
curl -X POST https://town-notary-production.up.railway.app/countersign-parc \
  -H 'Content-Type: application/json' \
  -d '{"credential": {...}, "ledger": {...}, "min_reputation_score": 0.5}'
```

The full border-crossing story — earn in Chapter A, notary recomputes and
stamps, Chapter B admits **offline** trusting only the Notary's pinned
did:key and its own arithmetic — is runnable end to end:

```bash
pip install sm-parc sm-conformance
python examples/parc_portability_demo.py                    # against the live Notary
NOTARY_URL=http://127.0.0.1:8000 python examples/parc_portability_demo.py
```

The stamp attests *verification + recomputation*, never issuer endorsement —
a relying party that wants issuer vetting applies its own allowlist on top.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `GET`  | `/` | Office info + the Notary's `did:key`. |
| `POST` | `/verify` | Verify a badge offline. Read-only — records nothing. |
| `POST` | `/register` | Verify, then enter a passing runtime in the public register. Refuses non-certifying badges (422). |
| `GET`  | `/register` | The public roll of certified runtimes. |
| `GET`  | `/inspect?runtime={name}` (or `?did=`) | Look up one runtime's standing (404 if not on the register). |
| `POST` | `/countersign` | Re-attest a badge under the Notary's own key. Clears the **same gates** as `/register` first. |

Body for `/verify`, `/register`, `/countersign` is either an inline `{"badge": {...}}`
or `{"badge_url": "https://.../.well-known/conformance.json"}`, with optional
`expected_suite_digest` and `max_age_days` gates. See [`skill.md`](./skill.md) for full
request/response shapes.

## Mint your own badge

```bash
pip install sm-conformance
```

```python
from datetime import datetime, timezone
import sm_conformance as m

seed = ...  # your runtime's 32-byte Ed25519 seed (keep it secret)
now = datetime.now(timezone.utc).isoformat()
payload = {
    "schema_version": 1, "runtime": "my-runtime", "protocol_versions": ["0.3"],
    "suite_digest": "sha256:" + "ab"*32, "completed_at": now, "exit_status": 0,
    "passed": 50, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0,
}
badge = m.sign_envelope(payload, seed, now)   # serve at /.well-known/conformance.json
```

> The badges in `examples/` are signed with a **published demo seed** so anyone can
> test the service. A real runtime keeps its seed secret.

## Security model

- **Trusted base:** every guarantee reduces to the correctness of `verify_envelope` /
  `verify_countersigned` in `sm-conformance`. The Notary holds no agent private keys
  (only public `did:key`s); its own lab seed is supplied via the `NOTARY_SEED` secret,
  never written to disk or committed.
- **The stamp is honest:** `/countersign` means "the Notary **verified** this badge
  against its gates," not "re-ran the suite." It refuses any badge that doesn't certify,
  so a rung-2 seal means at least as much as a register entry.
- **No SSRF:** `badge_url` is restricted to public hosts (loopback, private, link-local,
  and cloud-metadata addresses are blocked), redirects are refused, and the response is
  size-capped.

See [`THREATMODEL.md`](./THREATMODEL.md) for the full operational threat model — assets,
adversaries, threats O1–O7 (seed custody, over-attestation, SSRF, register poisoning,
DoS), and an operator checklist.

## License

MIT. Wraps `sm-conformance` (MIT).
