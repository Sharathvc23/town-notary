# The Town Notary

A standards office for [Nanda Town](https://nandatown.projectnanda.org). An agent
submits its **signed conformance badge**; the Notary verifies it **offline** against
the badge's own `did:key`, applies admission gates (including a **pinned suite** per
protocol version), and — if it passes — enters the agent in a public **register** of
certified runtimes. A self-signed badge is **listed**; a badge counter-signed by a
configured lab makes its key an **anchor** for portable reputation (below). The Notary
can also affix an official **rung-2 counter-signature** (its lab seal) to a badge that
clears the gates.

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

`GET /` also reports the admission configuration in force (`admission.suite_pins`,
`lab_dids`, `root_anchors`) and the register log's current head.

Verify a badge using one of the sample badges in [`examples/`](./examples) — the
Notary fetches it by URL (only public hosts; `raw.githubusercontent.com` is one):

```bash
# A signed, passing badge. Its suite_digest (sha256:abab…) is a placeholder, so
# the result depends on the Notary's pins: certified: true only where that digest
# is pinned for protocol 0.3, otherwise certified: false, "suite not pinned".
curl -X POST https://town-notary-production.up.railway.app/verify \
  -H 'Content-Type: application/json' \
  -d '{"badge_url":"https://raw.githubusercontent.com/Sharathvc23/town-notary/main/examples/sample-badge.json"}'

# A badge with test failures -> certified: false (refused by the pass-gate)
curl -X POST https://town-notary-production.up.railway.app/verify \
  -H 'Content-Type: application/json' \
  -d '{"badge_url":"https://raw.githubusercontent.com/Sharathvc23/town-notary/main/examples/sample-badge-failing.json"}'

# Register it (same gates: 422 unless it certifies), then read the public roll
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
did:key and its own arithmetic — is runnable end to end against a **local**
Notary. The demo's keys (including its demo lab) come from published seeds, so
its configuration is for local use only:

```bash
pip install -r requirements.txt
eval "$(python examples/parc_portability_demo.py --env)"   # demo pins, lab, root anchor
uvicorn app:app --port 8000 &
python examples/parc_portability_demo.py                   # NOTARY_URL defaults to :8000
```

The stamp attests *verification + recomputation*, never issuer endorsement —
a relying party that wants issuer vetting applies its own allowlist on top.

**The anchor rule.** did:keys are free to mint, so one party can produce a
recomputable corroborated score by co-signing its own receipts with fresh keys.
A stamp therefore also requires at least one receipt whose counterparty is an
**anchor** and whose co-signature by that anchor verifies. The anchor set is:

- the `NOTARY_ANCHORS` dids (the configured root), plus
- every register key whose standing is `anchor`: registered with a badge that is
  counter-signed by a `NOTARY_LAB_DIDS` lab, with both signatures verifying and the
  badge clearing the same gates as any registration.

A **self-signed** registration is `listed` and never enters the anchor set — anyone
can mint a key and register it. Nor does the Notary's own `/countersign` stamp, which
it issues to any caller (startup refuses a `NOTARY_LAB_DIDS` that contains the Notary's
own did). If the anchor set is **empty**, every stamp is refused `anchor_absent`. The
documented residual: a party that obtains one genuine co-signed receipt from an anchor
satisfies the rule.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `GET`  | `/` | Office info, the Notary's `did:key`, the admission configuration, and the register log head. |
| `POST` | `/verify` | Verify a badge offline. Read-only — records nothing. |
| `POST` | `/register` | Verify, then append the runtime to the register with standing `listed` (self-signed) or `anchor` (lab-countersigned). 422 if the badge does not certify; 409 if the key is an anchor and the new badge is not lab-countersigned. Re-sending the identical badge appends nothing. |
| `GET`  | `/register` | The public roll: one entry per key (the latest record), with `standing`. |
| `GET`  | `/inspect?runtime={name}` (or `?did=`) | Look up one runtime's entry and standing (404 if not on the register). |
| `POST` | `/countersign` | Re-attest a badge under the Notary's own key. Clears the **same gates** as `/register` first. Does not make the key an anchor. |
| `POST` | `/verify-parc`, `/countersign-parc` | Verify + recompute (and stamp) a PARC credential — see above. |
| `GET`  | `/skill.md` | The SkillMD served by this deployment. |

Body for `/verify`, `/register`, `/countersign` is either an inline `{"badge": {...}}`
or `{"badge_url": "https://.../.well-known/conformance.json"}`, with optional
`expected_suite_digest` and `max_age_days` gates (applied on top of the configured
suite pins). See [`skill.md`](./skill.md) for full request/response shapes.

## Admission gates

A badge **certifies** when all of these hold (the same set for `/verify`, `/register`
and `/countersign`):

1. **Signatures and schema** — `verify_envelope`, or for a counter-signed envelope
   `verify_countersigned` (inner badge and lab signature), from `sm-conformance`.
2. **Pass-gate** — `failed == 0` and `exit_status == 0`.
3. **Suite pin** — for **every** protocol version in `protocol_versions`,
   `NOTARY_SUITE_PINS` has a pin and the badge's `suite_digest` is one of that
   version's pinned digests. With no pins configured, no badge certifies.
4. The caller's optional `expected_suite_digest` and `max_age_days`.

A certifying badge registers with standing **`anchor`** when it is counter-signed and
`countersigned_by` is one of `NOTARY_LAB_DIDS` — the server-side equivalent of
`python -m sm_conformance.verify_badge --require-countersigned --trusted-signer <lab>`.
Otherwise its standing is **`listed`**. Entries are keyed by the runtime's own
`did:key` (for a counter-signed envelope, the inner badge's signer).

## Configuration

| Variable | Meaning |
|---|---|
| `NOTARY_SEED` | 64 hex chars: the Notary's Ed25519 seed (its `did:key`). Unset → insecure dev seed with a warning. |
| `NOTARY_SUITE_PINS` | JSON object `{"<protocol version>": "sha256:<hex>"}`; a value may be a list of digests (e.g. during a suite rotation). Unset → every badge is refused. |
| `NOTARY_LAB_DIDS` | Comma-separated `did:key`s whose counter-signature makes a registered key an anchor. Must not include the Notary's own `did:key`. |
| `NOTARY_ANCHORS` | Comma-separated root anchor dids for the PARC anchor rule. |
| `REGISTER_PATH` | File for the append-only register log (e.g. on a mounted volume). Unset → in memory only. |

A malformed `NOTARY_SUITE_PINS` or `NOTARY_LAB_DIDS` stops startup.

## The register log

The register is an append-only JSON Lines file at `REGISTER_PATH`. Each line is one
record `{"seq", "prev", "at", "op", "key", "entry", "hash"}`, written as
`json.dumps(sort_keys=True, separators=(",", ":"))`; `hash` is SHA-256 over that
serialization of the record without `hash`, and `prev` is the previous record's
`hash` (64 zeros for the first). A registration appends one line (opened in append
mode, then `fsync`); no line is rewritten.

- **On every start** the whole file is checked — canonical form, `seq`, `prev` link,
  and `hash` for each line. Any mismatch, including a partial last line, stops the
  service with `RegisterChainError` naming the line.
- **Standing is recomputed on start** from each entry's stored badge against the
  current `NOTARY_SUITE_PINS` / `NOTARY_LAB_DIDS`; the file's own `standing` field is
  not trusted. Removing a lab from the configuration therefore removes the anchors it
  promoted at the next start.
- **What the chain shows and what it doesn't:** editing, deleting or reordering
  existing lines breaks the chain. It does not say who wrote the file — anyone who
  can write it can recompute every hash — and records cut from the end leave a
  shorter, valid chain. To notice that, keep a copy of `register_head` from `GET /`
  somewhere else and compare.
- **New log:** starts with `import` records for the grandfathered entries in
  `data/register-seed.json`. These carry no badge, so they are `listed`.
- **Earlier format:** a `REGISTER_PATH` that still holds the earlier single-object
  JSON snapshot is converted once at start. The original bytes are kept at
  `<REGISTER_PATH>.pre-chain.json`, and each of its entries becomes an `import`
  record (standing recomputed as above).

## Mint your own badge

```bash
pip install sm-conformance
```

The Notary only certifies a badge whose `suite_digest` it pins for every listed
protocol version, so use the digest of the suite you actually ran
(`sm_conformance.compute_suite_digest`).

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

## Trust model

- **Verification code:** signature and schema checks are `verify_envelope` /
  `verify_countersigned` in `sm-conformance`; the Notary adds the gates above. The
  Notary holds no agent private keys (only public `did:key`s); its own seed is
  supplied via the `NOTARY_SEED` secret and is not written to disk or committed.
- **What a stamp means:** `/countersign` means "the Notary **verified** this badge
  against its gates," not "re-ran the suite." It refuses any badge that doesn't
  certify, so a stamped badge has cleared at least the checks a register entry has.
- **What a listing means:** "this `did:key` presented a signed, passing badge for a
  pinned suite" — not who controls the key. Only `anchor` standing feeds the PARC
  anchor rule.
- **`badge_url` fetching:** http(s) only; the host must resolve exclusively to public
  addresses (loopback, private, link-local and cloud-metadata ranges are refused);
  redirects are not followed; the response read is capped at 1 MB.

See [`THREATMODEL.md`](./THREATMODEL.md) for the operational threat model — assets,
adversaries, threats O1–O8 (seed custody, over-attestation, SSRF, register poisoning,
DoS, register integrity, self-registered anchors), residuals, and an operator
checklist.

## License

MIT. Wraps `sm-conformance` (MIT).
