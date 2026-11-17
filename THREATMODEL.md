# Threat Model — The Town Notary

This is an **operational / service** threat model for the Town Notary deployment. It is a
*different flavor* from the protocol threat models it builds on: the Town Notary is a live
HTTP service that is both **a relying party** for
[`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) badges and a **rung-2
issuer** (it counter-signs). So its threats are about key custody, abuse of its
endpoints, and the honesty of what its register and stamp *mean* — not about the badge
format itself.

- **Protocol TCB** is inherited: every conformance guarantee reduces to `verify_envelope`
  / `verify_countersigned` in `sm-conformance` (see that repo's `THREATMODEL.md`, threats
  T1–T10). The Notary implements that document's relying-party checklist steps 1–6
  server-side.
- This document covers what the *service* adds.

## 1. Assets

- **The lab signing seed (`NOTARY_SEED`)** — the entire value of every rung-2
  counter-signature rests on it staying secret.
- **Integrity / meaning of the public register** — what "listed" and "anchor"
  actually assert, and that recorded entries are not silently changed.
- **Meaning of a counter-signature** — that a stamp conveys real additional trust.
- **Availability** of the endpoints (a SkillMD is only live if they answer).

## 2. Adversaries

- A **runtime seeking a false stamp or listing** it didn't earn.
- An attacker probing `badge_url` for **SSRF** / internal-network access.
- A **resource-exhaustion / DoS** actor.
- Any member of the public — the register and the Notary's `did:key` are open by design.
- A party that **mints keys freely** to manufacture corroboration (Sybil).
- Anyone with **write access to the register volume**.

## 3. Threats

| # | Attack | Defended by | Residual risk |
|---|---|---|---|
| **O1** | **Lab seed compromise** → forge Notary counter-signatures as the lab. | seed lives **only** in the platform secret store (`NOTARY_SEED`), never in code/git/disk; rotated via stdin, not a file | single key, no HSM, and **no revocation** of the Notary's `did:key` — a leak means rotating the seed, which invalidates all prior stamps (their `did:key` changes) |
| **O2** | **Over-attestation ("cheapest false stamp").** Get the lab to stamp a badge that records failures, is stale, or is for the wrong suite. | `/countersign` applies the **same admission gates as `/register`** (signature + pass-gate + the configured `NOTARY_SUITE_PINS` + caller suite/freshness pins); refuses non-certifying badges (422) | trust in a stamp = trust in the Notary's gate policy; `method:"verified"` means *verified, not re-run* — it is not fresh test evidence |
| **O3** | **SSRF via `badge_url`.** Point the fetch at `localhost`, RFC-1918, or `169.254.169.254`. | scheme + **host allowlist** (block loopback/private/link-local/reserved/multicast/metadata); redirects refused; 1 MB read cap; errors are generic (no internal-shape leak) | **DNS-rebinding TOCTOU**: the host is checked at resolve time and `urlopen` re-resolves — a rebind between the two could slip through. Pin the resolved IP for a fully robust fix. |
| **O4** | **Register spoofing / poisoning.** Anyone `POST /register`s a validly-signed passing badge — there is no caller auth or identity vetting. | every entry is verified + gated: signatures, pass-gate, and a suite pinned for every claimed protocol version (a badge for a `did:key` you don't hold cannot be produced); entries are keyed by the runtime's own `did:key` | a listing asserts only *"this `did:key` presented a passing badge for a pinned suite"* — **not** real-world identity. No auth/rate-limit ⇒ register **spam** is possible. `runtime` names are not unique: `/inspect?runtime=` returns the first entry with that name, so look up by `did`. Anyone can re-submit a key's older public badge, which becomes that key's displayed entry (the latest record wins); it cannot lower an anchor to listed (409) |
| **O5** | **No authentication / authorization.** `/register` and `/countersign` are open; the Notary will stamp any certifying badge on request. | gating ensures only *certifying* badges are stamped/listed | by design for a *public* notary — but the stamp conveys "the badge passed," not "this caller is authorized." Add caller auth if you want a private notary |
| **O6** | **Denial of service / resource exhaustion.** Hammer the endpoints, or feed slow/large `badge_url`s. | per-fetch 8 s timeout + 1 MB cap; re-sending an identical badge appends nothing | **no rate limiting**; the register log grows by one line per distinct certifying badge, with no size cap |
| **O7** | **Register loss or tampering.** Entries vanish on restart, or someone with volume access edits, deletes or reorders records. | with `REGISTER_PATH` set, the register is an **append-only JSON Lines log** (append mode + `fsync`, no line rewritten). Each record carries `prev` = the previous record's SHA-256 `hash`. On every start the whole chain (canonical form, `seq`, `prev`, `hash`) is checked and the service **does not start** on any mismatch. Standing is recomputed from each stored badge against the current configuration, never read from the file | without `REGISTER_PATH` the log is in memory and lost on restart. The chain is unkeyed: a writer with file access can rewrite and rehash it — that can alter or drop listings but cannot create an anchor without a configured lab's signature. Records cut from the **end** leave a valid shorter chain; detecting that needs a `register_head` (from `GET /`) recorded elsewhere. A crash mid-append leaves a partial last line, which stops the service until an operator inspects and repairs the file. Assumes **one writer process** (the lock is in-process; the Procfile runs a single uvicorn worker) |
| **O8** | **Self-registered anchors (Sybil).** Mint a key, register it with a self-signed passing badge, then co-sign your own agent's receipts with it so the PARC anchor rule is satisfied. | registration standing is split: a self-signed badge is **listed** only; **anchor** requires a counter-signature by a `NOTARY_LAB_DIDS` lab (both signatures verified, all gates cleared). The Notary's own key is refused as a lab at startup, because `/countersign` stamps for anyone. An empty anchor set refuses every PARC stamp | anchor standing is only as good as the configured labs' counter-signing practice; a compromised lab key can promote keys until it is removed from `NOTARY_LAB_DIDS` and the service restarts (its anchors then revert to listed). One genuine co-signed receipt from an anchor still satisfies the rule (P4) |

### PARC endpoints (portable reputation)

The `/verify-parc` and `/countersign-parc` surface inherits O1–O8 and adds:

- **P1 — Inflated-but-signed scores.** A trusted-looking issuer re-signs a
  bumped score. Mitigated by construction: the Notary recomputes the merkle
  root and nanda-rep/0.2 scores from the presented ledger; divergence is a 422
  (`score_mismatch`). The stamp is therefore *recomputation*, not deference.
- **P2 — Withheld receipts.** A presenter drops bad receipts from the ledger.
  Mitigated: the credential's signed `receipt_count` and merkle root must both
  match the presented ledger (sm-parc's anti-withholding checks).
- **P3 — Recompute-cost DoS.** A hostile ledger forces expensive verification.
  Mitigated: `PARC_MAX_RECEIPTS` (5000) request cap, a 5 MB inline body cap
  (Content-Length-based; a chunked request without Content-Length bypasses the
  early check and is bounded only by the platform), plus the same 1 MB / SSRF
  fetch guards as badges. No rate limiting — rely on the platform's.
- **P4 — Stamp overclaim.** Relying parties reading the stamp as issuer
  endorsement. Mitigated in-band: the signed method is `verified-recomputed`
  and every assessment carries `"attests": "... NOT issuer endorsement"`.
  Free-to-mint counterparty dids corroborating their own receipts are
  addressed by the ANCHOR RULE: a stamp requires at least one receipt whose
  counterparty is in the anchor set AND whose co-signature by that anchor
  verifies — refusal stage `anchor_absent`. The anchor set is NOTARY_ANCHORS
  plus register keys with standing `anchor` (lab-countersigned, see O8); a
  self-signed registration does not add to it. An empty anchor set refuses
  every stamp (there is no bootstrap mode). Remaining residuals: an attacker
  who obtains ONE genuine corroborated receipt from an anchor passes the rule
  (sm-parc's own documented required_anchors residual), and an inline
  single-subject ledger still cannot reveal an N-party ring among non-anchor
  parties (published-ledger severance remains out of scope for this service).
- **P5 — Timestamp trust.** RESOLVED for PARC stamps: `countersigned_at` is
  inside the signed payload (the top-level copy is display-only). The badge
  envelope's timestamp remains advisory (sm-conformance format, unchanged).
- **P6 — Cross-protocol signature confusion.** The Notary key signs badge
  counter-signatures and PARC stamps. PARC payloads carry an explicit signed
  `"type": "parc-countersign/1"` tag, so a stamp can never be replayed as a
  badge attestation or vice versa.
- **P7 — Register durability.** The register is the append-only log of O7.
  A new log starts with `import` records for `data/register-seed.json`
  (entries issued before persistence existed), so a redeploy does not drop
  already-issued registrations (e.g. notarized A2A contracts). A
  `REGISTER_PATH` still in the earlier single-object JSON format is converted
  once at start; its original bytes are kept at
  `<REGISTER_PATH>.pre-chain.json`. Entries store the full badge, so they are
  re-verifiable; grandfathered seed entries are assessments only, carry no
  badge, and are therefore always `listed`.

## 4. Explicit non-goals

- **Identity vetting** of registrants — the Notary certifies *badges*, not who controls a key.
- **Tamper-proof storage** — the register log makes edits to recorded entries
  detectable on start; it does not prevent them, authenticate the writer, or
  detect records removed from the end without an externally kept head.
- **Abuse protection** (rate-limiting, quotas) — not in scope for the reference deployment.
- **Confidentiality** — the register and the Notary `did:key` are public on purpose.
- **Re-running suites** — the Notary verifies; it does not execute anyone's tests.

## 5. Operator checklist

1. Keep `NOTARY_SEED` **only** in the platform secret store; set it via stdin
   (`--set-from-stdin`), never a file or commit; rotate on any suspected exposure (accept
   that rotation changes the Notary's `did:key` and invalidates prior stamps).
2. Treat the published `did:key` as the **public** verification key — it is meant to be
   shared; it is not a secret.
3. Set `NOTARY_SUITE_PINS` to the digests of the suites you actually accept;
   without it every badge is refused. Put in `NOTARY_LAB_DIDS` only labs whose
   counter-signing practice you trust (never the Notary's own `did:key`, which
   startup refuses, and never a key with a published seed such as the demo lab).
   Set `NOTARY_ANCHORS` to the root anchor dids; with no anchors, PARC stamps are refused.
4. Set `REGISTER_PATH` on a persistent volume, back the file up, run a **single**
   process, and periodically record `register_head` from `GET /` somewhere else.
   If startup fails with `RegisterChainError`, inspect the named line before
   changing anything; a partial last line after a crash is the expected case.
5. Before exposing long-term, add **rate limiting** and — if you want it
   non-public — **auth on `/register` and `/countersign`**.
6. Watch for SSRF allowlist bypass; if `badge_url` fetching is heavily used, pin the
   resolved IP to close the DNS-rebinding window (O3).
7. Communicate plainly what the artifacts mean: a **listing** = "presented a passing
   badge for a pinned suite"; an **anchor** = "listed, and counter-signed by a
   configured lab"; a **stamp** = "the Notary verified it against its gates," not a re-run.
