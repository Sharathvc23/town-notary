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
- **Integrity / meaning of the public register** — what "listed" actually asserts.
- **Meaning of a counter-signature** — that a stamp conveys real additional trust.
- **Availability** of the endpoints (a SkillMD is only live if they answer).

## 2. Adversaries

- A **runtime seeking a false stamp or listing** it didn't earn.
- An attacker probing `badge_url` for **SSRF** / internal-network access.
- A **resource-exhaustion / DoS** actor.
- Any member of the public — the register and the Notary's `did:key` are open by design.

## 3. Threats

| # | Attack | Defended by | Residual risk |
|---|---|---|---|
| **O1** | **Lab seed compromise** → forge Notary counter-signatures as the lab. | seed lives **only** in the platform secret store (`NOTARY_SEED`), never in code/git/disk; rotated via stdin, not a file | single key, no HSM, and **no revocation** of the Notary's `did:key` — a leak means rotating the seed, which invalidates all prior stamps (their `did:key` changes) |
| **O2** | **Over-attestation ("cheapest false stamp").** Get the lab to stamp a badge that records failures, is stale, or is for the wrong suite. | `/countersign` applies the **same admission gates as `/register`** (signature + pass-gate + suite/freshness pins); refuses non-certifying badges (422) | trust in a stamp = trust in the Notary's gate policy; `method:"verified"` means *verified, not re-run* — it is not fresh test evidence |
| **O3** | **SSRF via `badge_url`.** Point the fetch at `localhost`, RFC-1918, or `169.254.169.254`. | scheme + **host allowlist** (block loopback/private/link-local/reserved/multicast/metadata); redirects refused; 1 MB read cap; errors are generic (no internal-shape leak) | **DNS-rebinding TOCTOU**: the host is checked at resolve time and `urlopen` re-resolves — a rebind between the two could slip through. Pin the resolved IP for a fully robust fix. |
| **O4** | **Register spoofing / poisoning.** Anyone `POST /register`s a validly-signed passing badge — there is no caller auth or identity vetting. | every entry is cryptographically verified + gated (you cannot forge a badge for a `did:key` you don't hold) | a listing asserts only *"this `did:key` presented a passing badge"* — **not** real-world identity. No auth/rate-limit ⇒ register **spam** is possible |
| **O5** | **No authentication / authorization.** `/register` and `/countersign` are open; the Notary will stamp any certifying badge on request. | gating ensures only *certifying* badges are stamped/listed | by design for a *public* notary — but the stamp conveys "the badge passed," not "this caller is authorized." Add caller auth if you want a private notary |
| **O6** | **Denial of service / resource exhaustion.** Hammer the endpoints, or feed slow/large `badge_url`s. | per-fetch 8 s timeout + 1 MB cap | **no rate limiting**; the in-memory register grows unbounded until restart |
| **O7** | **Register volatility.** The register is in-memory and clears on restart/redeploy — a "listed" runtime can silently vanish. | documented as demo-grade | not durable; back `REGISTER` with sqlite/redis for production (verification logic is unchanged) |

## 4. Explicit non-goals

- **Identity vetting** of registrants — the Notary certifies *badges*, not who controls a key.
- **A durable register** — in-memory by design for the demo.
- **Abuse protection** (rate-limiting, quotas) — not in scope for the reference deployment.
- **Confidentiality** — the register and the Notary `did:key` are public on purpose.
- **Re-running suites** — the Notary verifies; it does not execute anyone's tests.

## 5. Operator checklist

1. Keep `NOTARY_SEED` **only** in the platform secret store; set it via stdin
   (`--set-from-stdin`), never a file or commit; rotate on any suspected exposure (accept
   that rotation changes the Notary's `did:key` and invalidates prior stamps).
2. Treat the published `did:key` as the **public** verification key — it is meant to be
   shared; it is not a secret.
3. Before exposing long-term, add **rate limiting**, a **durable register** (sqlite/redis),
   and — if you want it non-public — **auth on `/register` and `/countersign`**.
4. Watch for SSRF allowlist bypass; if `badge_url` fetching is heavily used, pin the
   resolved IP to defeat DNS rebinding (O3).
5. Communicate honestly what the artifacts mean: a **listing** = "presented a passing
   badge"; a **stamp** = "the Notary verified it against its gates," not a re-run.
