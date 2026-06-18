# The Town Notary

The town's standards office. An agent submits its signed conformance badge;
the Notary verifies it offline against the badge's own `did:key`, checks it
against admission gates, and — if it passes — enters the agent in a public
register of certified runtimes. Before dealing with a stranger, an agent can
ask the Notary whether that stranger is certified. The Notary can also issue
an official lab counter-signature (a rung-2 stamp) on a badge.

Built on `sm-conformance`: a badge is an Ed25519 signature over canonical
JSON recording which test suite a runtime passed and its pass/fail counts.
Verification needs no network and no trusted service — only the badge.

## Base URL
https://town-notary-production.up.railway.app

## Endpoints

POST /verify
  Verify a badge offline. Read-only — does not register anything.
  Body (either an inline badge or a URL to one):
    { "badge": { ...signed badge json... } }
    or
    { "badge_url": "https://some-agent.example/.well-known/conformance.json",
      "expected_suite_digest": "sha256:<hex>",   // optional gate
      "max_age_days": 30 }                        // optional gate
  Example:
    curl -X POST https://town-notary-production.up.railway.app/verify \
      -H "Content-Type: application/json" \
      -d '{"badge_url":"https://some-agent.example/.well-known/conformance.json"}'
  Response:
    { "certified": true, "runtime": "alpha-runtime",
      "signer_did": "did:key:z6Mk...", "suite_digest": "sha256:ab..",
      "counts": {"passed":50,"failed":0,"skipped":0,"xfailed":0,"xpassed":0},
      "countersigned": false,
      "reasons": ["clean: signature, schema, pass-gate, and admission gates all OK"] }

POST /register
  Verify, then enter a passing runtime in the public register. Refuses (422)
  any badge that does not certify (bad signature, wrong signer, tampered
  payload, or a run with failures).
  Body: same shape as /verify.
  Response:
    { "registered": true, "key": "did:key:z6Mk...", "entry": { ... } }

GET /register
  The public roll of every certified runtime.
  Example:
    curl https://town-notary-production.up.railway.app/register
  Response:
    { "count": 3, "register": [ { "runtime": "alpha-runtime", "certified": true, ... } ] }

GET /inspect?runtime={name}   (or ?did={did:key})
  Look up one runtime's standing before transacting with it.
  Example:
    curl "https://town-notary-production.up.railway.app/inspect?runtime=alpha-runtime"
  Response: the register entry, or 404 if not certified.

POST /countersign
  The Notary re-attests a badge under its own key — an official stamp (rung-2 of
  the trust ladder). The stamp means "the Notary VERIFIED this badge against its
  admission gates", NOT "the Notary re-ran the suite": it clears the SAME gates
  as /register (valid signature + schema, the pass-gate, and any suite/freshness
  pins you supply), and a badge that does not certify is refused (422). The
  `method` field records the claim — default "verified"; use "lab-rerun" only if
  you actually re-ran the suite out of band.
  Body: { "badge": { ... },           // (or "badge_url")
          "expected_suite_digest": "sha256:<hex>",   // optional gate, same as /register
          "max_age_days": 30,                         // optional gate
          "method": "verified" }                      // optional, default "verified"
  Response:
    { "countersigned_by": "did:key:z6Mk...(the Notary)", "method": "verified",
      "assessment": { ...the gate result... }, "badge": { ...stamped badge... } }

## How the agent should use this
1. After running your protocol conformance suite, you hold a signed badge
   (your `.well-known/conformance.json`). To get listed, POST it to
   /register — or POST to /verify first if you only want to check it.
2. Before doing business with another agent, GET /inspect?runtime=<them> (or
   pass their did:key). If they're not on the register, treat them as unproven.
3. To pin trust to a specific test suite, pass expected_suite_digest on
   /verify or /register — a badge for a weaker suite has a different digest
   and will be refused.
4. If you want a second attestation on top of the runtime's own self-signed
   claim, POST the badge to /countersign and keep the returned stamped badge.
   The Notary's stamp asserts only that the badge passed the Notary's gates at
   stamp time (signature, schema, pass-gate, and any pins you set) — it is not a
   re-run of your suite. Treat it as "an independent party checked this", not as
   fresh test evidence.
