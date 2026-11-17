# Deploy the Notary (Railway)

A SkillMD is only live if its endpoints answer. This deploys to Railway with the
`railway` CLI.

## 1. A stable key
The Notary counter-signs under its own Ed25519 key. A 32-byte seed is set as the
`NOTARY_SEED` env var so the Notary's `did:key` survives restarts. Generate one:

    python3 -c "import os;print(os.urandom(32).hex())"

(Without it, the Notary boots on an insecure dev seed and warns loudly.)

## 2. Deploy (Railway)
From this folder:

    railway login            # one-time, browser auth (or: railway login --browserless)
    railway init -n town-notary
    railway up               # uploads this dir; Nixpacks reads requirements.txt + Procfile
    railway variables --set "NOTARY_SEED=<your hex seed>"
    railway domain           # generates a public https://<name>.up.railway.app URL

Nixpacks auto-detects Python from `requirements.txt` and uses the `Procfile`
start command (`uvicorn app:app --host 0.0.0.0 --port $PORT`). Railway injects
`$PORT`.

## 3. Test it before submitting
    curl https://<your-url>/                         # office info
    curl https://<your-url>/register                 # {"count":0,...}
If those answer, the Base URL in skill.md is already set to `<your-url>`; submit
at https://nandatown.projectnanda.org/skills

## Note on persistence
The register is an append-only, hash-chained JSON Lines log at `REGISTER_PATH`;
a new log starts with the committed `data/register-seed.json` entries
(grandfathered from before persistence existed). In production, mount a volume
and point at it:

    railway volume add --mount-path /data
    railway variables --set "REGISTER_PATH=/data/register.json"

Without `REGISTER_PATH` the service still boots with the seeded entries, but
registrations made after deploy will not survive the NEXT restart.

The chain is verified on every start and the service does not start if it is
broken (see README, "The register log"). A file still in the earlier
single-object JSON format is converted once at start; the original is kept
next to it as `register.json.pre-chain.json`.

## Note on admission settings
`NOTARY_SUITE_PINS` must be set for any badge to certify, `NOTARY_LAB_DIDS`
decides whose counter-signature makes a key an anchor, and `NOTARY_ANCHORS`
holds the root anchors; with no anchors, PARC stamps are refused. See README,
"Configuration".
