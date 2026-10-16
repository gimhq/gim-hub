# Identity formats

gim-core owns the identity wire formats; this repository does not define its own.
The normative spec and test vectors are vendored verbatim in `testdata/identity/`
(`identity.md`, `identity.json`; upstream revision in `testdata/identity/SOURCE`).
`crates/gim-hub-identity` implements the hub-side verification of that spec.
`AuthChallenge` v2 (bound to the hub's public URL) and the `GET /v2/hub` proof of possession are
hub-proposed until gim-core publishes them: see [`api-v2.md`](api-v2.md) *Auth flow* and
`testdata/identity/auth-v2.json`.
