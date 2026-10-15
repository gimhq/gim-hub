# Identity formats

gim-core owns the identity wire formats; this repository does not define its own.
The normative spec and test vectors are vendored verbatim in `testdata/identity/`
(`identity.md`, `identity.json`; upstream revision in `testdata/identity/SOURCE`).
`crates/gim-hub-identity` implements the hub-side verification of that spec.
