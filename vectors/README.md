# Agent Passport test vectors — binding v1.1, envelope v1.0, mandate collector (2026-10-29)

Published subset of the holder implementation's vector set: the 21 binding cases, the three status lists, the registration snapshot, the test keys, the example envelope and — since 2026-10-29, with the authority's permission — the authority's indicative mandate block and the holder's 13 mandate-collector vectors over it. The record vectors (the collector's verdicts on the reputation issuer's indicative block) are not republished yet; that block belongs to its issuer.

**Publication (2026-10-28, envelope v1.0):** the binding `@context` second entry became the permanent identifier `https://w3id.org/agent-passport/binding/v1` (it was a placeholder); the context sits in the signed payload, so all 21 binding JWS and the example envelope changed bytes once more. Keys, status lists and the registration snapshot are byte-identical to 10-28 11:31 UTC.

**v1.1 (2026-10-28):** every signed binding now carries `type` `["VerifiableCredential", "FlexHoldBinding", "AgentBinding"]`, so all 19 binding JWS changed bytes (payload only; keys, status lists, registration, record and mandate vectors are byte-identical to 10-27). Two vectors added: `binding-mandate-issuer-mismatch` (rule 5 issuer clause) and `binding-v1-type` (a v1 binding without `AgentBinding` still verifies; its `inputs.type` pins the older array — re-sign with that type). `verify.mandate_issuer` is the issuer your mandate verifier established; it must equal the binding's `mandate.issuer`.

Test-only keys — seeds are published in `keys.json`; never use them for anything real.

Each `binding-*.json` holds: `inputs` (the binding fields, the signing key name, `jti`, `iat`, `nonce`, optional `audience`),
`now` (the verifier's clock), `verify` (which status list and registration snapshot to supply, optional mandate bytes /
request key / audience), and `expected` (`jws`, `ok`, `reason`). Spec: [`../spec/binding-v1.1.md`](../spec/binding-v1.1.md).

To verify from the vectors alone, in any language:
1. Derive each key: `seed = SHA-256(seed_string)` → Ed25519 private key (did:key = `z` + base58btc(0xed01 ‖ pubkey)); for `*_pkh` keys the same 32 bytes are the secp256k1 private scalar, did:pkh:eip155:1:<EIP-55 address>. Check against `keys.json`.
2. Re-sign: build the payload per the spec from `inputs` (`validFrom`/`nbf` etc. from the binding, `jti`/`iat`/`nonce`/`aud` from the inputs), header `{"alg":"EdDSA","typ":"vc+jwt","kid":"<did>#<multibase>"}` (wallet owners: `"alg":"EIP712"`, `kid` = `<did:pkh>#blockchainAccountId`, signature = 65-byte r‖s‖v over the EIP-712 digest of spec §1a with an RFC 6979 nonce), JSON without whitespace in insertion order — the compact JWS must equal `expected.jws` (skip for `forged: true`).
3. Verify `expected.jws` with the status list in `verify.status_list` (the URL in the binding resolves to that file's `jws`), the registration snapshot if named, the mandate bytes (`mandate_bytes_b64`), the request key and audience — the verdict must be `expected.ok` / `expected.reason`.

| Vector | Reason |
|---|---|
| binding-valid, binding-valid-all-checks, binding-erc8004-valid | ok |
| binding-expired / binding-not-yet-valid | expired / not_yet_valid |
| binding-revoked | revoked |
| binding-status-unavailable / binding-status-wrong-issuer | status_unavailable / status_invalid |
| binding-wrong-owner (forged: X signs claims naming O) | signature_invalid |
| binding-mandate-mismatch / binding-mandate-issuer-mismatch (v1.1) / binding-agent-mismatch | mandate_mismatch / mandate_mismatch / agent_mismatch |
| binding-v1-type (v1.1: type array without `AgentBinding`) | ok |
| binding-audience-mismatch / binding-audience-missing | audience_mismatch |
| binding-erc8004-owner-mismatch / binding-erc8004-registration-unavailable | owner_mismatch / registration_unavailable |
| binding-pkh-valid, binding-pkh-door-bound, binding-pkh-erc8004-valid (wallet owner, EIP-712) | ok |
| binding-pkh-wrong-owner (forged: wallet X signs claims naming wallet O) | signature_invalid |

Ruby: `flexhold vectors verify` (exit 0 when all reproduce and verify).

## Mandate vectors (2026-10-29) — the holder's collector verdict on the authority's mandate block

`fixture-flexyield-mandate-indicative-v0.1.json` is **FlexYield's** indicative mandate block, published here with FlexYield's permission
under CC BY 4.0 (attribution: FlexYield), byte-identical to the file FlexYield delivered on 2026-10-28 (`mandate_hash`
`sha256:9b27482c…4936`; the generator stays in FlexYield's repository). It is a `mandate-v1` credential as a compact JWS (EdDSA, `typ vc+jwt`,
issuer `did:web:flexyield.io`), signed with a **test-only** key whose seed is published inside the file (`key.test_only: true`); the values
are illustrative, the shape and the field names are the contract. `mandate-keys.json` is that key as a JWK Set with validity
(`kid, kty OKP, crv Ed25519, x, valid_from, retired_at, compromised_at`) — the shape a holder reads for an issuer's signing keys.

Each `mandate-*.json` holds `document` (`{jws}`), `now` (the verifier's clock), `jwk_directory` (`kid → {x, valid_from, retired_at,
compromised_at}`), optional `expected_agent` (the binding's agent key K) and `expected` (`ok`, `reason`). The `spec` field names the holder's
collector spec, which is not republished; the six checks it runs on a mandate block are these, in order — the first failing check is the reason:

| # | Check | Reason |
|---|---|---|
| 1 | key: `kid` is in the JWK Set, valid at `iat` (else `nbf`), not retired, not compromised; the Ed25519 signature verifies with that key | `key_unknown`, `key_compromised`, `signature_invalid` |
| 2 | issuer: `iss == issuer.id ==` the DID part of `kid` | `issuer_mismatch` |
| 3 | window: `nbf ≤ now < exp` | `not_yet_valid`, `expired` |
| 4 | subject: when the caller names the binding's agent key K, `credentialSubject.id == sub == K` | `agent_mismatch` |
| 5 | claim: `principal.claim.kind == "mandate"`, `asserts_ownership == false`, `asserts_identity == false` — a mandate mandates, never asserts ownership or identity | `claim_overreach` |
| 6 | receipts: `inside + outside + no_mandate == count`, `window.from < window.to`, every sample verdict ∈ {inside, outside, no_mandate} with integer `cost_cents` | `receipts_inconsistent` |

A document that is not a compact JWS, or whose signed subject carries a float where cents / integers / RFC 3339 are required, reads `malformed` before check 1.

**Two kinds of document:** `mandate-indicative-as-delivered` carries FlexYield's JWS unchanged and expects `ok`; every other vector is the delivered
payload re-signed with the published test seed and then mutated. Re-signing the delivered payload with that seed reproduces FlexYield's JWS
byte-exact (`mandate-valid` == the delivered JWS), so the two generators agree.

| Vector | Reason |
|---|---|
| mandate-indicative-as-delivered, mandate-valid, mandate-valid-agent-match (`expected_agent` = the subject) | ok |
| mandate-key-unknown / mandate-key-compromised / mandate-signature-invalid | key_unknown / key_compromised / signature_invalid |
| mandate-issuer-mismatch | issuer_mismatch |
| mandate-not-yet-valid / mandate-expired | not_yet_valid / expired |
| mandate-agent-mismatch (`expected_agent` ≠ the subject) | agent_mismatch |
| mandate-claim-overreach | claim_overreach |
| mandate-receipts-inconsistent | receipts_inconsistent |
| mandate-float-in-subject | malformed |

To verify in any language: split the JWS, look the `kid` up in `jwk_directory`, Ed25519-verify, run the six checks, compare the reason.

## Example envelope (H3, 2026-10-28) — `envelope-example-v1.0.json`

One consistent Agent Passport Envelope ([`../spec/envelope-v1.0.md`](../spec/envelope-v1.0.md)) built from the valid vectors: `mandate-valid` (FlexYield's indicative
mandate block as delivered, issuer `did:web:flexyield.io`, subject K), `record-indicative-valid` (FlexTrust's indicative full-tier record as
delivered, subject `erc8004:8453:999999001`) and a binding by owner O over that mandate for agent K carrying the record's ERC-8004 id
(`registration-snapshot` gained that registration → O). `now` = `presented_at` = 2026-10-27T10:30:00Z sits inside all three windows.
The file holds `inputs` (what went in; the binding is re-signed deterministically from them), `verify` (per-block sources: the mandate's JWK
set, the record's key directory + commitments, the binding's status list + registration snapshot + the mandate bytes rule) and `expected`
(`envelope` — the document, `envelope_hash`, per-block `ok`, `cross` empty, `advisory` `["bound_stale"]`: the record says `bound: false`
while a live binding is presented — ENVELOPE §3 #7 reports, never fails). For a door verifier: parse the envelope, verify each block by its
issuer's rule, run §3 #3–#8; everything should read ok plus that one advisory. The holder's `flexhold vectors verify` rebuilds the document byte-identical
and runs FlexHold's own three verifiers over the blocks.
