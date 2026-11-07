# Agent Passport test vectors — binding v1.1, envelope v1.0, mandate and record collector (2026-11-07)

Published subset of the holder implementation's vector set: the 21 binding cases, the three status lists, the registration snapshot, the test keys, the example envelope and — since 2026-10-29, with the authority's permission — the authority's indicative mandate block and the holder's 13 mandate-collector vectors over it, and — since 2026-11-07, with the reputation issuer's permission — the reputation issuer's indicative record block and the holder's 13 record-collector vectors over it. With that, every block of the example envelope has its issuer's fixture and the holder's verdict vectors published here.

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

## Record vectors (2026-11-07) — the holder's collector verdict on the reputation issuer's record block

`fixture-flextrust-passport-indicative-v0.1.json` is **FlexTrust's** indicative record block (`passport-v1`, full tier), published here with
FlexTrust's permission under CC BY 4.0 (attribution: FlexTrust), byte-identical to the file FlexTrust delivered over the bridge on 2026-10-26
(the version the holder's vectors verify against; FlexTrust's later fixture revisions add `leaf_count`, `test_keys`, a filled `liveness` slot and
`kind` on incident items — same shape, not needed for these verdicts). It is signed with the ephemeral **`indicative-test-key`** — never a
FlexTrust attestation key; the address the key directory pins (`0xE5B5595C2f11306CD43D725CE8b98707a139BbBd`) is that test key's. Values are
illustrative (a synthetic agent, `erc8004:8453:999999001`); the shape, the field names and the six collector checks are the contract. The
generator and the real attestation keys stay in FlexTrust's repository.

Each `record-*.json` holds `block` (the fixture, possibly mutated), `now` (the verifier's clock), `key_directory` (`key_id → {address,
valid_from, retired_at, compromised_at}`), `commitments` (`day → {merkle_root, leaf_count, methodology_version}`; `leaf_count` 10657 = the
synthetic agent is the last leaf) and `expected` (`ok`, `reason`). Nothing is re-signed — the holder holds no FlexTrust key — so a runner
checks verdicts only. The `spec` field names the holder's collector spec, which is not republished; the six checks it runs, in order — the first
failing check is the reason:

| # | Check | Passes when | Reason |
|---|---|---|---|
| 1 | window | `statement.message.issuedAt ≤ now < validUntil` (epoch seconds) | `not_yet_valid`, `expired` |
| 2 | key | the address recovered from the EIP-712 `PassportStatement` signature equals the key directory's address for `keyId`, and that key was valid (`valid_from ≤ issuedAt`), not retired and not compromised at `issuedAt` | `key_unknown`, `key_compromised`, `signature_invalid` |
| 3 | digest | sha256 of the canonical `credentialSubject` equals `documentDigest` | `digest_mismatch` |
| 4 | merkle | the proof names the signed `leafPosition` and `commitmentDay`, and the leaf folds to `commitmentRoot` (hex-concatenation pairing) | `merkle_invalid` |
| 5 | root | the commitments source has the day, its `merkle_root` equals `commitmentRoot`, and the `CommitmentRoot` signature recovers to a directory key valid at `signed_at` | `root_unavailable`, `root_mismatch`, `root_signature_invalid` |
| 6 | freshness | `committed_score.value == statement.message.score` | `score_mismatch` |

Before the checks: a document that does not parse as `passport-v1` is `malformed`; a public-tier document (no `statement`) is `unsigned` — shown, proving nothing.

| Vector | Reason |
|---|---|
| record-indicative-valid | ok |
| record-not-yet-valid / record-expired | not_yet_valid / expired |
| record-key-unknown / record-key-compromised / record-signature-invalid | key_unknown / key_compromised / signature_invalid |
| record-digest-mismatch | digest_mismatch |
| record-merkle-invalid | merkle_invalid |
| record-root-unavailable / record-root-mismatch / record-root-signature-invalid | root_unavailable / root_mismatch / root_signature_invalid |
| record-score-mismatch | score_mismatch |
| record-public-tier-unsigned | unsigned |

To verify in any language: parse `block`, run the six checks with the two sources given, compare the reason.

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
