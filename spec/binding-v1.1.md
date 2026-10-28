# FlexHold binding — spec v1.1 (H1, 2026-10-26; v1.1 2026-10-28)

*v1.1 (additive, ADR-009): `AgentBinding` joins the `type` array (envelope role type, E1); rule 5 gains the issuer clause (envelope §3 #4). v1 bindings — type without `AgentBinding` — stay valid; the two pinned types are `VerifiableCredential` + `FlexHoldBinding`.*

*One page. The binding is the only credential FlexHold signs: "owner key O controls agent key K under mandate M until T,
revocable here." It proves control, not identity (identity = issuer credentials referenced in `identity_refs`). Source of the
fields: build instructions §4; the verification rule is the open rule any door may implement. Nothing here is a new standard —
it composes W3C VC 2.0, JOSE (RFC 7515/8037), Bitstring Status List (VC 2.0) and DIDs.*

## 1 · Encoding
One **W3C VC 2.0 credential**, secured as a **compact JWS** ("Securing VCs with JOSE"): header `{"alg":"EdDSA","typ":"vc+jwt","kid":<owner key id>}`, payload = the credential JSON plus the registered JWT claims, signature = Ed25519 over `base64url(header).base64url(payload)`. Two owner signature suites, same payload and same rule: **EdDSA / Ed25519** with owner `did:key` (`alg: "EdDSA"`), and for wallet owners **EIP-712** with owner `did:pkh:eip155:<chain>:<address>` (`alg: "EIP712"`, see §1a). The `alg` must match the owner's DID method; a mismatch is `signature_invalid`.

### 1a · EIP-712 profile for wallet owners (H1.1)
`alg: "EIP712"` is FlexHold's envelope profile, not a JOSE-registered algorithm: the third JWS part is the 65-byte `r‖s‖v` (v = 27/28, low-s) an Ethereum wallet produces over EIP-712 typed data. Domain `EIP712Domain(string name,string version,uint256 chainId)` = ("FlexHold Binding", "1", the chain id of the owner's `did:pkh`). Primary type `FlexHoldBinding(string jti,string owner,string agent,string mandateHash,string validUntil,string statusList,uint256 statusIndex,string audience,bytes32 payloadHash)` — the human-readable fields come from the payload (audience "" when absent); `payloadHash = keccak256(base64url(header) ‖ "." ‖ base64url(payload))` binds the exact JWS bytes. Verification = recover the address from the signature over that digest and compare it with the address in `issuer` (EIP-55). Nonces are RFC 6979-deterministic in the reference implementation, so the vectors reproduce; any wallet's signature verifies the same way.

## 2 · Fields (payload)
| Field | Content | §4 row |
|---|---|---|
| `@context` | `["https://www.w3.org/ns/credentials/v2", "https://w3id.org/agent-passport/binding/v1"]` — the second URL is the w3id.org permanent identifier (D37, published 2026-10-28 with envelope v1.0; context file in `1909-Works/agent-passport`) | — |
| `type` | `["VerifiableCredential", "FlexHoldBinding", "AgentBinding"]` (v1.1; `AgentBinding` = the envelope role type, so a door recognises the block by role — ENVELOPE E1); verifiers require `VerifiableCredential` + `FlexHoldBinding` and accept the v1 two-element array | — |
| `issuer` = `iss` | DID of the owner key O (pseudonymous) | `owner` |
| `validFrom` / `nbf`, `validUntil` / `exp` | RFC 3339 / epoch seconds; keep `validUntil` short, renewal is a new binding | `valid_until` |
| `credentialSubject.id` = `sub` | agent key id K (`did:key` or a Web Bot Auth key id) | `agent` |
| `credentialSubject.agent` | optional `web_bot_auth_key_id`; optional `erc8004: {chain_id, registry, agent_id}` — one binding per (O, K) | `agent` |
| `credentialSubject.mandate` | `{hash: "sha256:<hex>", issuer, version}` — hash over the mandate block **bytes exactly as presented**; FlexHold never restates the mandate | `mandate` |
| `credentialSubject.consent_ref` | opaque pointer into the owner's consent log, never the log | `consent_ref` |
| `credentialSubject.identity_refs` | credential ids of the owner's identity credentials (x401 → EUDI → KYC read-only); `[]` = pseudonymous owner | `identity_refs` |
| `credentialStatus` | `{type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex, statusListCredential: <URL>, issuer: <recovery key R DID>}` | `status` (+ `issuer`, ADR-004) |
| `id` = `jti`, `iat`, `nonce` | unique id, creation time, replay nonce | `proof` |
| `aud` (optional) | the door's `policy_url` or id when the binding is **door-bound**; absent = a **standing** binding accepted at any door | `proof` audience |

## 3 · Verification rule (every door, offline)
1. **Signature** — `iss` equals `issuer`; resolve the public key from `issuer` (`did:key` in v1); the JWS verifies. Else `signature_invalid` (`unsupported_owner_did` if the DID method is unknown).
2. **Time window** — `nbf ≤ now < exp`. Else `not_yet_valid` / `expired`.
3. **Audience** — if `aud` is present it must equal the verifier's own id; a door-bound binding never verifies elsewhere or without an audience (`audience_mismatch`). No `aud` = standing binding, accepted.
4. **Status** — fetch `statusListCredential`; it must be a `BitstringStatusListCredential` with purpose `revocation`, inside its own validity window, **signed by the key the binding names in `credentialStatus.issuer`** (never trusted from the list's own claim alone); bit `statusListIndex` must be 0. Else `status_unavailable` / `status_invalid` / `revoked`.
5. **Mandate** — when a mandate block is presented, `sha256(bytes)` equals `mandate.hash`, the bytes being the mandate credential's own bytes (for a compact JWS: the ASCII of `header.payload.signature`, nothing around it); **and (v1.1)** when the verifier has established the mandate block's issuer by that block's own rule, it equals `mandate.issuer` — the hash alone is not the rule. Else `mandate_mismatch`. (ENVELOPE §3 #4 is this rule, word for word.)
6. **Agent** — when a request is being verified, the key that signed the request (Web Bot Auth, RFC 9421) equals `credentialSubject.id`. Else `agent_mismatch`.
7. **Owner equality (ERC-8004)** — when `agent.erc8004` is present, the registration's owner (from any signed registration snapshot the verifier accepts; FlexTrust's nightly commitment root is one source, not the only one) must equal `issuer`. Else `owner_mismatch`; no snapshot = `registration_unavailable`. The on-chain control proof wins; a binding signed by another key *is* the hijack case.

Result = `ok` or exactly one reason; anything else is the door's policy, not the binding's business.

## 4 · Status list and revocation (ADR-004)
`statusListCredential` is a VC 2.0 **BitstringStatusListCredential** (≥ 131 072 bits, gzip, multibase base64url `u…`), secured as the same kind of JWS, issued by the **recovery key R** — a second owner-held key, kept offline, that **never signs a binding**. Revocation = R re-issues the list with the bit set; a thief who holds O cannot stop it, and a lost O is remedied with R: revoke, new binding under O′. Verifiers refetch after `validUntil` (the refresh window; 24 h default).

## 5 · Threats this answers (§6)
Hijack (claim without the owner): no binding, or a binding whose signature is not O's → refused. Stolen O: revoke with R. Replay at another door: `aud` + `nonce` + short `exp`; rule 6 ties the binding to the request key. Issuer impersonation of the status list: rule 4 pins the list to R.

## 6 · Test vectors
`vectors/` in the public repository `1909-Works/agent-passport` (the holder keeps the generating copy): test-only keys (seeds published; four Ed25519, two secp256k1), three status lists, a registration snapshot, 21 binding cases covering every reason above for both signature suites (v1.1: `binding-mandate-issuer-mismatch`; `binding-v1-type` = a v1 binding without `AgentBinding` still verifies; `binding-valid-all-checks` exercises the issuer clause). Run `flexhold vectors verify` or re-implement from `vectors/README.md`. Ed25519 and RFC 6979 ECDSA are deterministic, so every vector's JWS reproduces byte-for-byte from its inputs.
