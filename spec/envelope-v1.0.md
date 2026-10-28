# Agent Passport Envelope — spec v1.0 (RELEASE CANDIDATE — content agreed by FlexYield, FlexTrust and FlexHold; V2-PLAN #33, F8, DISTRIBUTION 7b)

**Status:** v1.0 RELEASE CANDIDATE, 2026-10-28 — the v0.3 content (agreement candidate 12:22 CET) confirmed by FlexHold (11:44 UTC), FlexTrust
(14:10 UTC) and FlexYield (15:35 CET, Christian's read: agreed). **v1.0 = v0.3 content + the two w3id.org context identifiers (D37) + FlexTrust's
§3 #5 wording correction; no other change.** It becomes **FINAL** — with no byte change to this text or to the example — once two independent
readers have run `envelope-example-v1.0.json`: FlexTrust's doors (C3.1) and FlexYield's door verifier. Written by the FlexYield session (DISTRIBUTION
v1.2 row 7b); **issuer-neutral by agreement: no FlexYield-only field.** Maintained by FlexHold from v1.0 on (HOLDER §5 "Shared"); changes over the
three-way bridge in numbered rounds; siblings mirror the published version. **Published:** `https://github.com/1909-Works/agent-passport`
(spec, JSON-LD contexts, test vectors) under **CC BY 4.0**; identifiers `https://w3id.org/agent-passport/envelope/v1` (this context) and
`https://w3id.org/agent-passport/binding/v1` (the binding context). Earlier text: `ENVELOPE-SPEC-v0.3.md` (bytes as delivered, kept).

## 0 · One paragraph

An agent walks up to a door with ONE document that carries up to three signed blocks from three different issuers, and a door
verifies any block alone or all together: the **mandate** (what the agent may do — its platform's authority, e.g. FlexYield's
mandate block), the **record** (what it has done and how it is scored — a reputation issuer's attestation, e.g. FlexTrust's
passport), and the **binding** (that its owner's key controls the agent key under exactly that mandate — the holder's control
assertion, e.g. FlexHold's binding). Identity of the owner is never asserted by the envelope; it is referenced through the binding's
`identity_refs` (issuer credentials: x401 → EUDI wallet → KYC read-only). Nothing here is a new standard: the envelope is a **W3C VC 2.0
Verifiable Presentation** whose credentials may each be secured their own way (embedded Data Integrity proof, or an enveloped compact
JWS), presented by the agent key that also signs the request (Web Bot Auth, RFC 9421).

## 1 · Shape

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/agent-passport/envelope/v1"],
  "type": ["VerifiablePresentation", "AgentPassportEnvelope"],
  "version": "envelope-v1.0",
  "holder": "<DID of the agent key K — the presenter>",
  "roles": { "mandate": 0, "record": 1, "binding": 2, "identity": [] },
  "verifiableCredential": [
    { "@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["EnvelopedVerifiableCredential"], "id": "data:application/vc+jwt,<mandate compact JWS>" },
    { "...": "the record credential as issued (JSON-LD with its embedded proof / statement), or enveloped if its issuer secures it as a JWS" },
    { "@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["EnvelopedVerifiableCredential"], "id": "data:application/vc+jwt,<binding compact JWS>" }
  ],
  "policy_url": "<the door's published gate policy, optional — reserved, vocabulary = the reputation issuer's (FlexTrust C3)>",
  "anchors": [],
  "presented_at": "<RFC 3339>", "aud": "<door id or policy_url when door-bound>", "nonce": "<replay nonce>",
  "proof": "<optional — see §3>"
}
```

| Field | Rule |
|---|---|
| `holder` | the agent key K (`did:key`, or a Web Bot Auth key id resolvable through `Signature-Agent`); MUST equal the key that signed the HTTP request when the envelope travels on one |
| `roles` | indexes into `verifiableCredential` by **role**, not by issuer: `mandate` · `record` · `binding` · `identity` (array, zero or more owner-identity credentials referenced by the binding). A role may be absent (`null` / `[]`); a door verifies what is there and its policy decides what it requires |
| `verifiableCredential[]` | each block **as issued, bytes unchanged**: a JWS-secured block travels as `EnvelopedVerifiableCredential` with a `data:application/vc+jwt,` URL; a JSON-LD block with an embedded proof travels inline. The envelope never restates, re-signs or reorders a block's content |
| `version` | `envelope-v1.0`; every block carries its issuer's own version inside (`mandate-v1`, `passport-v1`, binding v1) |
| `policy_url` | reserved; the door's gate policy (what it requires: score floor, `bound`, liveness, mandate caps) — **the vocabulary is the one the door publishes at `policy_url`; FlexTrust C3 is the first**; a FlexTrust record already carries what it refers to: `score` (public view rounded / exact in full tier), `bound`, `operator_attested_by`, `incidents[]` with `incident_policy`, and `liveness` `{rung 0–6, name, alive, protocol, probed_at, ladder}` (`/spec/liveness`), so a door can evaluate `alive` / `min_liveness` from the record block today; the envelope only carries the pointer |
| `anchors` | reserved for later on-chain anchoring of block digests (V2-PLAN Q1–Q4) so a verifier needs no trust in any issuer's availability; empty in v0.1 |
| `presented_at` · `aud` · `nonce` | replay protection for offline presentations; on an HTTP request the RFC 9421 signature's `created` / `nonce` and the request target take this role and these fields MAY be omitted |

## 2 · The three block types (roles) — what each one is, who signs it, how it is verified

| Role | Asserts | Issued and signed by | Shape in v0.1 (the known issuers) | Verified by |
|---|---|---|---|---|
| **mandate** | authority: cap, allowlist, action types, expiry, covered keys, receipts with per-receipt verdict — *what it may do*; never ownership or identity | the agent's platform (authority relation) | FlexYield `mandate-v1`: VC 2.0 as compact JWS EdDSA (indicative block delivered over the three-way review); other platforms: any VC 2.0 credential of type `AgentMandate` + their own type | the issuer's published key (`did:web` document / `.well-known`); rule: signature · window · `credentialSubject.id` = K |
| **record** | behaviour and standing: score, confidence, incidents (with mandate verdict), control continuity, `bound`, `operator_attested_by`, `liveness` — *can it be trusted*; never authority, never legal identity | a reputation issuer | FlexTrust `passport-v1`: JSON-LD VC, `type` `["VerifiableCredential","FlexTrustAgentPassport"]`, `@context` `credentials/v2` + `https://flextrust.io/spec/passport/v1`, `version` `passport-v1`; **the full tier only** carries `statement` (EIP-712 `PassportStatement` over the subject digest) + `proof` (`EthereumEip712Signature2021`, `signedFields: ["statement.message"]`) — a public-tier passport has no statement and fails verification by design, so **the record role always carries the full-tier document** (one unit or $0.005 via x402, fetched by the holder or the agent once a day; `validUntil` 24 h); others: type `AgentRecord` + own type | the issuer's rule — FlexTrust: six offline checks (window, key, digest, Merkle, root, freshness) **from the file plus the issuer's key directory alone** (`statement.proof.leaf_count` + `/.well-known/flextrust`); `/commitments.json` is the optional live cross-check for check 5; a door needs no call to the issuer |
| **binding** | control: owner key O controls agent key K under mandate M (by hash) until T, revocable — *is it really the owner's agent*; never identity | the owner, via the holder | FlexHold binding v1: VC 2.0 as compact JWS (EdDSA `did:key` or EIP-712 `did:pkh`), status list signed by recovery key R | the holder's seven-step rule (signature · window · audience · status · mandate hash · agent · owner equality for ERC-8004) |
| **identity** (0..n) | who the owner is, to the degree an issuer attests | identity issuers (x401, EUDI wallet, KYC read-only) | as issued; referenced from the binding's `identity_refs` by credential id | each issuer's rule; absent = pseudonymous owner |

**Issuer neutrality:** a door recognises a block by its role type (`AgentMandate` / `AgentRecord` / `AgentBinding` / `OwnerIdentity` in the
envelope context) and verifies it against **that block's issuer** key. FlexYield, FlexTrust and FlexHold are the first issuers, not the only
ones; nothing in §1–§3 names a company.

## 3 · Verification — the open-source verifier's rule (doors, offline where possible)

| # | Check | Reason on failure |
|---|---|---|
| 1 | envelope shape: `type`, `version` known, `roles` point at existing entries, every enveloped block decodes | `envelope_invalid` |
| 2 | **each present block verifies by its issuer's own rule** (§2, last column); the verifier reports a verdict **per block**, never one combined verdict | `mandate_invalid:<issuer reason>` · `record_invalid:<reason>` · `binding_invalid:<reason>` · `identity_invalid:<reason>` |
| 3 | **agent**: `holder` = mandate `credentialSubject.id` = binding `credentialSubject.id` = the key that signed the request (when there is one) | `agent_mismatch` |
| 4 | **mandate ↔ binding**: `sha256` over the mandate credential's **own bytes** — for an enveloped block the ASCII bytes of the compact JWS `header.payload.signature`, nothing around it (not the `data:` URL, not the envelope entry, no quotes, no newline) — = binding `credentialSubject.mandate.hash` (one rule with the holder's binding rule 5 and the collector's `mandate_hash`, confirmed byte for byte 10-28); **a block that another block hashes MUST travel enveloped** (`data:application/vc+jwt,…` or `data:application/vc+ld+json;base64,<bytes as issued>`), never inline, because inline JSON has no stable bytes after re-serialisation. Second clause: binding `mandate.issuer` = mandate issuer (the holder adds it to its rule 5 in binding v1.1; until then it is a cross-check this verifier runs) | `mandate_mismatch` |
| 5 | **record ↔ agent** — **primary:** the record's `credentialSubject.id` (`erc8004:<chainId>:<tokenId>` or `eoa:<address>`) equals the binding's `agent.erc8004` / owner key; **secondary, when the record lists it:** K among `credentialSubject.control_continuity.anchors[]` (`{kind, identifier, verified_at, status}`; kinds today `http_key` = Web Bot Auth key, `evm_key`). The id path always works in v0.x; the K path applies when the issuer has verified that key as an anchor (FlexTrust: a presented binding is evaluated per call at the gate doors — C3 — and never written; the passport's `bound` and the anchor flip come from FlexTrust's status-list reader once FlexHold's status-list URL is live, C1.x) | `anchor_mismatch` |
| 6 | **owner equality (ERC-8004)**: inherited from the binding rule — the binding issuer must equal the registration's owner per any signed snapshot the verifier accepts. A record's signed statement is one such snapshot **at `asOfBlock` of the commitment day** (`ownerAddress`, `asOfBlock` inside the signed message; daily, not live, lag up to ~24 h + the indexer's); a door holding a binding newer than `asOfBlock` prefers a chain read or a newer snapshot. The binding rule itself stays the holder's | `owner_mismatch` |
| 7 | **`bound` staleness**: a presented binding that verifies `ok` while the record says `bound: false` is **reported**, not failed — the record's `bound` is the issuer's observation at `validFrom`, and a live verifying binding is stronger evidence, so this is lag; the door's policy decides. A record saying `bound: true` with no binding presented is **nothing** — that is the presenter's minimum disclosure (§5), expected, not a finding. The same rule applies to `operator_attested_by` once live | `bound_stale` (advisory) |
| 8 | replay: `aud` (when present) = this door; `nonce` unseen; `presented_at` within the door's window — or the request signature's equivalents. **One audience:** a door-bound binding's own `aud` is checked by the binding rule against the **same** door id | `audience_mismatch` · `replay` · `stale` |

Result = `{ envelope: ok | reason, blocks: { mandate: ok | reason, record: …, binding: …, identity: [...] }, cross: [reasons] }`. **What a door
requires** (which blocks, which score, `bound` yes/no, liveness) is the door's policy at `policy_url`, never the envelope's business.
FlexYield's own doors are door #1 and publish their policy there; `check_before_serving` (FlexTrust C3) runs on the record block.

## 4 · Transport (open for review — two proposals)

| Where | How | Note |
|---|---|---|
| HTTP request (RPC, MCP, any API) | header `Agent-Passport: <https URL of the envelope>` (**default**) or `Agent-Passport: data:application/agent-passport+json;base64,<…>` for envelopes **≤ 32 KB** (a full-tier record alone is ≈ 11 KB today and grows with its history); the request itself signed per RFC 9421 by K (`Signature-Agent` → key directory) | the URL form keeps headers small and lets the holder serve a fresh envelope; the data form is self-contained |
| MCP | `_meta.agentPassport` on `initialize` / per call, same two forms, same cap; **data form is the default here** (a stdio MCP door has no second round trip; local-first); the URL form stays https-only and the door fetches with the request's own K signature in hand | one shape for both doors; FlexTrust C3 `check_before_serving` reads the record block in both transports |
| offline / file | the JSON document itself, with §1 `proof` = a JWS by K over the canonical envelope (keys sorted, no whitespace) carrying `aud` + `nonce` | when there is no request signature to lean on |

## 5 · Privacy and disclosure

Minimum disclosure is the presenter's job: a door that needs only the binding gets only the binding; the record's public tier
carries no exact score; identity credentials are referenced, not re-issued. Field-level disclosure (SD-JWT) for the mandate and
record is v1.x (HOLDER §6). No block in the envelope carries a legal name; the owner is a wallet or a key.

## 6 · Open items for the review (our view; please add, strike, replace — "ENVELOPE §n: old → new, why")

| # | Item | Our proposal |
|---|---|---|
| E1 | role type names | **agreed (both, 10-28):** `AgentMandate` · `AgentRecord` · `AgentBinding` · `OwnerIdentity`; FlexTrust adds `AgentRecord` (passport-v1.1) and FlexHold adds `AgentBinding` (binding v1.1) to their `type` arrays, non-breaking, in the same step as v1.0 publication |
| E2 | transport default | **agreed (both):** HTTP header `Agent-Passport`, URL form default, data form ≤ 32 KB; **MCP `_meta`: data form default** (FlexHold's point, stdio doors) — FlexTrust confirmed 10-28 14:10 UTC |
| E3 | `bound` inconsistency | **resolved (FlexTrust 10-28):** `bound_stale` advisory, one direction only (§3 #7) |
| E4 | anchor matching (§3 #5) | **resolved (FlexTrust 10-28):** primary = `credentialSubject.id` equality, secondary = `control_continuity.anchors[]` when listed |
| E5 | who hosts the envelope URL | **agreed (both):** the holder by default as the target; **FlexHold v1 presents the data / file form only** (local gem + CLI + stdio MCP; a hosted envelope URL is v1.x under the zero-cost gate); an agent without a holder presents mandate + **full-tier** record (two blocks, interim — DISTRIBUTION 7d) |
| E6 | context URL and publication | **closed (D37, Christian 2026-10-28):** W3C-community permanent identifiers `https://w3id.org/agent-passport/envelope/v1` and `https://w3id.org/agent-passport/binding/v1`, zero cost, issuer-neutral; each redirects (302) to the context file in the public spec repo `1909-Works/agent-passport` (GitHub Pages); FlexHold maintains the published version (HOLDER §5) |
| E7 | rule-5 byte parity | **confirmed one rule (FlexHold 10-28):** §3 #4 = binding rule 5 = collector `mandate_hash` = sha256 over the ASCII bytes of the compact JWS; `sha256:9b27482c…4936` is that value for the regenerated indicative fixture |

**Not in this draft:** scoring vocabulary (FlexTrust's), gate-policy vocabulary (FlexTrust C3), the status-list format (FlexHold's), anchoring (Q1–Q4).

## 7 · Review log

| Round | From | Date | Result |
|---|---|---|---|
| 1 | FlexTrust | 2026-10-28 09:40 UTC | shape, role indexing, per-block verdicts agreed; nine points — all applied in v0.2 (§1 `policy_url`, §2 record row ×2, §3 #5/#6/#7, §4 cap, E1, E5/E6) |
| 1 | FlexHold | 2026-10-28 11:03 + 11:19 UTC | E1 ✔ E5 ✔ E7 ✔; E2 MCP data-form default, E6 pattern + host at v1.0, §3 #4 own-bytes wording + enveloped rule, §3 #8 one audience, `policy_url` vocabulary neutral — all applied in v0.3; issuer-neutral claim checked and holds |
| 2 | FlexTrust | 2026-10-28 14:10 UTC | v0.3 confirmed against the file; E2 MCP data-form default confirmed; one wording correction for §3 #5 (applied here) |
| 2 | FlexHold | 2026-10-28 11:44 UTC | v0.3 confirmed as applied; D37 taken as the E6 answer |
| 2 | FlexYield | 2026-10-28 15:35 CET | Christian's read: agreed; FlexYield's side final |
| — | publication | 2026-10-28 | **v1.0 RELEASE CANDIDATE** = v0.3 content + the two w3id.org identifiers + the §3 #5 correction; `version` string `envelope-v1.0`; FlexHold publishes (`1909-Works/agent-passport`, CC BY 4.0) and maintains; siblings mirror; passport-v1.1 (`AgentRecord`) / binding v1.1 (`AgentBinding`, already shipped) type additions same step. **FINAL** once FlexTrust C3.1 and FlexYield's verifier have each read `envelope-example-v1.0.json` — label only, no byte change |
