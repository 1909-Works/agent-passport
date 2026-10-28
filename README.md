# Agent Passport

An open, issuer-neutral format for an AI agent to present who stands behind it: **one W3C Verifiable Presentation that
carries up to three signed blocks from three independent issuers**, each as issued, bytes unchanged.

| Role | What the block says | Who issues it |
|---|---|---|
| `mandate` | what the agent may do, on whose account, with which limits | the authority that mandated the agent |
| `record` | the agent's track record (score, incidents, liveness, `bound`) | a reputation issuer |
| `binding` | "owner key O controls agent key K under mandate M until T, revocable here" — self-signed by the owner | the owner, inside a holder (wallet) |
| `identity` | zero or more owner-identity credentials the binding refers to | third-party identity issuers |

A door (a service the agent calls) verifies each block with that issuer's own rule, then runs three cross-checks: agent
equality across blocks, mandate hash and issuer against the binding, and the record's anchor against the agent key. Roles
are indexed by role, never by issuer, so any issuer that follows the block schema fits.

## Permanent identifiers

| Identifier | Resolves to | Status |
|---|---|---|
| `https://w3id.org/agent-passport/envelope/v1` | [`contexts/envelope-v1.jsonld`](contexts/envelope-v1.jsonld) — the envelope's JSON-LD context | registered at w3id.org (pull request pending) |
| `https://w3id.org/agent-passport/binding/v1` | [`contexts/binding-v1.jsonld`](contexts/binding-v1.jsonld) — the binding block's JSON-LD context | registered at w3id.org (pull request pending) |

The identifiers are W3C-community permanent identifiers (w3id.org). They redirect to the files in this repository; if the
host moves, the identifiers stay.

## Specifications

| Document | Version | Status |
|---|---|---|
| [`spec/envelope-v1.0.md`](spec/envelope-v1.0.md) — the Agent Passport Envelope | v1.0 | **release candidate**: content agreed by its three authoring projects on 2026-10-28; becomes final, with no change to the text or the example, once two independent door implementations have read `vectors/envelope-example-v1.0.json` |
| [`spec/binding-v1.1.md`](spec/binding-v1.1.md) — the binding block | v1.1 | stable; v1.1 is additive over v1 (role type `AgentBinding`, rule 5 issuer clause) |

The envelope composes existing standards: W3C Verifiable Credentials 2.0 (presentation, `EnvelopedVerifiableCredential`),
compact JWS (`vc+jwt`) for JWS-secured blocks, DIDs for keys, Bitstring Status List for revocation, and RFC 9421 HTTP
message signatures when the envelope travels on a request. The mandate and record block schemas belong to their issuers;
this repository defines the envelope and the binding.

## Test vectors

`vectors/` holds the binding and envelope test vectors used by the implementations that agreed this format: 21 binding
cases (valid, expired, revoked, wrong owner, mandate mismatch, …), three status lists, a registration snapshot, and one
consistent example envelope. Every key in the vectors is **test-only**, published with its seed, and marked as such; each
file's `verify` block names the key and the expected verdict. See [`vectors/README.md`](vectors/README.md).

## Who maintains this

The format was written and agreed over an open review between three projects — an authority and meter (mandate), a
reputation issuer (record), and a holder (binding) — and is maintained by the holder project. Changes go through numbered
review rounds between the three; the published version here is the agreed one.

Contact: Christian Schlager · GitHub [`CSdev1909`](https://github.com/CSdev1909) · christian.schlager@me.com

## Licence

The specifications, contexts and vectors in this repository are published under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE).
