# Elmnet P2P Protocol Specification (Draft v0.2)

**Status:** Draft

**Scope:** This document defines the wire protocol, identity model, security requirements, and trust/reputation semantics for the Elmnet peer‑to‑peer network. It also describes how nodes operate in **local swarm mode** and **live internet mode**. The goal is to provide a minimal, implementable specification that can be extended by future versions without breaking interoperability.

---

## 1. Goals & Non‑Goals

### Goals
- Provide a **Bitcoin‑style P2P protocol** that allows agents to discover peers, exchange queries, and build trust.
- Support **two operating modes**: local swarm (test) and live internet (production).
- Define **identity**, **message integrity**, **trust evidence**, and **reputation exchange**.
- Specify a **versioned message format** with forward compatibility.

### Non‑Goals
- This spec does not define the internal reasoning model of an agent.
- This spec does not mandate a specific database, ML model, or orchestration framework.
- This spec does not define payment rails (may be specified in a future extension).

---

## 2. Terminology

- **Node**: A running Elmnet agent instance.
- **Peer**: A node with an established P2P connection.
- **Identity Key**: A long‑lived asymmetric keypair used to sign messages.
- **Node ID**: A stable identifier derived from the public key.
- **Envelope**: Signed message wrapper used in transport.
- **Trust Evidence**: Signed statements about behavior or data quality.

---

## 3. Modes of Operation

### 3.1 Local Swarm Mode (Test)
- Intended for **local development** and private clusters (e.g., docker‑compose).
- **Bootstrap peers** are explicitly configured.
- Transport encryption **MAY** be disabled for ease of debugging.
- Trust is **non‑adversarial**, but integrity checks are still recommended.

### 3.2 Live Internet Mode (Production)
- **Transport encryption REQUIRED** (e.g., TLS or Noise).
- Nodes **MUST** verify message signatures and identity.
- Nodes **MUST** rate‑limit and enforce message size limits.
- Peer discovery uses **seed nodes + peer exchange** and MAY use DHT.

---

## 4. Identity & Keys

### 4.1 Key Types
- Nodes **MUST** generate and persist a **long‑lived asymmetric keypair**.
- Recommended: **Ed25519** or **secp256k1**.

### 4.2 Node ID
- Node ID is derived as:

```
node_id = base58check(sha256(pubkey))
```

- Nodes **MUST** include their Node ID in all signed envelopes.

### 4.3 Key Rotation
- Nodes **MAY** rotate keys.
- If rotating, nodes **SHOULD** publish a signed `identity_update` linking old → new key.

---

## 5. Transport

### 5.1 Framing
- Messages are sent as **newline‑delimited JSON** (NDJSON) for the POC.
- A future version MAY use **CBOR** or **protobuf** for canonical encoding.

### 5.2 Encryption
- **Local swarm**: encryption optional.
- **Live mode**: encryption **REQUIRED**.

### 5.3 Message Size Limits
- Nodes **MUST** enforce a maximum message size (recommended default: **256 KB**).
- Oversized messages **MUST** be rejected with `error`.

---

## 6. Envelope & Signature

All messages **MUST** be wrapped in a signed envelope in live mode. In local swarm mode, envelopes MAY be unsigned, but SHOULD still include the envelope fields for compatibility.

### 6.1 Envelope Schema

```
{
  "envelope": {
    "protocol": "elmnet/0.2",
    "message_id": "uuid-or-hash",
    "timestamp": "RFC3339",
    "node_id": "base58check-id",
    "public_key": "base64",
    "signature": "base64"
  },
  "message": { ... }
}
```

### 6.2 Signing
- `signature` is computed over the **canonical serialization** of `message` + envelope fields (excluding `signature`).
- Nodes **MUST** verify signatures in live mode.

---

## 7. Handshake & Connection Lifecycle

### 7.1 Version Handshake
1. `version`
2. `verack`

**version** MUST include:
- `protocol` (string)
- `node_id`
- `public_key`
- `capabilities` (list)
- `services` (list)

**verack** acknowledges successful validation.

### 7.2 Ping/Pong
- Nodes SHOULD periodically send `ping`.
- Peers MUST respond with `pong`.

---

## 8. Core Message Types

### 8.1 `query`
```
{
  "type": "query",
  "id": "uuid",
  "origin": "node_id",
  "topic": "optional string",
  "payload": "query text",
  "ttl": 3
}
```
- Nodes forward queries when TTL > 0.

### 8.2 `response`
```
{
  "type": "response",
  "id": "uuid",
  "from": "node_id",
  "response": { ... },
  "confidence": 0.0-1.0,
  "evidence": [ ... ]
}
```

### 8.3 `peer_list`
```
{
  "type": "peer_list",
  "peers": ["host:port", ...]
}
```

### 8.4 `peer_announce`
```
{
  "type": "peer_announce",
  "address": "host:port",
  "node_id": "node_id"
}
```

### 8.5 `reputation_update`
```
{
  "type": "reputation_update",
  "subject": "node_id",
  "score": -1.0..1.0,
  "reason": "string",
  "evidence": [ ... ]
}
```

### 8.6 `error`
```
{
  "type": "error",
  "code": "string",
  "message": "string"
}
```

---

## 9. Peer Discovery

- Nodes maintain a **peer table** and exchange `peer_list` periodically.
- Nodes SHOULD **deduplicate** peers and reject invalid entries.
- Nodes MAY use a **DHT** for distributed discovery (optional extension).

---

## 10. Trust, Reputation, and Memory

### 10.1 Trust Evidence
- Evidence MUST be signed by the node asserting it.
- Evidence can include:
  - Response correctness
  - Uptime/latency
  - Consistency of claims

### 10.2 Reputation Model
- Local trust is **subjective** and node‑specific.
- Nodes SHOULD store:
  - Peer responses
  - Confidence scores
  - Evidence hashes
- Reputation MAY decay over time.

---

## 11. Security Requirements

### 11.1 Replay Protection
- Messages **MUST** include `timestamp` and `message_id`.
- Nodes SHOULD reject messages older than a configurable window.

### 11.2 Rate Limiting
- Nodes MUST rate‑limit inbound messages per peer.

### 11.3 Abuse Prevention
- Nodes MAY ban peers for repeated invalid signatures or spam.

---

## 12. Compatibility & Versioning

- The `protocol` field in envelopes and `version` messages dictates compatibility.
- Nodes MAY support multiple versions but MUST reject unknown major versions.

---

## 13. Implementation Notes (POC Guidance)

- Current POC uses JSON and plain TCP sockets in `poc-1/app/network.py`.
- This spec provides a migration path: start by **adding envelopes + signatures**, then **add trust storage**, then **harden transport**.

---

## 14. Appendix: Example Message Flow

```
Node A connects → version → verack
Node A broadcasts query → peers forward (TTL)
Peers respond → A aggregates responses
Optional reputation_update emitted by A
```

---

**End of Draft**
