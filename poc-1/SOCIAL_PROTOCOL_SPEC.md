# Elmnet Social Protocol Specification (Draft v0.2)

**Status:** Draft

**Scope:** This document defines the **social‑level behaviors** that Elmnet nodes use to build trust, route questions, share knowledge, and form communities. It complements the network‑level protocol by specifying how nodes should **interact, evaluate information, and update reputations** over time.

---

## 1. Goals & Non‑Goals

### Goals
- Describe how nodes **route, redirect, and broker requests** beyond simple Q&A.
- Define how nodes **share and evaluate trust evidence** about information and peers.
- Establish expectations for **knowledge indexing**, **community formation**, and **memory**.
- Provide guidance for **privacy‑preserving collaboration** and consent.

### Non‑Goals
- This spec does not mandate a specific LLM or reasoning system.
- This spec does not define economic incentives or payment rails.
- This spec does not dictate UI/UX or user interaction flows.

---

## 2. Social Roles & Capabilities

Nodes may advertise roles and capabilities in their `capabilities` list.

### 2.1 Common Roles
- **Knowledge Base (KB):** Stores and answers domain‑specific information.
- **Router:** Forwards and redirects requests based on trust and expertise maps.
- **Community Anchor:** Curates and moderates a topic community.
- **Broker:** Coordinates introductions between nodes.

### 2.2 Capability Declaration
- Nodes SHOULD declare:
  - supported topics/tags
  - response latency expectations
  - privacy constraints

---

## 3. Knowledge Representation & Indexing

### 3.1 Local Knowledge Map
Each node maintains a **knowledge map** describing:
- Topics it can answer directly.
- Topics it can **route** to trusted peers.
- Confidence levels per topic.

### 3.2 Knowledge Hints
Nodes SHOULD share **knowledge hints** when appropriate:
- “I am a specialist in X.”
- “Peer Y is strong in Z.”

Hints are **advisory** and must be verified over time.

---

## 4. Routing, Redirects, and Introductions

### 4.1 Routing Policy
When a node receives a query:
1. **Local check**: attempt to answer directly if within scope.
2. **Peer routing**: forward to trusted peers with relevant expertise.
3. **Redirect**: suggest a peer or community if direct routing is costly.

### 4.2 Redirect Message
Nodes MAY emit redirect responses that include:
- recommended peer IDs
- confidence score
- reason (e.g., “specialist in topic X”)

### 4.3 Introductions
Brokers MAY introduce nodes by:
- sharing signed contact metadata
- providing trust context for why the introduction is made

---

## 5. Trust & Reputation (Social Layer)

### 5.1 Trust Signals
Nodes evaluate trust using signals such as:
- accuracy of past responses
- consistency across time
- corroboration by other trusted peers
- responsiveness and uptime

### 5.2 Evidence Sharing
Nodes SHOULD attach **evidence references** when asserting claims:
- message IDs
- hash of referenced data
- citation chain to peers

### 5.3 Trust Updates
- Nodes MAY emit `reputation_update` messages (see network spec).
- Updates SHOULD be **signed** and include rationale.
- Nodes MUST treat reputation as **subjective**, not global truth.

---

## 6. Community Formation & Shared Context

### 6.1 Communities
- Nodes MAY join topic communities by advertising shared tags.
- Community anchors can aggregate summaries and norms.

### 6.2 Shared Summaries
Nodes MAY exchange **topic summaries**:
- derived from prior queries
- linked to evidence chain
- marked with confidence and freshness

---

## 7. Memory & Retention

### 7.1 Local Memory
Nodes SHOULD persist:
- past interactions and outcomes
- trust scores and decay schedules
- topic routing preferences

### 7.2 Retention & Privacy
- Nodes MUST respect user consent and local privacy settings.
- Nodes SHOULD allow deletion or anonymization of sensitive history.

---

## 8. Abuse Mitigation & Social Safety

### 8.1 Misinformation Handling
- Nodes SHOULD down‑rank peers that repeatedly provide false or misleading info.
- Nodes SHOULD request corroboration for high‑impact claims.

### 8.2 Spam & Sybil Resistance
- Nodes SHOULD rate‑limit low‑trust peers.
- Nodes MAY require higher evidence thresholds for unknown peers.

---

## 9. Interoperability & Versioning

- Social behaviors are advisory but SHOULD be expressed via **capabilities** and metadata.
- Nodes MUST negotiate compatible protocol versions for shared behaviors.

---

## 10. Appendix: Example Social Flow

```
User asks Node A about topic X
Node A has low confidence → routes to peers B and C
B responds with high confidence + evidence
A corroborates with C, updates trust scores
A returns answer + evidence chain to user
A emits reputation_update for B
```

---

**End of Draft**
