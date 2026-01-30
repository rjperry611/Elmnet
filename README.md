# Elmnet Protocol: Decentralized Network of Personal LLM Agents

## Introduction

The early internet empowered individuals not only to publish information through personal websites and blogs but also to discover communities of like‑minded people via forums and mailing lists. This combination of free content sharing and social connection built trust and enabled people to learn from one another. Today’s AI platforms, however, centralize both information and relationships around a few providers, eroding the participatory spirit of the web. Elmnet aims to restore that openness by proposing a protocol where personal language‑model agents help users share knowledge, find answers and connect with others.

## Vision

Elmnet envisions a decentralized ecosystem where every person is represented by a single, multifaceted LLM agent. This personal agent learns your interests, hosts your content, seeks out information on your behalf and connects you with communities that match your passions. It can answer questions itself, forward requests to other agents when necessary, and remember past interactions to improve routing. With this unified agent model, Elmnet blends content discovery and social networking into one seamless experience.

## Concept Overview

- **Unified personal agent**: Each user has an agent that performs three roles: it acts as your knowledge base, querying the network for information you lack; it serves as an interactive “site” where others can ask questions and receive answers drawn from your expertise; and it functions as a router, learning from prior interactions to direct queries toward trusted sources or communities.

- **Community building**: Beyond finding facts, your agent helps you meet people. It can discover groups of individuals who share your interests and facilitate introductions. You can choose to interact directly with others, or dispatch your agent to exchange messages, share articles and ask questions on your behalf when you’re unavailable.

- **Decentralized routing**: Agents rely on reputations to evaluate which peers and routers are trustworthy. No single entity has a complete view of the network; instead, routing decisions emerge from accumulated interactions and community feedback.

## Example Scenario

1. **Finding vegan‑friendly Chinese cuisine**: A user asks their agent to locate Chinese restaurants that offer vegan dishes. The agent doesn’t just query generic directories; it consults agents with geographically local expertise, routes the question to dining communities and restaurant experts in the user’s area, and even reaches out to the agents of past patrons to retrieve feedback those patrons have saved. The result is a curated list of nearby restaurants along with first‑hand reviews and links to order or read more.

2. **Helping an experienced guitarist launch a teaching business**: A seasoned guitarist wants to start offering lessons. Their agent searches for music communities and local jam groups to build connections, but it also markets their services by reaching out to prospective students. The agent can share sample recordings, answer preliminary questions from parents or learners, arrange trial sessions and manage the teacher’s schedule, while still facilitating collaborative jam opportunities for artistic growth.

3. **Collaborative research and support**: A person studying climate science wishes to analyze recent data and discuss findings with peers. Their agent retrieves relevant datasets via MCP‑enabled tools and connects them with a global community of researchers. During work hours the agent can request advice, share preliminary results and coordinate virtual meet‑ups, ensuring that the user stays plugged into both data and community conversations.

4. **Engaging civic leaders and communities**: A local politician wants to understand what their constituents care about. Instead of reading thousands of emails, community members tell their agents what they’d like to see in their neighbourhoods. Those agents forward feedback to the politician’s agent, which aggregates opinions, highlights unique ideas and provides statistics on community sentiment. Constituents can also query their own agents to learn where candidates stand on issues. This two‑way communication gives new meaning to “talk to your representative.”

## Protocol Details

- **Decentralized hosting**: Agents run on a variety of hardware, allowing content creators to maintain direct ownership of their data.

- **Reputation & trust**: Routing decisions depend on reputations built through successful interactions, much like backlinks conveyed trust on the early web.

- **Privacy & control**: Users decide how much personal information is shared and can delegate tasks to their agents without exposing sensitive data.

- **Structured data via MCP**: Elmnet uses the Model Context Protocol to give agents a standardized way to access and manipulate structured data and external services. By adding this capability the network can handle tasks beyond conversation—such as updating a document or pulling sensor data—without losing the benefits of decentralization.

- **Paywalled information**: For premium content or services, agents alert users to costs and, with consent, execute payments, ensuring creators are rewarded without central control.

## Benefits

- **Empowers creators and communities**: Hosting data through personal agents re‑establishes direct relationships with audiences and helps like‑minded people find each other.

- **Supports diversity and resilience**: Decentralization avoids single points of failure and encourages a wide variety of specialized agents and communities.

- **Fosters trust**: Reputation mechanisms and standardized structured interactions make it easier to verify information while respecting privacy.

## Reference implementation and extensibility

Elmnet does not prescribe a single implementation; rather it outlines a set of core capabilities that an agent must possess to be trusted by the network. This repository therefore serves both as a whitepaper explaining those capabilities and as a working example of a personal agent. Developers are free to build their own agents with additional functionality or to serve specific purposes. As long as these agents implement the same basic interfaces and behaviours, they can join the network and interact with other agents just as seamlessly as the reference implementation.

## Conclusion

Elmnet proposes a return to the cooperative ethos of the early internet. By giving everyone a personal LLM agent that can share knowledge, explore the network, and build communities, and by using standards like MCP to extend its reach into structured data, the protocol aims to cultivate a richer, more human‑centered web.

## Proof of Concept (poc-1)

The `poc-1` folder contains a runnable reference node that implements the Elmnet
P2P and social protocol drafts. It exposes an HTTP API on port 8000 and a P2P
socket listener on port 9000. The docker-compose setup launches three nodes
connected in a local swarm so you can test query routing and peer discovery.

### Run locally with Docker

1. Build and start the services:

   ```bash
   cd poc-1
   docker compose up --build
   ```

2. Query a node over HTTP:

   ```bash
   curl "http://localhost:8001/internal?query=What%20is%20Elmnet%3F"
   ```

3. Watch the logs to see the P2P handshake, peer list exchange, and query
   propagation.

### Run locally without Docker

1. Install dependencies:

   ```bash
   cd poc-1
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Start a node (repeat in multiple shells with different ports):

   ```bash
   export P2P_PORT=9000
   export P2P_ADVERTISE_ADDR=127.0.0.1:9000
   export BOOTSTRAP_PEERS=
   python -m app.main
   ```

   For a second node:

   ```bash
   export P2P_PORT=9001
   export P2P_ADVERTISE_ADDR=127.0.0.1:9001
   export BOOTSTRAP_PEERS=127.0.0.1:9000
   python -m app.main
   ```

### Test the POC

Run the included unit tests for envelope signing and identity verification:

```bash
cd poc-1
python -m unittest discover -s app/tests
```
