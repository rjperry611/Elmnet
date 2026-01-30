"""
Entry point for the Elmnet proof of concept node.  This module
instantiates the orchestrator and a P2P network and exposes a
FastAPI application for handling HTTP based queries.  The previous
HTTP peer discovery mechanism has been replaced by the P2P network
implemented in :mod:`network`.  Nodes now discover one another via
bootstrap peers and exchange queries over persistent socket
connections.
"""

from fastapi import FastAPI
import os
import uvicorn
from orchestrator import orchestrator
from network import P2PNetwork


app = FastAPI()

# Global reference to the running P2P network instance.  It is
# initialized in ``main()`` once environment variables are read.
p2p_network: P2PNetwork | None = None


@app.get("/internal")
async def query_internal(query: str):
    """Handle a query originating from this node's owner.

    The query is first processed locally through the orchestrator and
    then broadcast to any connected peers.  Both the local and remote
    responses are returned in a dictionary.  If no peers are
    connected only the local response will be included under the
    ``local`` key.
    """
    # Local handling via orchestrator.  The orchestrator call may
    # return a coroutine when integrated with asynchronous LLMs, so
    # await it accordingly.
    local_resp = await orchestrator.orchestrate_request(True, query)

    # Broadcast to peers if the network is running.
    peer_responses: list | None = None
    if p2p_network is not None:
        # Running this in a separate coroutine on the network's loop
        # ensures it doesn't block the HTTP handler.
        peer_responses = await p2p_network.query_peers(query)  # type: ignore[arg-type]
    return {
        "local": local_resp,
        "peers": peer_responses,
    }


def main() -> None:
    """Set up the orchestrator, P2P network and launch the API server."""
    orchestrator.start()
    # Read P2P configuration from environment variables.  A default
    # port of 9000 is used if ``P2P_PORT`` is not set.  The
    # ``BOOTSTRAP_PEERS`` variable should contain a comma separated
    # list of ``host:port`` entries. ``ELMNET_MODE`` switches between
    # local swarm and live internet mode.
    p2p_port_str = os.environ.get('P2P_PORT', '9000')
    try:
        p2p_port = int(p2p_port_str)
    except ValueError:
        p2p_port = 9000
    bootstrap_csv = os.environ.get('BOOTSTRAP_PEERS', '')
    bootstrap_peers: list[str] = []
    if bootstrap_csv:
        bootstrap_peers = [p.strip() for p in bootstrap_csv.split(',') if p.strip()]
    mode = os.environ.get('ELMNET_MODE', 'local')
    capabilities_csv = os.environ.get('P2P_CAPABILITIES', '')
    services_csv = os.environ.get('P2P_SERVICES', '')
    advertise_address = os.environ.get('P2P_ADVERTISE_ADDR', f'127.0.0.1:{p2p_port}')
    capabilities = [cap.strip() for cap in capabilities_csv.split(',') if cap.strip()]
    services = [svc.strip() for svc in services_csv.split(',') if svc.strip()]
    query_ttl_str = os.environ.get('P2P_QUERY_TTL', '3')
    try:
        query_ttl = int(query_ttl_str)
    except ValueError:
        query_ttl = 3

    # Define a simple wrapper around the orchestrator call.  When
    # broadcasting queries to peers we want to synchronously call
    # orchestrator from the network's loop; if the orchestrator ever
    # returns a coroutine this wrapper will await it.  Passing the
    # wrapper avoids tight coupling between the network and the
    # orchestrator implementation.
    def on_query(query: str):
        resp = orchestrator.orchestrate_request(True, query)
        return resp

    # Instantiate and start the P2P network.  Store it in the module
    # level variable so the HTTP handlers can reference it.
    global p2p_network
    p2p_network = P2PNetwork(
        p2p_port,
        bootstrap_peers,
        on_query,
        mode=mode,
        capabilities=capabilities,
        services=services,
        advertise_address=advertise_address,
        query_ttl=query_ttl,
    )  # type: ignore
    p2p_network.start()

    # Log startup information.
    print(f"HTTP API listening on port 8000, P2P port {p2p_port}")
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
