"""
network.py
~~~~~~~~~~~

This module implements a lightweight peer-to-peer (P2P) networking
layer that follows the Elmnet protocol draft. Nodes exchange
newline-delimited JSON envelopes, perform a version/verack handshake,
and propagate queries across peers while attaching signatures and
identity metadata.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from fastecdsa import curve, ecdsa, keys
from fastecdsa.point import Point


DEFAULT_PROTOCOL = "elmnet/0.2"
DEFAULT_MAX_MESSAGE_SIZE = 256 * 1024
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 600
DEFAULT_QUERY_TTL = 3
DEFAULT_PING_INTERVAL = 30.0


class P2PNetwork:
    """A simple peer-to-peer network built using asyncio sockets.

    Instances manage a TCP server, connect to known peers, perform a
    version/verack handshake and then exchange newline-delimited JSON
    messages wrapped in signed envelopes. Queries may be broadcast to
    all connected peers and responses are collected and returned to
    the caller.
    """

    def __init__(
        self,
        port: int,
        bootstrap_peers: Optional[List[str]],
        on_query: Callable[[str], object],
        mode: str = "local",
        capabilities: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        advertise_address: Optional[str] = None,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        query_ttl: int = DEFAULT_QUERY_TTL,
        ping_interval: float = DEFAULT_PING_INTERVAL,
    ):
        self.port = port
        self.bootstrap_peers = bootstrap_peers or []
        self.on_query = on_query
        self.mode = mode
        self.capabilities = capabilities or []
        self.services = services or []
        self.advertise_address = advertise_address or f"127.0.0.1:{self.port}"
        self.max_message_size = max_message_size
        self.query_ttl = query_ttl
        self.ping_interval = ping_interval
        self.require_signatures = self.mode == "live"

        # Generate a long-lived secp256k1 keypair for identity.
        self._private_key, self._public_key = keys.gen_keypair(curve.secp256k1)
        self.public_key_bytes = self._serialize_public_key(self._public_key)
        self.public_key_b64 = base64.b64encode(self.public_key_bytes).decode("utf-8")
        self.node_id = self._derive_node_id(self.public_key_bytes)

        # Maps peer node IDs to stream writers.
        self.peers: Dict[str, asyncio.StreamWriter] = {}
        # Metadata about peers.
        self.peer_info: Dict[str, Dict[str, object]] = {}
        # Known peer addresses for discovery.
        self.known_peers: set[str] = {self.advertise_address}

        # Set of processed query IDs to prevent replay loops.
        self.processed_queries: set[str] = set()
        # Set of processed message IDs to prevent replay.
        self.seen_message_ids: set[str] = set()

        # Pending queries waiting for responses.
        self.pending_queries: Dict[str, Dict[str, object]] = {}

        # Dedicated event loop for all networking tasks.
        self.loop = asyncio.new_event_loop()

    # ------------------------------------------------------------------
    # Public API

    def start(self) -> None:
        """Start the P2P network in a background daemon thread."""
        thread = threading.Thread(target=self._start_loop, daemon=True)
        thread.start()

    async def query_peers(self, query: str, timeout: float = 10.0, topic: str | None = None) -> List[object]:
        """Broadcast a query to all connected peers and collect responses."""
        if asyncio.get_running_loop() != self.loop:
            future = asyncio.run_coroutine_threadsafe(
                self._query_peers_internal(query, timeout=timeout, topic=topic),
                self.loop,
            )
            return await asyncio.wrap_future(future)
        return await self._query_peers_internal(query, timeout=timeout, topic=topic)

    # ------------------------------------------------------------------
    # Private helpers

    async def _query_peers_internal(self, query: str, timeout: float, topic: str | None) -> List[object]:
        if not self.peers:
            return []
        qid = str(uuid.uuid4())
        self.processed_queries.add(qid)
        agg = {
            "responses": [],
            "remaining": len(self.peers),
            "event": asyncio.Event(),
        }
        self.pending_queries[qid] = agg
        msg = {
            "type": "query",
            "id": qid,
            "origin": self.node_id,
            "topic": topic,
            "payload": query,
            "ttl": self.query_ttl,
        }
        for peer_id, writer in list(self.peers.items()):
            try:
                await self._send_message(writer, msg)
            except Exception as exc:
                print(f"Error sending query to peer {peer_id}: {exc}")
                agg["remaining"] -= 1
        try:
            await asyncio.wait_for(agg["event"].wait(), timeout=timeout)
        except asyncio.TimeoutError:
            print("Timed out waiting for peer responses")
        self.pending_queries.pop(qid, None)
        return list(agg["responses"])

    def _start_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._run())

    async def _run(self) -> None:
        server = await asyncio.start_server(self._handle_incoming, host="0.0.0.0", port=self.port)
        print(f"P2P network listening on port {self.port}, node_id {self.node_id}")
        for peer in self.bootstrap_peers:
            await self._connect_to_peer(peer)
        self.loop.create_task(self._ping_loop())
        async with server:
            await server.serve_forever()

    async def _connect_to_peer(self, peer: str) -> None:
        if not peer or peer == self.advertise_address:
            return
        if peer in self.known_peers:
            return
        self.known_peers.add(peer)
        try:
            host, port_str = peer.split(":", 1)
            port = int(port_str)
        except ValueError:
            print(f"Invalid peer entry: {peer}, expected host:port")
            return
        try:
            reader, writer = await asyncio.open_connection(host, port)
            await self._outgoing_handshake(reader, writer)
        except Exception as exc:
            print(f"Failed to connect to bootstrap peer {peer}: {exc}")

    @staticmethod
    def _base58_encode(data: bytes) -> str:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, "big")
        encode = ""
        while num > 0:
            num, rem = divmod(num, 58)
            encode = alphabet[rem] + encode
        pad = 0
        for b in data:
            if b == 0:
                pad += 1
            else:
                break
        return alphabet[0] * pad + encode

    @classmethod
    def _derive_node_id(cls, public_key: bytes) -> str:
        payload = hashlib.sha256(public_key).digest()
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return cls._base58_encode(payload + checksum)

    @staticmethod
    def _serialize_public_key(public_key: Point) -> bytes:
        x_bytes = int(public_key.x).to_bytes(32, "big")
        y_bytes = int(public_key.y).to_bytes(32, "big")
        return x_bytes + y_bytes

    @staticmethod
    def _deserialize_public_key(public_key_bytes: bytes) -> Point:
        if len(public_key_bytes) != 64:
            raise ValueError("Invalid public key length")
        x = int.from_bytes(public_key_bytes[:32], "big")
        y = int.from_bytes(public_key_bytes[32:], "big")
        return Point(x, y, curve.secp256k1)

    @staticmethod
    def _canonical_json(payload: Dict[str, object]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _sign_payload(self, payload: Dict[str, object]) -> str:
        data = self._canonical_json(payload)
        r, s = ecdsa.sign(data, self._private_key, curve=curve.secp256k1, hashfunc=hashlib.sha256)
        signature_bytes = int(r).to_bytes(32, "big") + int(s).to_bytes(32, "big")
        return base64.b64encode(signature_bytes).decode("utf-8")

    @staticmethod
    def _verify_signature(payload: Dict[str, object], signature_b64: str, public_key: Point) -> bool:
        data = P2PNetwork._canonical_json(payload)
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return False
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            return ecdsa.verify((r, s), data, public_key, curve=curve.secp256k1, hashfunc=hashlib.sha256)
        except Exception:
            return False

    def _build_envelope(self, message: Dict[str, object]) -> Dict[str, object]:
        envelope = {
            "protocol": DEFAULT_PROTOCOL,
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "node_id": self.node_id,
            "public_key": self.public_key_b64,
            "signature": "",
        }
        payload = {"envelope": envelope, "message": message}
        if self.require_signatures:
            envelope["signature"] = self._sign_payload(payload)
        return {"envelope": envelope, "message": message}

    def _verify_envelope(self, envelope: Dict[str, object], message: Dict[str, object]) -> bool:
        if envelope.get("protocol") != DEFAULT_PROTOCOL:
            return False
        message_id = envelope.get("message_id")
        timestamp = envelope.get("timestamp")
        node_id = envelope.get("node_id")
        public_key_b64 = envelope.get("public_key")
        signature = envelope.get("signature")
        if not all(isinstance(value, str) for value in [message_id, timestamp, node_id, public_key_b64]):
            return False
        if message_id in self.seen_message_ids:
            return False
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            public_key = self._deserialize_public_key(public_key_bytes)
        except Exception:
            return False
        if node_id != self._derive_node_id(public_key_bytes):
            return False
        if not self._is_timestamp_fresh(timestamp):
            return False
        payload = {"envelope": {**envelope, "signature": ""}, "message": message}
        signature_present = isinstance(signature, str) and bool(signature)
        if self.require_signatures:
            if not signature_present:
                return False
            if not self._verify_signature(payload, signature, public_key):
                return False
        elif signature_present:
            if not self._verify_signature(payload, signature, public_key):
                return False
        self.seen_message_ids.add(message_id)
        return True

    @staticmethod
    def _is_timestamp_fresh(timestamp: str) -> bool:
        try:
            if timestamp.endswith("Z"):
                timestamp = timestamp.replace("Z", "+00:00")
            msg_time = datetime.fromisoformat(timestamp)
        except Exception:
            return False
        now = datetime.now(timezone.utc)
        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
        delta = abs((now - msg_time).total_seconds())
        return delta <= DEFAULT_MAX_CLOCK_SKEW_SECONDS

    async def _outgoing_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version_msg = self._build_version_message()
        await self._send_message(writer, version_msg)
        msg = await self._read_message(reader, writer)
        if msg is None:
            return
        envelope, payload = msg
        if payload.get("type") != "version":
            print("Unexpected message during handshake (outgoing):", payload)
            writer.close()
            await writer.wait_closed()
            return
        remote_node_id = self._validate_version_message(envelope, payload)
        if remote_node_id is None:
            writer.close()
            await writer.wait_closed()
            return
        await self._send_message(writer, {"type": "verack"})
        msg2 = await self._read_message(reader, writer)
        if msg2 is None:
            return
        _, payload2 = msg2
        if payload2.get("type") != "verack":
            print("Expected verack during handshake (outgoing)")
            writer.close()
            await writer.wait_closed()
            return
        self.peers[remote_node_id] = writer
        print(f"Connected to peer {remote_node_id}")
        self.loop.create_task(self._peer_reader(remote_node_id, reader, writer))
        await self._send_peer_list(remote_node_id)

    async def _incoming_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
        msg = await self._read_message(reader, writer)
        if msg is None:
            return None
        envelope, payload = msg
        if payload.get("type") != "version":
            print("Unexpected message during handshake (incoming):", payload)
            return None
        remote_node_id = self._validate_version_message(envelope, payload)
        if remote_node_id is None:
            return None
        await self._send_message(writer, self._build_version_message())
        msg2 = await self._read_message(reader, writer)
        if msg2 is None:
            return None
        _, payload2 = msg2
        if payload2.get("type") != "verack":
            print("Expected verack during handshake (incoming)")
            return None
        await self._send_message(writer, {"type": "verack"})
        self.peers[remote_node_id] = writer
        print(f"Accepted connection from peer {remote_node_id}")
        await self._send_peer_list(remote_node_id)
        return remote_node_id

    async def _handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_id = await self._incoming_handshake(reader, writer)
        if peer_id is None:
            writer.close()
            await writer.wait_closed()
            return
        await self._peer_reader(peer_id, reader, writer)

    async def _peer_reader(self, peer_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                msg = await self._read_message(reader, writer)
                if msg is None:
                    break
                envelope, payload = msg
                if not payload:
                    continue
                await self._dispatch_message(payload, envelope, peer_id)
        except Exception as exc:
            print(f"Error while reading from peer {peer_id}: {exc}")
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]
            writer.close()
            await writer.wait_closed()
            print(f"Disconnected from peer {peer_id}")

    async def _dispatch_message(
        self,
        msg: Dict[str, object],
        envelope: Dict[str, object],
        sender_peer: str,
    ) -> None:
        mtype = msg.get("type")
        if mtype == "query":
            await self._handle_query(msg, sender_peer)
        elif mtype == "response":
            await self._handle_response(msg, sender_peer)
        elif mtype == "peer_list":
            await self._handle_peer_list(msg)
        elif mtype == "peer_announce":
            await self._handle_peer_announce(msg)
        elif mtype == "ping":
            await self._send_message(self.peers[sender_peer], {"type": "pong"})
        elif mtype == "pong":
            self.peer_info.setdefault(sender_peer, {})["last_seen"] = envelope.get("timestamp")
        elif mtype == "reputation_update":
            self._handle_reputation_update(msg)
        elif mtype == "error":
            print(f"Received error from peer {sender_peer}: {msg}")

    async def _handle_query(self, msg: Dict[str, object], sender_peer: str) -> None:
        qid = msg.get("id")
        query = msg.get("payload")
        ttl = msg.get("ttl", 0)
        if not isinstance(qid, str) or not isinstance(query, str):
            return
        if qid in self.processed_queries:
            return
        self.processed_queries.add(qid)
        if isinstance(ttl, int) and ttl > 0:
            forward_msg = dict(msg)
            forward_msg["ttl"] = ttl - 1
            for peer_id, writer in list(self.peers.items()):
                if peer_id == sender_peer:
                    continue
                try:
                    await self._send_message(writer, forward_msg)
                except Exception as exc:
                    print(f"Error forwarding query to peer {peer_id}: {exc}")
        try:
            result = self.on_query(query)
            if asyncio.iscoroutine(result):
                result = await result
            response_payload = {
                "answer": result,
                "confidence": 0.5,
                "evidence": [],
            }
        except Exception as exc:
            response_payload = {"error": str(exc)}
        resp_msg = {
            "type": "response",
            "id": qid,
            "from": self.node_id,
            "response": response_payload,
            "confidence": response_payload.get("confidence", 0.0),
            "evidence": response_payload.get("evidence", []),
        }
        writer = self.peers.get(sender_peer)
        if writer is not None:
            try:
                await self._send_message(writer, resp_msg)
            except Exception as exc:
                print(f"Error sending response to peer {sender_peer}: {exc}")

    async def _handle_response(self, msg: Dict[str, object], peer_id: str) -> None:
        qid = msg.get("id")
        if not isinstance(qid, str):
            return
        agg = self.pending_queries.get(qid)
        if agg is None:
            return
        response_payload = msg.get("response")
        agg["responses"].append({"from": peer_id, "response": response_payload})
        agg["remaining"] -= 1
        if agg["remaining"] <= 0:
            agg["event"].set()

    async def _handle_peer_list(self, msg: Dict[str, object]) -> None:
        peers = msg.get("peers")
        if not isinstance(peers, list):
            return
        for peer in peers:
            if isinstance(peer, str):
                await self._connect_to_peer(peer)

    async def _handle_peer_announce(self, msg: Dict[str, object]) -> None:
        address = msg.get("address")
        if isinstance(address, str):
            await self._connect_to_peer(address)

    def _handle_reputation_update(self, msg: Dict[str, object]) -> None:
        subject = msg.get("subject")
        score = msg.get("score")
        reason = msg.get("reason")
        if not isinstance(subject, str):
            return
        if not isinstance(score, (int, float)):
            return
        record = {
            "subject": subject,
            "score": score,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.peer_info.setdefault(subject, {})["reputation_update"] = record

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(self.ping_interval)
            for peer_id, writer in list(self.peers.items()):
                try:
                    await self._send_message(writer, {"type": "ping"})
                except Exception as exc:
                    print(f"Error sending ping to peer {peer_id}: {exc}")

    async def _send_peer_list(self, peer_id: str) -> None:
        writer = self.peers.get(peer_id)
        if writer is None:
            return
        peer_list = sorted(self.known_peers)
        await self._send_message(writer, {"type": "peer_list", "peers": peer_list})

    def _build_version_message(self) -> Dict[str, object]:
        return {
            "type": "version",
            "protocol": DEFAULT_PROTOCOL,
            "node_id": self.node_id,
            "public_key": self.public_key_b64,
            "capabilities": self.capabilities,
            "services": self.services,
            "address": self.advertise_address,
        }

    def _validate_version_message(self, envelope: Dict[str, object], payload: Dict[str, object]) -> Optional[str]:
        if payload.get("protocol") != DEFAULT_PROTOCOL:
            print("Protocol mismatch:", payload)
            return None
        node_id = payload.get("node_id")
        public_key_b64 = payload.get("public_key")
        address = payload.get("address")
        if not isinstance(node_id, str) or not isinstance(public_key_b64, str):
            print("Invalid version message:", payload)
            return None
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            derived_id = self._derive_node_id(public_key_bytes)
        except Exception:
            return None
        if derived_id != node_id:
            print("Node ID mismatch in version message")
            return None
        if envelope.get("node_id") != node_id:
            print("Envelope node_id mismatch")
            return None
        self.peer_info[node_id] = {
            "address": address,
            "public_key": public_key_b64,
            "capabilities": payload.get("capabilities", []),
            "services": payload.get("services", []),
        }
        if isinstance(address, str):
            self.known_peers.add(address)
        return node_id

    async def _send_message(self, writer: asyncio.StreamWriter, message: Dict[str, object]) -> None:
        payload = self._build_envelope(message)
        data = json.dumps(payload).encode("utf-8") + b"\n"
        writer.write(data)
        await writer.drain()

    async def _read_message(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> Optional[Tuple[Dict[str, object], Dict[str, object]]]:
        try:
            line = await reader.readline()
        except Exception:
            return None
        if not line:
            return None
        if len(line) > self.max_message_size:
            await self._send_message(writer, {"type": "error", "code": "message_too_large", "message": "Message exceeded 256 KB."})
            return ({}, {})
        try:
            payload = json.loads(line.decode("utf-8"))
        except Exception:
            await self._send_message(writer, {"type": "error", "code": "invalid_json", "message": "Invalid JSON payload."})
            return ({}, {})
        if not isinstance(payload, dict):
            return ({}, {})
        envelope = payload.get("envelope")
        message = payload.get("message")
        if not isinstance(envelope, dict) or not isinstance(message, dict):
            await self._send_message(writer, {"type": "error", "code": "invalid_envelope", "message": "Missing envelope."})
            return ({}, {})
        if not self._verify_envelope(envelope, message):
            await self._send_message(writer, {"type": "error", "code": "invalid_signature", "message": "Envelope verification failed."})
            return ({}, {})
        return envelope, message
