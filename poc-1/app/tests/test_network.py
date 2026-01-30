import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.network import P2PNetwork


class TestEnvelopeSigning(unittest.TestCase):
    def test_node_id_derivation(self):
        network = P2PNetwork(0, [], lambda _: "ok", mode="live")
        derived = network._derive_node_id(network.public_key_bytes)
        self.assertEqual(network.node_id, derived)

    def test_envelope_signature_round_trip(self):
        network = P2PNetwork(0, [], lambda _: "ok", mode="live")
        message = {"type": "ping"}
        envelope = network._build_envelope(message)
        self.assertTrue(network._verify_envelope(envelope["envelope"], envelope["message"]))

    def test_envelope_signature_rejects_tamper(self):
        network = P2PNetwork(0, [], lambda _: "ok", mode="live")
        message = {"type": "ping"}
        envelope = network._build_envelope(message)
        envelope["message"]["type"] = "pong"
        self.assertFalse(network._verify_envelope(envelope["envelope"], envelope["message"]))


if __name__ == "__main__":
    unittest.main()
