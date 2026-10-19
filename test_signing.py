"""
FLUX Signing Engine — Comprehensive test suite.
Tests: signing, verification, hash chains, multi-sig, revocation,
       expiry, key rotation, commit linking, batch verify, audit log,
       weighted signatures, snapshots, pruning, and serialization.
"""
import json
import time
import unittest

from signing import (
    AgentIdentity, AgentRole, AuditAction, ChainLink, CommitLink,
    HashChain, ProgramSignature, RevocationEntry, SigningEngine,
    SignatureStatus, WeightedApproval, _sha256, _hmac_sign, _hmac_verify,
)


def _make_bytecode(seed: int = 42) -> list:
    """Generate deterministic test bytecode."""
    return [0x18, 0, seed & 0xFF, 0x20, 1, 1, 0, 0x00]


class TestCryptoPrimitives(unittest.TestCase):
    """Test low-level crypto helpers."""

    def test_sha256_deterministic(self):
        h1 = _sha256(b"hello")
        h2 = _sha256(b"hello")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_sha256_different_inputs(self):
        self.assertNotEqual(_sha256(b"abc"), _sha256(b"def"))

    def test_hmac_sign_verify(self):
        key = b"secret-key-123"
        msg = b"test message"
        sig = _hmac_sign(key, msg)
        self.assertTrue(_hmac_verify(key, msg, sig))

    def test_hmac_wrong_key(self):
        sig = _hmac_sign(b"key1", b"msg")
        self.assertFalse(_hmac_verify(b"key2", b"msg", sig))

    def test_hmac_tampered_message(self):
        sig = _hmac_sign(b"key", b"original")
        self.assertFalse(_hmac_verify(b"key", b"tampered", sig))

    def test_hmac_invalid_hex(self):
        self.assertFalse(_hmac_verify(b"key", b"msg", "not-hex!!"))


class TestAgentIdentity(unittest.TestCase):
    """Test agent identity generation and management."""

    def test_generate_agent(self):
        agent = AgentIdentity.generate("agent-001", "Alice")
        self.assertEqual(agent.agent_id, "agent-001")
        self.assertEqual(agent.name, "Alice")
        self.assertTrue(agent.is_active)
        self.assertEqual(len(agent.private_key), 64)

    def test_sign_and_verify(self):
        agent = AgentIdentity.generate("a1", "Bob")
        sig = agent.sign(b"hello")
        self.assertTrue(agent.verify(b"hello", sig))

    def test_sign_different_data(self):
        agent = AgentIdentity.generate("a2", "Carol")
        sig = agent.sign(b"data1")
        self.assertFalse(agent.verify(b"data2", sig))

    def test_key_rotation(self):
        agent = AgentIdentity.generate("a3", "Dave")
        old_key = agent.private_key
        new_fingerprint = agent.rotate_key()
        self.assertNotEqual(old_key, agent.private_key)
        self.assertEqual(new_fingerprint, agent.key_fingerprint)
        self.assertEqual(agent.key_generation, 1)

    def test_verify_after_rotation(self):
        agent = AgentIdentity.generate("a4", "Eve")
        sig = agent.sign(b"before-rotation")
        agent.rotate_key()
        # Old signatures should still verify
        self.assertTrue(agent.verify(b"before-rotation", sig))
        # New signatures with new key
        new_sig = agent.sign(b"after-rotation")
        self.assertTrue(agent.verify(b"after-rotation", new_sig))

    def test_multiple_rotations(self):
        agent = AgentIdentity.generate("a5", "Frank")
        sigs = []
        for i in range(5):
            sigs.append(agent.sign(f"msg-{i}".encode()))
            agent.rotate_key()
        # All historical signatures should verify
        for i, sig in enumerate(sigs):
            self.assertTrue(agent.verify(f"msg-{i}".encode(), sig),
                            f"Failed to verify signature from generation {i}")

    def test_deactivate(self):
        agent = AgentIdentity.generate("a6", "Grace")
        agent.is_active = False
        self.assertFalse(agent.is_active)

    def test_to_dict(self):
        agent = AgentIdentity.generate("a7", "Heidi")
        d = agent.to_dict()
        self.assertEqual(d["agent_id"], "a7")
        self.assertEqual(d["name"], "Heidi")
        self.assertIn("key_fingerprint", d)
        self.assertNotIn("public_key", d)  # no such thing: signing is symmetric
        self.assertNotIn("private_key", d)  # never export private key


class TestProgramSignature(unittest.TestCase):
    """Test program signature data class."""

    def test_expiry(self):
        sig = ProgramSignature(program_hash="abc", agent_id="a1", signature="sig",
                               expires_at=time.time() - 1)
        self.assertTrue(sig.is_expired())

    def test_no_expiry(self):
        sig = ProgramSignature(program_hash="abc", agent_id="a1", signature="sig")
        self.assertFalse(sig.is_expired())

    def test_future_expiry(self):
        sig = ProgramSignature(program_hash="abc", agent_id="a1", signature="sig",
                               expires_at=time.time() + 3600)
        self.assertFalse(sig.is_expired())

    def test_serialization_roundtrip(self):
        sig = ProgramSignature(
            program_hash="hash123", agent_id="agent-1", signature="sig456",
            metadata={"version": "2.0"}, expires_at=time.time() + 100,
            commit_hash="commitabc",
        )
        d = sig.to_dict()
        restored = ProgramSignature.from_dict(d)
        self.assertEqual(restored.program_hash, "hash123")
        self.assertEqual(restored.agent_id, "agent-1")
        self.assertEqual(restored.metadata, {"version": "2.0"})
        self.assertEqual(restored.commit_hash, "commitabc")


class TestHashChain(unittest.TestCase):
    """Test hash chain integrity."""

    def test_empty_chain(self):
        chain = HashChain()
        valid, msg = chain.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(chain.tip)

    def test_single_link(self):
        chain = HashChain()
        chain.append("prog_hash", "agent-1")
        valid, _ = chain.verify_chain()
        self.assertTrue(valid)
        self.assertIsNotNone(chain.tip)
        self.assertEqual(chain.length, 1)

    def test_multi_link(self):
        chain = HashChain()
        for i in range(10):
            chain.append(f"hash-{i}", f"agent-{i % 3}")
        valid, _ = chain.verify_chain()
        self.assertTrue(valid)
        self.assertEqual(chain.length, 10)

    def test_tamper_detection(self):
        chain = HashChain()
        chain.append("original", "agent-1")
        # Tamper with the program hash
        chain.links[0].program_hash = "tampered"
        valid, msg = chain.verify_chain()
        self.assertFalse(valid)

    def test_get_link_at(self):
        chain = HashChain()
        chain.append("h0", "a0")
        chain.append("h1", "a1")
        link = chain.get_link_at(1)
        self.assertIsNotNone(link)
        self.assertEqual(link.program_hash, "h1")
        self.assertIsNone(chain.get_link_at(5))

    def test_contains_program(self):
        chain = HashChain()
        chain.append("target", "a1")
        chain.append("other", "a2")
        self.assertTrue(chain.contains_program("target"))
        self.assertFalse(chain.contains_program("missing"))

    def test_snapshot(self):
        chain = HashChain()
        chain.append("h0", "a0")
        chain.append("h1", "a1")
        seq, snap_hash = chain.create_snapshot()
        self.assertEqual(seq, 1)
        valid, _ = chain.verify_snapshot(seq)
        self.assertTrue(valid)

    def test_get_history_range(self):
        chain = HashChain()
        for i in range(5):
            chain.append(f"h{i}", f"a{i}")
        history = chain.get_history(1, 3)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].program_hash, "h1")

    def test_chain_serialization(self):
        chain = HashChain()
        chain.append("h0", "a0")
        chain.append("h1", "a1")
        d = chain.to_dict()
        restored = HashChain.from_dict(d)
        valid, _ = restored.verify_chain()
        self.assertTrue(valid)
        self.assertEqual(restored.length, 2)


class TestSigningEngine(unittest.TestCase):
    """Test the main SigningEngine facade."""

    def setUp(self):
        self.engine = SigningEngine()
        self.agent1 = AgentIdentity.generate("agent-1", "Alice", AgentRole.AUTHOR)
        self.agent2 = AgentIdentity.generate("agent-2", "Bob", AgentRole.REVIEWER)
        self.agent3 = AgentIdentity.generate("agent-3", "Carol", AgentRole.APPROVER)
        self.engine.register_agent(self.agent1)
        self.engine.register_agent(self.agent2)
        self.engine.register_agent(self.agent3)

    def test_register_agent(self):
        agent = AgentIdentity.generate("new", "New")
        self.engine.register_agent(agent)
        self.assertIsNotNone(self.engine.get_agent("new"))

    def test_hash_bytecode(self):
        bc = _make_bytecode(42)
        h = self.engine.hash_bytecode(bc)
        self.assertEqual(len(h), 64)
        # Same bytecode -> same hash
        self.assertEqual(h, self.engine.hash_bytecode(_make_bytecode(42)))

    def test_sign_program(self):
        bc = _make_bytecode(42)
        sig = self.engine.sign_program("agent-1", bc)
        self.assertEqual(sig.agent_id, "agent-1")
        self.assertIsNotNone(sig.signature)

    def test_sign_unknown_agent(self):
        with self.assertRaises(ValueError):
            self.engine.sign_program("unknown", _make_bytecode())

    def test_sign_inactive_agent(self):
        self.engine.deactivate_agent("agent-1")
        with self.assertRaises(ValueError):
            self.engine.sign_program("agent-1", _make_bytecode())

    def test_verify_valid(self):
        bc = _make_bytecode(42)
        self.engine.sign_program("agent-1", bc)
        status, msg = self.engine.verify_program(bc)
        self.assertEqual(status, SignatureStatus.VALID)

    def test_verify_missing(self):
        status, _ = self.engine.verify_program(_make_bytecode(99))
        self.assertEqual(status, SignatureStatus.MISSING)

    def test_verify_tampered(self):
        bc = _make_bytecode(42)
        self.engine.sign_program("agent-1", bc)
        bc_tampered = bc[:] + [0xFF]
        status, _ = self.engine.verify_program(bc_tampered)
        self.assertEqual(status, SignatureStatus.MISSING)

    def test_revoke_signature(self):
        bc = _make_bytecode(42)
        self.engine.sign_program("agent-1", bc)
        prog_hash = self.engine.hash_bytecode(bc)
        result = self.engine.revoke_signature(prog_hash, "agent-1", "agent-2", "security issue")
        self.assertTrue(result)
        status, _ = self.engine.verify_program(bc)
        self.assertEqual(status, SignatureStatus.REVOKED)

    def test_revoke_nonexistent(self):
        result = self.engine.revoke_signature("nohash", "agent-1", "agent-2")
        self.assertFalse(result)

    def test_multi_sig_workflow(self):
        bc = _make_bytecode(42)
        self.engine.create_multi_sig(bc, required=2, description="needs 2 approvals")
        ok1, msg1 = self.engine.sign_multi("agent-1", bc)
        self.assertTrue(ok1)
        # Not yet fully signed
        status, _ = self.engine.verify_multi(bc)
        self.assertEqual(status, SignatureStatus.INVALID)
        ok2, msg2 = self.engine.sign_multi("agent-2", bc)
        self.assertTrue(ok2)
        status, _ = self.engine.verify_multi(bc)
        self.assertEqual(status, SignatureStatus.VALID)

    def test_multi_sig_duplicate(self):
        bc = _make_bytecode(42)
        self.engine.create_multi_sig(bc, required=2)
        self.engine.sign_multi("agent-1", bc)
        ok, _ = self.engine.sign_multi("agent-1", bc)
        self.assertFalse(ok)  # already signed

    def test_weighted_sig_workflow(self):
        bc = _make_bytecode(42)
        self.engine.create_weighted_sig(bc, {"agent-1": 1, "agent-2": 2, "agent-3": 1}, threshold=3)
        ok, _ = self.engine.sign_weighted("agent-2", bc)  # weight 2
        self.assertTrue(ok)
        status, _ = self.engine.verify_weighted(bc)
        self.assertEqual(status, SignatureStatus.INVALID)  # 2 < 3
        ok, _ = self.engine.sign_weighted("agent-1", bc)  # weight 1
        self.assertTrue(ok)
        status, _ = self.engine.verify_weighted(bc)
        self.assertEqual(status, SignatureStatus.VALID)  # 2+1=3 >= 3

    def test_signature_expiry(self):
        engine = SigningEngine(default_ttl=0.01)  # 10ms TTL
        engine.register_agent(self.agent1)
        bc = _make_bytecode(42)
        engine.sign_program("agent-1", bc)
        time.sleep(0.02)
        status, _ = engine.verify_program(bc)
        self.assertEqual(status, SignatureStatus.EXPIRED)

    def test_commit_linking(self):
        bc = _make_bytecode(42)
        link = self.engine.link_commit("agent-1", "commit-abc", bc, "initial version")
        self.assertEqual(link.commit_hash, "commit-abc")
        self.assertEqual(link.agent_id, "agent-1")
        valid, _ = self.engine.verify_commit("commit-abc")
        self.assertTrue(valid)

    def test_commit_link_tampered(self):
        bc = _make_bytecode(42)
        self.engine.link_commit("agent-1", "commit-xyz", bc, "test")
        # Tamper with stored link
        self.engine.commit_links["commit-xyz"].program_hash = "tampered"
        valid, _ = self.engine.verify_commit("commit-xyz")
        self.assertFalse(valid)

    def test_commit_history(self):
        bc = _make_bytecode(42)
        self.engine.link_commit("agent-1", "c3", bc, "v3", parent_commits=["c2"])
        self.engine.link_commit("agent-1", "c2", bc, "v2", parent_commits=["c1"])
        self.engine.link_commit("agent-1", "c1", bc, "v1")
        history = self.engine.get_commit_history("c3")
        hashes = [l.commit_hash for l in history]
        self.assertIn("c1", hashes)
        self.assertIn("c2", hashes)
        self.assertIn("c3", hashes)

    def test_batch_verify(self):
        bc1 = _make_bytecode(42)
        bc2 = _make_bytecode(99)
        sig1 = self.engine.sign_program("agent-1", bc1)
        sig2 = self.engine.sign_program("agent-1", bc2)
        results = self.engine.batch_verify([
            (bc1, sig1),
            (bc2, sig2),
        ])
        for status, _ in results:
            self.assertEqual(status, SignatureStatus.VALID)

    def test_audit_log(self):
        self.engine.sign_program("agent-1", _make_bytecode())
        self.engine.sign_program("agent-2", _make_bytecode())
        log = self.engine.get_audit_log(action=AuditAction.PROGRAM_SIGNED)
        self.assertEqual(len(log), 2)

    def test_audit_log_filter_by_actor(self):
        sign_log = self.engine.get_audit_log(action=AuditAction.PROGRAM_SIGNED, actor="agent-1")
        self.assertEqual(len(sign_log), 0)
        self.engine.sign_program("agent-1", _make_bytecode())
        self.engine.sign_program("agent-2", _make_bytecode())
        sign_log = self.engine.get_audit_log(action=AuditAction.PROGRAM_SIGNED, actor="agent-1")
        self.assertEqual(len(sign_log), 1)
        sign_log2 = self.engine.get_audit_log(action=AuditAction.PROGRAM_SIGNED, actor="agent-2")
        self.assertEqual(len(sign_log2), 1)

    def test_audit_entry_immutability(self):
        from signing import AuditEntry
        # Use fixed timestamp to ensure deterministic hash
        ts = 1700000000.0
        entry = AuditEntry(action=AuditAction.PROGRAM_SIGNED, actor="a1", target="h1",
                           timestamp=ts)
        entry2 = AuditEntry(action=AuditAction.PROGRAM_SIGNED, actor="a1", target="h1",
                            timestamp=ts)
        self.assertEqual(entry.entry_hash, entry2.entry_hash)
        # Different data -> different hash
        entry3 = AuditEntry(action=AuditAction.PROGRAM_SIGNED, actor="a2", target="h1",
                            timestamp=ts)
        self.assertNotEqual(entry.entry_hash, entry3.entry_hash)

    def test_chain_integrity_in_engine(self):
        bc = _make_bytecode(42)
        self.engine.sign_program("agent-1", bc)
        self.engine.sign_program("agent-2", bc)
        valid, _ = self.engine.verify_chain()
        self.assertTrue(valid)

    def test_chain_snapshot_in_engine(self):
        self.engine.sign_program("agent-1", _make_bytecode(1))
        self.engine.sign_program("agent-2", _make_bytecode(2))
        seq, snap_hash = self.engine.snapshot_chain()
        self.assertIsNotNone(snap_hash)

    def test_revocation_list(self):
        bc = _make_bytecode(42)
        self.engine.sign_program("agent-1", bc)
        ph = self.engine.hash_bytecode(bc)
        self.engine.revoke_signature(ph, "agent-1", "admin", "compromised key")
        revocations = self.engine.get_revocations(program_hash=ph)
        self.assertEqual(len(revocations), 1)
        self.assertEqual(revocations[0].reason, "compromised key")

    def test_export_state(self):
        self.engine.sign_program("agent-1", _make_bytecode())
        state = self.engine.export_state()
        self.assertIn("agents", state)
        self.assertIn("signatures", state)
        self.assertIn("hash_chain", state)
        self.assertIn("audit_log", state)
        self.assertIn("agent-1", state["agents"])


class TestKeyFingerprintAndCustody(unittest.TestCase):
    """The field called `public_key` was sha256 of the secret and verified nothing.

    Signing here is HMAC and is symmetric by choice. The defect was the name and
    the missing custody, not the choice of HMAC — so these tests pin the honest
    property and the round trip.
    """

    def test_fingerprint_is_not_a_verification_key(self):
        """A fingerprint names a key generation. It must not verify anything.

        If key_fingerprint could verify a signature it would be a public key.
        It cannot, so nothing may claim that it does.
        """
        agent = AgentIdentity.generate("fp-1", "Fingerprint")
        sig = agent.sign(b"payload")
        self.assertFalse(
            _hmac_verify(agent.key_fingerprint.encode(), b"payload", sig),
            "key_fingerprint must not be usable as a verification key",
        )
        self.assertTrue(agent.verify(b"payload", sig))

    def test_fingerprint_is_sha256_of_the_secret(self):
        agent = AgentIdentity.generate("fp-2", "Fingerprint")
        self.assertEqual(agent.key_fingerprint, _sha256(agent.private_key.encode()))

    def test_fingerprint_is_safe_to_publish(self):
        agent = AgentIdentity.generate("fp-3", "Fingerprint")
        d = agent.to_dict()
        self.assertNotIn(agent.private_key, json.dumps(d))
        self.assertIn(agent.key_fingerprint, json.dumps(d))

    def test_fingerprint_changes_on_rotation(self):
        agent = AgentIdentity.generate("fp-4", "Fingerprint")
        before = agent.key_fingerprint
        self.assertNotEqual(agent.rotate_key(), before)
        self.assertEqual(agent.key_fingerprint, _sha256(agent.private_key.encode()))

    def test_from_dict_rejects_a_key_that_does_not_match(self):
        agent = AgentIdentity.generate("fp-5", "Fingerprint")
        d = agent.to_dict()
        with self.assertRaises(ValueError):
            AgentIdentity.from_dict(d, "not-the-secret")

    def test_from_dict_round_trip(self):
        agent = AgentIdentity.generate("fp-6", "Fingerprint")
        d = agent.to_dict()
        restored = AgentIdentity.from_dict(d, agent.private_key)
        self.assertEqual(restored.agent_id, agent.agent_id)
        self.assertEqual(restored.key_fingerprint, agent.key_fingerprint)
        sig = agent.sign(b"round trip")
        self.assertTrue(restored.verify(b"round trip", sig))

    def test_from_dict_refuses_a_short_history(self):
        """Dropping rotated secrets would silently stop old signatures verifying."""
        agent = AgentIdentity.generate("fp-7", "Fingerprint")
        old_secret = agent.private_key
        agent.rotate_key()
        d = agent.to_dict()
        self.assertEqual(d["key_generation"], 1)
        with self.assertRaises(ValueError):
            AgentIdentity.from_dict(d, agent.private_key)
        restored = AgentIdentity.from_dict(d, agent.private_key, [old_secret])
        sig = AgentIdentity(agent.agent_id, agent.name, agent.key_fingerprint,
                            old_secret).sign(b"pre-rotation")
        self.assertTrue(restored.verify(b"pre-rotation", sig))


class TestStateRoundTrip(unittest.TestCase):
    """export_state() with no inverse leaves an exported signature unverifiable."""

    def _engine_with_a_signature(self):
        engine = SigningEngine()
        agent = AgentIdentity.generate("rt-1", "RoundTrip")
        engine.register_agent(agent)
        engine.sign_program("rt-1", _make_bytecode(7))
        return engine, agent

    def test_exported_signature_verifies_after_import(self):
        engine, agent = self._engine_with_a_signature()
        bc = _make_bytecode(7)
        self.assertEqual(engine.verify_program(bc)[0], SignatureStatus.VALID)

        state = engine.export_state()
        restored = engine.import_state(state, {"rt-1": agent.private_key})
        status, msg = restored.verify_program(bc)
        self.assertEqual(status, SignatureStatus.VALID, msg)

    def test_export_carries_no_secret(self):
        engine, agent = self._engine_with_a_signature()
        state = engine.export_state()
        self.assertNotIn(agent.private_key, json.dumps(state))

    def test_import_refuses_without_a_secret(self):
        engine, _ = self._engine_with_a_signature()
        with self.assertRaises(ValueError) as ctx:
            engine.import_state(engine.export_state(), {})
        self.assertIn("rt-1", str(ctx.exception))

    def test_import_refuses_the_wrong_secret(self):
        engine, _ = self._engine_with_a_signature()
        with self.assertRaises(ValueError):
            engine.import_state(engine.export_state(), {"rt-1": "not-the-secret"})

    def test_import_preserves_chain_and_revocations(self):
        engine = SigningEngine()
        agent = AgentIdentity.generate("rt-2", "Chain")
        engine.register_agent(agent)
        bc = _make_bytecode(9)
        engine.sign_program("rt-2", bc)
        ph = engine.hash_bytecode(bc)
        engine.revoke_signature(ph, "rt-2", "admin", "compromised")
        engine.snapshot_chain()

        state = engine.export_state()
        restored = engine.import_state(state, {"rt-2": agent.private_key})

        ok, msg = restored.verify_chain()
        self.assertTrue(ok, msg)
        self.assertEqual(len(restored.get_revocations(program_hash=ph)), 1)
        self.assertEqual(restored.get_revocations(program_hash=ph)[0].reason, "compromised")
        self.assertEqual(restored.verify_program(bc)[0], SignatureStatus.REVOKED)
        self.assertEqual(len(restored.audit_log), len(engine.audit_log))

    def test_import_keeps_pre_rotation_signatures_verifiable(self):
        engine = SigningEngine()
        agent = AgentIdentity.generate("rt-3", "Rotator")
        engine.register_agent(agent)
        bc = _make_bytecode(11)
        old_secret = agent.private_key
        engine.sign_program("rt-3", bc)          # signed under generation 0
        engine.rotate_agent_key("rt-3")

        state = engine.export_state()
        with self.assertRaises(ValueError):
            engine.import_state(state, {"rt-3": agent.private_key})
        restored = engine.import_state(
            state, {"rt-3": agent.private_key}, {"rt-3": [old_secret]}
        )
        status, msg = restored.verify_program(bc)
        self.assertEqual(status, SignatureStatus.VALID, msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
