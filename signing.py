"""
FLUX Signing — code signing, verification, hash chains, multi-sig, and revocation.

Provides a complete cryptographic infrastructure for FLUX bytecode programs:
  - Bytecode signing via HMAC-SHA256
  - Verification pipeline with tamper detection
  - Hash chains for program version integrity
  - Agent identity management (commit authorship)
  - Multi-signature approval workflows
  - Signature revocation list
  - Signature expiry (TTL)
  - Agent key rotation
  - Commit linking (link signatures to fleet commits)
  - Batch verification
  - Audit logging
  - Threshold/weighted multi-sig
  - Hash chain snapshots

Signing is HMAC-SHA256 and is symmetric by design: sign() and verify() use the
same secret, so a verifier must hold the agent's secret. There is no public key
in this module and no asymmetric leg. What an agent publishes is a
`key_fingerprint` — sha256 of the secret — which names a key generation and
verifies nothing. Key custody is the operator's: secrets are never written by
to_dict()/export_state(), and are supplied on import.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Set


# ── Utility ──────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _hmac_sign(key: bytes, message: bytes) -> str:
    """HMAC-SHA256 sign."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _hmac_verify(key: bytes, message: bytes, sig: str) -> bool:
    """Constant-time HMAC-SHA256 verify."""
    expected = hmac.new(key, message, hashlib.sha256).digest()
    try:
        provided = bytes.fromhex(sig)
        return hmac.compare_digest(expected, provided)
    except (ValueError, TypeError):
        return False


# ── Enums ────────────────────────────────────────────────────────────────────

class SignatureStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    MISSING = "missing"


class AgentRole(Enum):
    AUTHOR = "author"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    OPERATOR = "operator"
    ADMIN = "admin"


class AuditAction(Enum):
    AGENT_REGISTERED = "agent_registered"
    AGENT_DEACTIVATED = "agent_deactivated"
    AGENT_KEY_ROTATED = "agent_key_rotated"
    PROGRAM_SIGNED = "program_signed"
    SIGNATURE_REVOKED = "signature_revoked"
    MULTI_SIG_CREATED = "multi_sig_created"
    MULTI_SIG_SIGNED = "multi_sig_signed"
    COMMIT_LINKED = "commit_linked"
    CHAIN_SNAPSHOT = "chain_snapshot"


# ── Agent Identity ──────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    """A FLUX fleet agent with signing capabilities.

    Signing here is HMAC-SHA256, which is symmetric by choice: sign() and
    verify() use the same secret. That is a legitimate design, but it has one
    consequence worth stating plainly — **a verifier must hold the agent's
    secret**. There is no public key, and nothing in this module is a public
    key.

    What this module carries instead is `key_fingerprint`: sha256 of the secret,
    hex-encoded. It is a *name* for a key generation — it identifies which
    secret signed, it is safe to publish, and it verifies nothing at all. It was
    previously called `public_key`, which was a lie in the type system: a hash of
    the secret that no verifier could use.

    Because verification needs the secret, custody is the operator's job. Keep
    secrets in whatever the fleet already keeps secrets in and supply them on
    import via AgentIdentity.from_dict / SigningEngine.import_state. They are
    never written into to_dict() or export_state().
    """
    agent_id: str
    name: str
    key_fingerprint: str  # hex sha256 of the secret. Identifies a key generation. Verifies nothing.
    private_key: str  # hex-encoded secret key
    role: AgentRole = AgentRole.AUTHOR
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    previous_keys: List[str] = field(default_factory=list)  # rotated-out secrets, kept to verify old signatures

    @classmethod
    def generate(cls, agent_id: str, name: str, role: AgentRole = AgentRole.AUTHOR) -> "AgentIdentity":
        """Generate a new agent with a random 256-bit secret."""
        private_key = uuid.uuid4().hex + uuid.uuid4().hex  # 256-bit
        key_fingerprint = _sha256(private_key.encode())
        return cls(agent_id=agent_id, name=name, key_fingerprint=key_fingerprint,
                   private_key=private_key, role=role)

    def sign(self, data: bytes) -> str:
        """Sign arbitrary data with this agent's secret (HMAC)."""
        return _hmac_sign(self.private_key.encode(), data)

    def verify(self, data: bytes, signature: str) -> bool:
        """Verify a signature. Requires the secret — HMAC is symmetric."""
        # Try current key first, then historical keys
        if _hmac_verify(self.private_key.encode(), data, signature):
            return True
        for old_key in self.previous_keys:
            if _hmac_verify(old_key.encode(), data, signature):
                return True
        return False

    def rotate_key(self) -> str:
        """Rotate to a new secret. Returns the new key_fingerprint.

        The old secret is kept in previous_keys so signatures made before the
        rotation still verify — which is also why previous_keys are secrets the
        operator must retain and supply again on import.
        """
        self.previous_keys.append(self.private_key)
        new_private = uuid.uuid4().hex + uuid.uuid4().hex
        self.private_key = new_private
        self.key_fingerprint = _sha256(new_private.encode())
        return self.key_fingerprint

    @property
    def key_generation(self) -> int:
        """Number of key rotations performed."""
        return len(self.previous_keys)

    def to_dict(self) -> dict:
        """Public record of the agent. Carries the fingerprint, never the secret."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "key_fingerprint": self.key_fingerprint,
            "role": self.role.value,
            "created_at": self.created_at,
            "is_active": self.is_active,
            "key_generation": self.key_generation,
        }

    @classmethod
    def from_dict(cls, d: dict, private_key: str,
                  previous_keys: Sequence[str] = ()) -> "AgentIdentity":
        """Rebuild an agent from to_dict() plus the secrets, held separately.

        to_dict() never carries a secret, so an export on its own is a record,
        not a working agent. Custody is the caller's: read `private_key` from
        wherever the fleet keeps secrets and pass it in.

        The fingerprint is recomputed from the supplied secret and checked
        against the recorded one, so a mismatched key is refused rather than
        silently accepted. `previous_keys` must hold one secret per recorded
        key_generation, in rotation order — without them, signatures made before
        the last rotation would silently stop verifying, so that is an error
        rather than a silent loss of verifiability.
        """
        fingerprint = _sha256(private_key.encode())
        if d.get("key_fingerprint") != fingerprint:
            raise ValueError(
                f"private key does not match the recorded key_fingerprint for "
                f"agent {d.get('agent_id')!r}"
            )
        previous_keys = list(previous_keys)
        generations = d.get("key_generation", 0)
        if len(previous_keys) != generations:
            raise ValueError(
                f"agent {d.get('agent_id')!r} has {generations} rotated key(s) but "
                f"{len(previous_keys)} historical secret(s) were supplied; "
                f"signatures made before the last rotation would not verify"
            )
        return cls(
            agent_id=d["agent_id"],
            name=d.get("name", ""),
            key_fingerprint=fingerprint,
            private_key=private_key,
            role=AgentRole(d.get("role", AgentRole.AUTHOR.value)),
            created_at=d.get("created_at", 0.0),
            is_active=d.get("is_active", True),
            previous_keys=previous_keys,
        )


# ── Program Signature ───────────────────────────────────────────────────────

@dataclass
class ProgramSignature:
    """A cryptographic signature over FLUX bytecode."""
    program_hash: str
    agent_id: str
    signature: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, str] = field(default_factory=dict)
    is_revoked: bool = False
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    expires_at: Optional[float] = None  # TTL support
    commit_hash: Optional[str] = None  # linked commit

    def is_expired(self) -> bool:
        """Check if the signature has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        d = {
            "program_hash": self.program_hash,
            "agent_id": self.agent_id,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "is_revoked": self.is_revoked,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        if self.commit_hash:
            d["commit_hash"] = self.commit_hash
        if self.revoked_at:
            d["revoked_at"] = self.revoked_at
        if self.revoked_by:
            d["revoked_by"] = self.revoked_by
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ProgramSignature":
        return cls(
            program_hash=d["program_hash"],
            agent_id=d["agent_id"],
            signature=d["signature"],
            timestamp=d.get("timestamp", 0),
            metadata=d.get("metadata", {}),
            is_revoked=d.get("is_revoked", False),
            revoked_at=d.get("revoked_at"),
            revoked_by=d.get("revoked_by"),
            expires_at=d.get("expires_at"),
            commit_hash=d.get("commit_hash"),
        )


# ── Commit Link ─────────────────────────────────────────────────────────────

@dataclass
class CommitLink:
    """Links a fleet commit to a signed program."""
    commit_hash: str
    agent_id: str
    program_hash: str
    signature: str  # signature over commit_hash
    message: str
    parent_commits: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "commit_hash": self.commit_hash,
            "agent_id": self.agent_id,
            "program_hash": self.program_hash,
            "signature": self.signature,
            "message": self.message,
            "parent_commits": self.parent_commits,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CommitLink":
        return cls(**d)


# ── Hash Chain ──────────────────────────────────────────────────────────────

@dataclass
class ChainLink:
    """A single link in the program integrity hash chain."""
    sequence: int
    program_hash: str
    previous_hash: str
    link_hash: str
    agent_id: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "program_hash": self.program_hash,
            "previous_hash": self.previous_hash,
            "link_hash": self.link_hash,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ChainLink":
        return cls(**d)


@dataclass
class HashChain:
    """Hash chain providing attestable (re-derivable) program version history.

    NOT tamper-evident, and the missing leg is leg 3. The rest of this module is
    real signing: agents hold keys, keys rotate, signatures expire and are
    revoked, approval is weighted. So a head signed under an agent key would be
    leg 2. But no head is ever published somewhere the log writer does not
    control, and the writer holds the keys — there is no anchor, and no anchor
    is leg 3. Without it an attacker who re-chains an edit verifies perfectly,
    and a truncated chain is a shorter valid chain.

    So the chain alone is `attestable`: it re-derives, an edit is expensive, and
    a naive edit is named by verify_chain(). It becomes tamper-evident when the
    tip is signed under a key the writer does not hold and published where the
    writer does not control it. Nothing in this module does that.
    """
    links: List[ChainLink] = field(default_factory=list)
    snapshots: Dict[int, str] = field(default_factory=dict)  # seq -> snapshot hash

    @property
    def tip(self) -> Optional[str]:
        """Hash of the most recent link."""
        return self.links[-1].link_hash if self.links else None

    @property
    def length(self) -> int:
        return len(self.links)

    def append(self, program_hash: str, agent_id: str,
               metadata: Dict[str, str] = None) -> ChainLink:
        """Append a new program version to the chain."""
        prev = self.tip or "0" * 64  # genesis uses all-zeros
        seq = len(self.links)
        meta_json = json.dumps(metadata or {}, sort_keys=True)
        raw = f"{seq}|{prev}|{program_hash}|{agent_id}|{meta_json}"
        link_hash = _sha256(raw.encode())
        link = ChainLink(
            sequence=seq, program_hash=program_hash,
            previous_hash=prev, link_hash=link_hash,
            agent_id=agent_id, metadata=metadata or {},
        )
        self.links.append(link)
        return link

    def verify_chain(self) -> Tuple[bool, str]:
        """Verify entire chain integrity. Returns (is_valid, error_message)."""
        if not self.links:
            return True, "empty chain"

        if self.links[0].previous_hash != "0" * 64:
            return False, "genesis link has invalid previous_hash"

        for i, link in enumerate(self.links):
            if link.sequence != i:
                return False, f"sequence mismatch at index {i}: expected {i}, got {link.sequence}"

            expected_prev = "0" * 64 if i == 0 else self.links[i - 1].link_hash
            if link.previous_hash != expected_prev:
                return False, f"previous_hash mismatch at link {i}"

            meta_json = json.dumps(link.metadata, sort_keys=True)
            raw = f"{link.sequence}|{link.previous_hash}|{link.program_hash}|{link.agent_id}|{meta_json}"
            expected_hash = _sha256(raw.encode())
            if link.link_hash != expected_hash:
                return False, f"link_hash mismatch at link {i}: chain may be tampered"

        return True, "chain verified"

    def get_link_at(self, sequence: int) -> Optional[ChainLink]:
        """Get a chain link by sequence number."""
        if 0 <= sequence < len(self.links):
            return self.links[sequence]
        return None

    def _snapshot_digest(self, seq: int) -> str:
        """Digest of the chain prefix links[0..seq].

        create_snapshot() and verify_snapshot() both read this, so the digest a
        snapshot is checked against is by construction the digest it was made
        from.
        """
        snapshot_data = json.dumps(
            {"links": [l.to_dict() for l in self.links[:seq + 1]]}, sort_keys=True
        )
        return _sha256(snapshot_data.encode())

    def create_snapshot(self) -> Tuple[int, str]:
        """Create a checkpoint snapshot of the chain at current state."""
        seq = len(self.links) - 1
        snapshot_hash = self._snapshot_digest(seq)
        self.snapshots[seq] = snapshot_hash
        return seq, snapshot_hash

    def verify_snapshot(self, seq: int) -> Tuple[bool, str]:
        """Verify a previously created snapshot is still valid.

        Recomputes the digest over links[0..seq] and compares it against the
        digest recorded when the snapshot was taken. A history that no longer
        re-derives fails here for the same reason it fails verify_chain(): a
        snapshot is evidence, and evidence that is not re-derived is not
        evidence.
        """
        if seq not in self.snapshots:
            return False, f"no snapshot at sequence {seq}"
        if seq < 0 or seq >= len(self.links):
            return False, "sequence out of range"
        snapshot_hash = self.snapshots[seq]
        current_hash = self._snapshot_digest(seq)
        if current_hash != snapshot_hash:
            return False, (f"snapshot mismatch at sequence {seq}: chain no longer "
                           f"re-derives to {snapshot_hash[:16]}...")
        return True, f"snapshot valid at sequence {seq} (tip_hash={snapshot_hash[:16]}...)"

    def get_history(self, start: int = 0, end: Optional[int] = None) -> List[ChainLink]:
        """Get a range of chain links."""
        if end is None:
            end = len(self.links)
        return self.links[start:end]

    def contains_program(self, program_hash: str) -> bool:
        """Check if a program hash exists in the chain."""
        return any(link.program_hash == program_hash for link in self.links)

    def prune_before(self, sequence: int) -> int:
        """Prune links before a given sequence (keep from sequence onward).
        Returns number of links pruned. Cannot prune if snapshots exist before sequence."""
        for snap_seq in self.snapshots:
            if snap_seq < sequence:
                raise ValueError(f"cannot prune: snapshot exists at sequence {snap_seq}")
        pruned = self.links[:sequence]
        self.links = self.links[sequence:]
        # Update first link's previous_hash to genesis if we pruned everything
        if self.links and sequence > 0:
            pass  # keep chain intact from sequence point
        return len(pruned)

    def to_dict(self) -> dict:
        return {"links": [l.to_dict() for l in self.links],
                "snapshots": dict(self.snapshots)}

    @classmethod
    def from_dict(cls, d: dict) -> "HashChain":
        links = [ChainLink.from_dict(l) for l in d.get("links", [])]
        snapshots = {int(k): v for k, v in d.get("snapshots", {}).items()}
        return cls(links=links, snapshots=snapshots)


# ── Multi-Signature ─────────────────────────────────────────────────────────

@dataclass
class MultiSignature:
    """Collects multiple agent signatures for a single program."""
    program_hash: str
    signatures: List[ProgramSignature] = field(default_factory=list)
    required_approvals: int = 1
    description: str = ""

    @property
    def is_fully_signed(self) -> bool:
        active_sigs = [s for s in self.signatures if not s.is_revoked]
        return len(active_sigs) >= self.required_approvals

    @property
    def unique_agents(self) -> Set[str]:
        return {s.agent_id for s in self.signatures if not s.is_revoked}

    def add_signature(self, sig: ProgramSignature) -> bool:
        """Add a signature. Returns True if added, False if already signed by this agent."""
        if sig.program_hash != self.program_hash:
            return False
        for existing in self.signatures:
            if existing.agent_id == sig.agent_id and not existing.is_revoked:
                return False
        self.signatures.append(sig)
        return True

    def get_status(self) -> SignatureStatus:
        active = [s for s in self.signatures if not s.is_revoked]
        if len(active) >= self.required_approvals:
            return SignatureStatus.VALID
        if self.signatures and not active:
            return SignatureStatus.REVOKED
        if not self.signatures:
            return SignatureStatus.MISSING
        return SignatureStatus.INVALID

    def to_dict(self) -> dict:
        return {
            "program_hash": self.program_hash,
            "signatures": [s.to_dict() for s in self.signatures],
            "required_approvals": self.required_approvals,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MultiSignature":
        return cls(
            program_hash=d["program_hash"],
            signatures=[ProgramSignature.from_dict(s) for s in d.get("signatures", [])],
            required_approvals=d.get("required_approvals", 1),
            description=d.get("description", ""),
        )


# ── Weighted/Threshold Signatures ────────────────────────────────────────────

@dataclass
class WeightedApproval:
    """A multi-sig approval with a weight (for threshold signatures)."""
    program_hash: str
    agent_weights: Dict[str, int] = field(default_factory=dict)  # agent_id -> weight
    required_threshold: int = 1
    signatures: List[ProgramSignature] = field(default_factory=list)
    description: str = ""

    @property
    def current_weight(self) -> int:
        """Total weight of active (non-revoked) signatures."""
        active_agents = {s.agent_id for s in self.signatures if not s.is_revoked}
        return sum(self.agent_weights.get(aid, 0) for aid in active_agents)

    @property
    def is_fully_signed(self) -> bool:
        return self.current_weight >= self.required_threshold

    @property
    def unique_agents(self) -> Set[str]:
        return {s.agent_id for s in self.signatures if not s.is_revoked}

    def add_signature(self, sig: ProgramSignature) -> bool:
        """Add a signature. Returns True if added."""
        if sig.program_hash != self.program_hash:
            return False
        for existing in self.signatures:
            if existing.agent_id == sig.agent_id and not existing.is_revoked:
                return False
        self.signatures.append(sig)
        return True

    def get_status(self) -> SignatureStatus:
        active = [s for s in self.signatures if not s.is_revoked]
        if len(active) >= 1 and self.current_weight >= self.required_threshold:
            return SignatureStatus.VALID
        if self.signatures and not active:
            return SignatureStatus.REVOKED
        if not self.signatures:
            return SignatureStatus.MISSING
        return SignatureStatus.INVALID

    def to_dict(self) -> dict:
        return {
            "program_hash": self.program_hash,
            "agent_weights": self.agent_weights,
            "required_threshold": self.required_threshold,
            "signatures": [s.to_dict() for s in self.signatures],
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WeightedApproval":
        return cls(
            program_hash=d["program_hash"],
            agent_weights=dict(d.get("agent_weights", {})),
            required_threshold=d.get("required_threshold", 1),
            signatures=[ProgramSignature.from_dict(s) for s in d.get("signatures", [])],
            description=d.get("description", ""),
        )


# ── Revocation List ─────────────────────────────────────────────────────────

@dataclass
class RevocationEntry:
    signature_hash: str
    program_hash: str
    agent_id: str
    revoked_by: str
    reason: str
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_dict(cls, d: dict) -> "RevocationEntry":
        return cls(
            signature_hash=d["signature_hash"],
            program_hash=d["program_hash"],
            agent_id=d["agent_id"],
            revoked_by=d["revoked_by"],
            reason=d.get("reason", ""),
            timestamp=d.get("timestamp", 0.0),
        )


# ── Audit Log ───────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    """Immutable audit log entry for all signing engine operations."""
    action: AuditAction
    actor: str
    target: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    entry_hash: str = ""

    def __post_init__(self):
        if not self.entry_hash:
            raw = f"{self.action.value}|{self.actor}|{self.target}|{json.dumps(self.details, sort_keys=True)}|{self.timestamp}"
            self.entry_hash = _sha256(raw.encode())

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "actor": self.actor,
            "target": self.target,
            "details": self.details,
            "timestamp": self.timestamp,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(
            action=AuditAction(d["action"]),
            actor=d["actor"],
            target=d["target"],
            details=d.get("details", {}),
            timestamp=d.get("timestamp", 0.0),
            entry_hash=d.get("entry_hash", ""),
        )


# ── Signing Engine (main facade) ────────────────────────────────────────────

class SigningEngine:
    """Main facade for FLUX program signing operations."""

    def __init__(self, default_ttl: Optional[float] = None):
        self.agents: Dict[str, AgentIdentity] = {}
        self.signatures: Dict[str, List[ProgramSignature]] = {}  # program_hash -> list
        self.hash_chain = HashChain()
        self.revocations: Dict[str, RevocationEntry] = {}  # signature_hash -> entry
        self.multi_sigs: Dict[str, MultiSignature] = {}  # program_hash -> multi-sig
        self.weighted_sigs: Dict[str, WeightedApproval] = {}
        self.commit_links: Dict[str, CommitLink] = {}  # commit_hash -> link
        self.audit_log: List[AuditEntry] = []
        self.default_ttl = default_ttl  # seconds, None = no expiry

    # ── Audit ──

    def _audit(self, action: AuditAction, actor: str, target: str, details: Dict = None):
        entry = AuditEntry(action=action, actor=actor, target=target, details=details or {})
        self.audit_log.append(entry)

    def get_audit_log(self, action: AuditAction = None, actor: str = None,
                      since: float = None) -> List[AuditEntry]:
        """Query audit log with optional filters."""
        entries = self.audit_log
        if action:
            entries = [e for e in entries if e.action == action]
        if actor:
            entries = [e for e in entries if e.actor == actor]
        if since:
            entries = [e for e in entries if e.timestamp >= since]
        return entries

    # ── Agent management ──

    def register_agent(self, agent: AgentIdentity) -> None:
        """Register an agent identity."""
        self.agents[agent.agent_id] = agent
        self._audit(AuditAction.AGENT_REGISTERED, agent.agent_id, agent.key_fingerprint)

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        return self.agents.get(agent_id)

    def deactivate_agent(self, agent_id: str) -> bool:
        agent = self.agents.get(agent_id)
        if agent:
            agent.is_active = False
            self._audit(AuditAction.AGENT_DEACTIVATED, agent_id, agent_id)
            return True
        return False

    def rotate_agent_key(self, agent_id: str) -> Optional[str]:
        """Rotate an agent's secret. Returns the new key_fingerprint or None."""
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        new_fingerprint = agent.rotate_key()
        self._audit(AuditAction.AGENT_KEY_ROTATED, agent_id, new_fingerprint,
                    {"generation": agent.key_generation})
        return new_fingerprint

    # ── Signing ──

    def hash_bytecode(self, bytecode: List[int]) -> str:
        """Compute the canonical hash of a bytecode program."""
        return _sha256(bytes(bytecode))

    def sign_program(self, agent_id: str, bytecode: List[int],
                     metadata: Dict[str, str] = None, ttl: float = None) -> ProgramSignature:
        """Sign a bytecode program with an agent's identity."""
        agent = self.agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent '{agent_id}' not found")
        if not agent.is_active:
            raise ValueError(f"Agent '{agent_id}' is deactivated")

        program_hash = self.hash_bytecode(bytecode)
        signature = agent.sign(program_hash.encode())

        effective_ttl = ttl or self.default_ttl
        expires_at = time.time() + effective_ttl if effective_ttl else None

        sig = ProgramSignature(
            program_hash=program_hash,
            agent_id=agent_id,
            signature=signature,
            metadata=metadata or {},
            expires_at=expires_at,
        )

        if program_hash not in self.signatures:
            self.signatures[program_hash] = []
        self.signatures[program_hash].append(sig)

        # Append to hash chain
        self.hash_chain.append(program_hash, agent_id, metadata)

        self._audit(AuditAction.PROGRAM_SIGNED, agent_id, program_hash,
                    {"ttl": effective_ttl, "metadata": metadata})

        return sig

    # ── Verification ──

    def verify_program(self, bytecode: List[int]) -> Tuple[SignatureStatus, str]:
        """Verify all signatures on a bytecode program."""
        program_hash = self.hash_bytecode(bytecode)
        sigs = self.signatures.get(program_hash)

        if not sigs:
            return SignatureStatus.MISSING, "no signatures found for this program"

        for sig in sigs:
            if sig.is_revoked:
                return SignatureStatus.REVOKED, f"signature by {sig.agent_id} has been revoked"
            if sig.is_expired():
                return SignatureStatus.EXPIRED, f"signature by {sig.agent_id} has expired"

            agent = self.agents.get(sig.agent_id)
            if not agent:
                return SignatureStatus.INVALID, f"agent {sig.agent_id} not found"

            if not agent.verify(program_hash.encode(), sig.signature):
                return SignatureStatus.INVALID, f"signature by {sig.agent_id} is invalid"

        return SignatureStatus.VALID, "all signatures valid"

    def verify_signature(self, program_hash: str, signature: ProgramSignature) -> Tuple[SignatureStatus, str]:
        """Verify a specific signature against a known program hash."""
        if signature.is_revoked:
            return SignatureStatus.REVOKED, f"signature by {signature.agent_id} revoked"
        if signature.is_expired():
            return SignatureStatus.EXPIRED, f"signature by {signature.agent_id} expired"

        agent = self.agents.get(signature.agent_id)
        if not agent:
            return SignatureStatus.INVALID, f"agent {signature.agent_id} not found"

        if not agent.verify(program_hash.encode(), signature.signature):
            return SignatureStatus.INVALID, f"signature by {signature.agent_id} is invalid"

        return SignatureStatus.VALID, "signature valid"

    def batch_verify(self, programs: List[Tuple[List[int], ProgramSignature]]) -> List[Tuple[SignatureStatus, str]]:
        """Verify multiple programs in batch. Returns list of (status, message)."""
        results = []
        for bytecode, sig in programs:
            program_hash = self.hash_bytecode(bytecode)
            status, msg = self.verify_signature(program_hash, sig)
            results.append((status, msg))
        return results

    # ── Multi-signature ──

    def create_multi_sig(self, bytecode: List[int], required: int = 2,
                         description: str = "") -> MultiSignature:
        """Create a multi-signature request for a program."""
        program_hash = self.hash_bytecode(bytecode)
        ms = MultiSignature(
            program_hash=program_hash,
            required_approvals=required,
            description=description,
        )
        self.multi_sigs[program_hash] = ms
        self._audit(AuditAction.MULTI_SIG_CREATED, "system", program_hash,
                    {"required": required})
        return ms

    def sign_multi(self, agent_id: str, bytecode: List[int],
                   metadata: Dict[str, str] = None) -> Tuple[bool, str]:
        """Have an agent sign a multi-sig program. Returns (added, message)."""
        program_hash = self.hash_bytecode(bytecode)
        ms = self.multi_sigs.get(program_hash)

        if not ms:
            return False, "no multi-sig request for this program"

        agent = self.agents.get(agent_id)
        if not agent:
            return False, f"agent '{agent_id}' not found"
        if not agent.is_active:
            return False, f"agent '{agent_id}' is deactivated"

        sig = ProgramSignature(
            program_hash=program_hash,
            agent_id=agent_id,
            signature=agent.sign(program_hash.encode()),
            metadata=metadata or {},
        )

        added = ms.add_signature(sig)
        if added:
            if program_hash not in self.signatures:
                self.signatures[program_hash] = []
            self.signatures[program_hash].append(sig)
            self._audit(AuditAction.MULTI_SIG_SIGNED, agent_id, program_hash)
            return True, f"agent '{agent_id}' signed successfully ({len(ms.unique_agents)}/{ms.required_approvals})"
        return False, f"agent '{agent_id}' already signed"

    def verify_multi(self, bytecode: List[int]) -> Tuple[SignatureStatus, str]:
        """Verify a multi-signed program."""
        program_hash = self.hash_bytecode(bytecode)
        ms = self.multi_sigs.get(program_hash)

        if not ms:
            return SignatureStatus.MISSING, "no multi-sig request found"

        if not ms.is_fully_signed:
            active = len([s for s in ms.signatures if not s.is_revoked])
            return SignatureStatus.INVALID, f"insufficient approvals: {active}/{ms.required_approvals}"

        for sig in ms.signatures:
            if sig.is_revoked:
                return SignatureStatus.REVOKED, f"signature by {sig.agent_id} revoked"
            agent = self.agents.get(sig.agent_id)
            if not agent or not agent.verify(program_hash.encode(), sig.signature):
                return SignatureStatus.INVALID, f"invalid signature from {sig.agent_id}"

        return SignatureStatus.VALID, f"fully verified with {len(ms.unique_agents)} approvals"

    # ── Weighted/Threshold Signatures ──

    def create_weighted_sig(self, bytecode: List[int], agent_weights: Dict[str, int],
                            threshold: int, description: str = "") -> WeightedApproval:
        """Create a weighted/threshold multi-sig request."""
        program_hash = self.hash_bytecode(bytecode)
        wa = WeightedApproval(
            program_hash=program_hash,
            agent_weights=agent_weights,
            required_threshold=threshold,
            description=description,
        )
        self.weighted_sigs[program_hash] = wa
        return wa

    def sign_weighted(self, agent_id: str, bytecode: List[int]) -> Tuple[bool, str]:
        """Have an agent sign a weighted multi-sig program."""
        program_hash = self.hash_bytecode(bytecode)
        wa = self.weighted_sigs.get(program_hash)
        if not wa:
            return False, "no weighted sig request for this program"
        if agent_id not in wa.agent_weights:
            return False, f"agent '{agent_id}' not in weight list"

        agent = self.agents.get(agent_id)
        if not agent or not agent.is_active:
            return False, f"agent '{agent_id}' not found or inactive"

        sig = ProgramSignature(
            program_hash=program_hash,
            agent_id=agent_id,
            signature=agent.sign(program_hash.encode()),
        )
        added = wa.add_signature(sig)
        if added:
            return True, f"weight {wa.current_weight}/{wa.required_threshold}"
        return False, f"agent '{agent_id}' already signed"

    def verify_weighted(self, bytecode: List[int]) -> Tuple[SignatureStatus, str]:
        """Verify a weighted multi-signed program."""
        program_hash = self.hash_bytecode(bytecode)
        wa = self.weighted_sigs.get(program_hash)
        if not wa:
            return SignatureStatus.MISSING, "no weighted sig request found"
        if not wa.is_fully_signed:
            return SignatureStatus.INVALID, f"insufficient weight: {wa.current_weight}/{wa.required_threshold}"
        for sig in wa.signatures:
            if sig.is_revoked:
                return SignatureStatus.REVOKED, f"signature by {sig.agent_id} revoked"
            agent = self.agents.get(sig.agent_id)
            if not agent or not agent.verify(program_hash.encode(), sig.signature):
                return SignatureStatus.INVALID, f"invalid signature from {sig.agent_id}"
        return SignatureStatus.VALID, f"verified with weight {wa.current_weight}/{wa.required_threshold}"

    # ── Commit Linking ──

    def link_commit(self, agent_id: str, commit_hash: str, bytecode: List[int],
                    message: str, parent_commits: List[str] = None,
                    metadata: Dict[str, str] = None) -> CommitLink:
        """Link a fleet commit to a signed program."""
        agent = self.agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent '{agent_id}' not found")

        program_hash = self.hash_bytecode(bytecode)
        signature = agent.sign(f"{commit_hash}|{program_hash}".encode())

        link = CommitLink(
            commit_hash=commit_hash,
            agent_id=agent_id,
            program_hash=program_hash,
            signature=signature,
            message=message,
            parent_commits=parent_commits or [],
            metadata=metadata or {},
        )
        self.commit_links[commit_hash] = link
        self._audit(AuditAction.COMMIT_LINKED, agent_id, commit_hash,
                    {"program_hash": program_hash, "message": message})
        return link

    def verify_commit(self, commit_hash: str) -> Tuple[bool, str]:
        """Verify a linked commit's authenticity."""
        link = self.commit_links.get(commit_hash)
        if not link:
            return False, "commit not found"

        agent = self.agents.get(link.agent_id)
        if not agent:
            return False, f"agent {link.agent_id} not found"

        expected = agent.sign(f"{commit_hash}|{link.program_hash}".encode())
        if not hmac.compare_digest(expected, link.signature):
            return False, "signature mismatch: commit may be tampered"

        return True, f"commit verified by {link.agent_id}"

    def get_commit_history(self, commit_hash: str) -> List[CommitLink]:
        """Walk the commit graph from a given commit to roots."""
        history = []
        visited = set()
        queue = [commit_hash]
        while queue:
            ch = queue.pop(0)
            if ch in visited:
                continue
            visited.add(ch)
            link = self.commit_links.get(ch)
            if link:
                history.append(link)
                queue.extend(link.parent_commits)
        return history

    # ── Revocation ──

    def revoke_signature(self, program_hash: str, agent_id: str,
                         revoked_by: str, reason: str = "") -> bool:
        """Revoke a specific agent's signature on a program."""
        sigs = self.signatures.get(program_hash, [])
        target = None
        for sig in sigs:
            if sig.agent_id == agent_id and not sig.is_revoked:
                target = sig
                break

        if not target:
            return False

        target.is_revoked = True
        target.revoked_at = time.time()
        target.revoked_by = revoked_by

        entry = RevocationEntry(
            signature_hash=target.signature,
            program_hash=program_hash,
            agent_id=agent_id,
            revoked_by=revoked_by,
            reason=reason,
        )
        self.revocations[target.signature] = entry
        self._audit(AuditAction.SIGNATURE_REVOKED, revoked_by, program_hash,
                    {"revoked_agent": agent_id, "reason": reason})
        return True

    def get_revocations(self, program_hash: str = None) -> List[RevocationEntry]:
        entries = list(self.revocations.values())
        if program_hash:
            entries = [e for e in entries if e.program_hash == program_hash]
        return entries

    # ── Hash chain ──

    def verify_chain(self) -> Tuple[bool, str]:
        return self.hash_chain.verify_chain()

    def snapshot_chain(self) -> Tuple[int, str]:
        """Create a snapshot of the current chain state."""
        seq, hash_ = self.hash_chain.create_snapshot()
        self._audit(AuditAction.CHAIN_SNAPSHOT, "system", str(seq))
        return seq, hash_

    # ── Serialization ──

    def export_state(self) -> dict:
        """Export everything except the agent secrets.

        An export on its own is a *record*, not a working engine: verification
        is HMAC and needs the secret, which never appears here. Pair it with
        import_state() and the secrets to get a verifiable engine back.
        """
        return {
            "agents": {aid: a.to_dict() for aid, a in self.agents.items()},
            "signatures": {h: [s.to_dict() for s in sigs] for h, sigs in self.signatures.items()},
            "hash_chain": self.hash_chain.to_dict(),
            "revocations": {sh: {
                "signature_hash": e.signature_hash,
                "program_hash": e.program_hash,
                "agent_id": e.agent_id,
                "revoked_by": e.revoked_by,
                "reason": e.reason,
                "timestamp": e.timestamp,
            } for sh, e in self.revocations.items()},
            "multi_sigs": {h: ms.to_dict() for h, ms in self.multi_sigs.items()},
            "weighted_sigs": {h: ws.to_dict() for h, ws in self.weighted_sigs.items()},
            "commit_links": {ch: cl.to_dict() for ch, cl in self.commit_links.items()},
            "audit_log": [e.to_dict() for e in self.audit_log],
            "default_ttl": self.default_ttl,
        }

    def import_state(self, state: dict,
                     agent_secrets: Dict[str, str],
                     agent_history: Optional[Dict[str, Sequence[str]]] = None) -> "SigningEngine":
        """Rebuild an engine from export_state() plus the agent secrets.

        agent_secrets maps agent_id -> current secret, read from wherever the
        fleet keeps secrets; export_state() deliberately never carries them.
        agent_history maps agent_id -> rotated-out secrets in rotation order,
        and is required for any agent that has rotated (see
        AgentIdentity.from_dict) so that pre-rotation signatures keep verifying.

        This is the inverse of export_state(). Without it, an exported signature
        set could never be verified again by this process.
        """
        agent_history = agent_history or {}
        missing = sorted(a for a in state.get("agents", {}) if a not in agent_secrets)
        if missing:
            raise ValueError(
                "no secret supplied for agent(s): " + ", ".join(missing) +
                "; HMAC verification requires the secret, not the fingerprint"
            )

        engine = SigningEngine(default_ttl=state.get("default_ttl"))
        for aid, d in state.get("agents", {}).items():
            engine.agents[aid] = AgentIdentity.from_dict(
                d, agent_secrets[aid], agent_history.get(aid, ())
            )
        engine.signatures = {
            h: [ProgramSignature.from_dict(s) for s in sigs]
            for h, sigs in state.get("signatures", {}).items()
        }
        engine.hash_chain = HashChain.from_dict(state.get("hash_chain", {}))
        engine.revocations = {
            sh: RevocationEntry.from_dict(e) for sh, e in state.get("revocations", {}).items()
        }
        engine.multi_sigs = {
            h: MultiSignature.from_dict(ms) for h, ms in state.get("multi_sigs", {}).items()
        }
        engine.weighted_sigs = {
            h: WeightedApproval.from_dict(ws) for h, ws in state.get("weighted_sigs", {}).items()
        }
        engine.commit_links = {
            ch: CommitLink.from_dict(cl) for ch, cl in state.get("commit_links", {}).items()
        }
        engine.audit_log = [AuditEntry.from_dict(e) for e in state.get("audit_log", [])]
        return engine
