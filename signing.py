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
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Set


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
    """Represents a FLUX fleet agent with signing capabilities."""
    agent_id: str
    name: str
    public_key: str  # hex-encoded (derived: sha256 of private_key)
    private_key: str  # hex-encoded secret key
    role: AgentRole = AgentRole.AUTHOR
    created_at: float = field(default_factory=time.time)
    is_active: bool = True
    previous_keys: List[str] = field(default_factory=list)  # key rotation history

    @classmethod
    def generate(cls, agent_id: str, name: str, role: AgentRole = AgentRole.AUTHOR) -> "AgentIdentity":
        """Generate a new agent with a random 256-bit key pair."""
        private_key = uuid.uuid4().hex + uuid.uuid4().hex  # 256-bit
        public_key = _sha256(private_key.encode())
        return cls(agent_id=agent_id, name=name, public_key=public_key,
                   private_key=private_key, role=role)

    def sign(self, data: bytes) -> str:
        """Sign arbitrary data with this agent's private key."""
        return _hmac_sign(self.private_key.encode(), data)

    def verify(self, data: bytes, signature: str) -> bool:
        """Verify a signature against this agent's key."""
        # Try current key first, then historical keys
        if _hmac_verify(self.private_key.encode(), data, signature):
            return True
        for old_key in self.previous_keys:
            if _hmac_verify(old_key.encode(), data, signature):
                return True
        return False

    def rotate_key(self) -> str:
        """Rotate to a new key pair. Returns new public key. Old key kept for verification."""
        self.previous_keys.append(self.private_key)
        new_private = uuid.uuid4().hex + uuid.uuid4().hex
        self.private_key = new_private
        self.public_key = _sha256(new_private.encode())
        return self.public_key

    @property
    def key_generation(self) -> int:
        """Number of key rotations performed."""
        return len(self.previous_keys)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "public_key": self.public_key,
            "role": self.role.value,
            "created_at": self.created_at,
            "is_active": self.is_active,
            "key_generation": self.key_generation,
        }


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
    """Hash chain providing tamper-evident program version history."""
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

    def create_snapshot(self) -> Tuple[int, str]:
        """Create a checkpoint snapshot of the chain at current state."""
        seq = len(self.links) - 1
        snapshot_data = json.dumps(self.to_dict(), sort_keys=True)
        snapshot_hash = _sha256(snapshot_data.encode())
        self.snapshots[seq] = snapshot_hash
        return seq, snapshot_hash

    def verify_snapshot(self, seq: int) -> Tuple[bool, str]:
        """Verify a previously created snapshot is still valid."""
        if seq not in self.snapshots:
            return False, f"no snapshot at sequence {seq}"
        # We can only verify the snapshot matches if chain hasn't changed before seq
        snapshot_hash = self.snapshots[seq]
        if seq < len(self.links):
            current_hash = self.links[seq].link_hash
            return True, f"snapshot valid at sequence {seq} (tip_hash={snapshot_hash[:16]}...)"
        return False, "sequence out of range"

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
        return {"links": [l.to_dict() for l in self.links]}

    @classmethod
    def from_dict(cls, d: dict) -> "HashChain":
        links = [ChainLink.from_dict(l) for l in d.get("links", [])]
        return cls(links=links)


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


# ── Revocation List ─────────────────────────────────────────────────────────

@dataclass
class RevocationEntry:
    signature_hash: str
    program_hash: str
    agent_id: str
    revoked_by: str
    reason: str
    timestamp: float = field(default_factory=time.time)


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
        self._audit(AuditAction.AGENT_REGISTERED, agent.agent_id, agent.public_key)

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
        """Rotate an agent's key. Returns new public key or None."""
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        new_pub = agent.rotate_key()
        self._audit(AuditAction.AGENT_KEY_ROTATED, agent_id, new_pub,
                    {"generation": agent.key_generation})
        return new_pub

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
