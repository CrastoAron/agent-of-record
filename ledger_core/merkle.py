"""Ordered SHA3-256 Merkle trees for AoR ledger entries."""

from __future__ import annotations

from dataclasses import dataclass

from crypto_core.hashing import hash_sha3_256

from .ledger import LedgerEntry

_LEFT_SIBLING = b"\x00"
_RIGHT_SIBLING = b"\x01"
_HASH_SIZE = 32


def _parent_hash(left: bytes, right: bytes) -> bytes:
    """Hash an ordered pair of child hashes using the Stage 1 SHA3 helper."""
    return hash_sha3_256(left + right)


@dataclass
class MerkleTree:
    """A Merkle tree built from ledger leaf hashes.

    For an odd-sized level, the last hash is duplicated before computing its
    parent. Proof items are 33 bytes: a direction marker (``0x00`` means the
    sibling is left, ``0x01`` means it is right) followed by the 32-byte sibling
    hash. The marker lets a verifier reconstruct ordered parent hashes without
    needing the source tree or entry position.
    """

    _levels: list[list[bytes]]
    _entry_positions: dict[int, int]

    def root(self) -> bytes:
        """Return the current Merkle root."""
        return self._levels[-1][0]

    def get_proof(self, entry_id: int) -> list[bytes]:
        """Return an ordered inclusion proof for the supplied ledger entry."""
        try:
            index = self._entry_positions[entry_id]
        except KeyError as exc:
            raise KeyError(f"entry_id {entry_id} is not in this tree") from exc

        proof: list[bytes] = []
        for level in self._levels[:-1]:
            if index % 2 == 0:
                # Odd levels duplicate their final hash as the right sibling.
                sibling_index = index + 1 if index + 1 < len(level) else index
                direction = _RIGHT_SIBLING
            else:
                sibling_index = index - 1
                direction = _LEFT_SIBLING
            proof.append(direction + level[sibling_index])
            index //= 2
        return proof


def build_merkle_tree(entries: list[LedgerEntry]) -> MerkleTree:
    """Build an ordered Merkle tree from ledger entries.

    The leaf hash stored in each entry is used directly. At every level with an
    odd number of nodes, its final node is duplicated before parent construction.
    At least one entry is required because an empty ledger has no inclusion root.
    """
    if not entries:
        raise ValueError("cannot build a Merkle tree with no entries")

    entry_positions: dict[int, int] = {}
    leaves: list[bytes] = []
    for position, entry in enumerate(entries):
        if entry.entry_id in entry_positions:
            raise ValueError(f"duplicate entry_id: {entry.entry_id}")
        if len(entry.leaf_hash) != _HASH_SIZE:
            raise ValueError("each entry leaf_hash must be a 32-byte SHA3-256 digest")
        entry_positions[entry.entry_id] = position
        leaves.append(entry.leaf_hash)

    levels = [leaves]
    current_level = leaves
    while len(current_level) > 1:
        padded_level = (
            current_level if len(current_level) % 2 == 0 else current_level + [current_level[-1]]
        )
        next_level = [
            _parent_hash(padded_level[index], padded_level[index + 1])
            for index in range(0, len(padded_level), 2)
        ]
        levels.append(next_level)
        current_level = next_level

    return MerkleTree(_levels=levels, _entry_positions=entry_positions)


def verify_merkle_proof(leaf_hash: bytes, proof: list[bytes], root: bytes) -> bool:
    """Verify an ordered Merkle inclusion proof without access to the tree."""
    if len(leaf_hash) != _HASH_SIZE or len(root) != _HASH_SIZE:
        return False

    current_hash = leaf_hash
    for proof_item in proof:
        if len(proof_item) != _HASH_SIZE + 1:
            return False
        direction, sibling_hash = proof_item[:1], proof_item[1:]
        if direction == _LEFT_SIBLING:
            current_hash = _parent_hash(sibling_hash, current_hash)
        elif direction == _RIGHT_SIBLING:
            current_hash = _parent_hash(current_hash, sibling_hash)
        else:
            return False
    return current_hash == root
