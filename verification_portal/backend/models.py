"""Presentation-safe verification results for the AoR portal."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LinkResult(BaseModel):
    """The outcome of one independently checkable link in an AoR action."""

    link_name: str
    passed: bool
    detail: str
    # ``pending`` is deliberately not a failure: Stage 9 anchors periodically.
    status: str = "passed"


class MerkleNodeView(BaseModel):
    """A presentation-safe Merkle node; content is never included."""

    hash: str
    entry_id: int | None = None
    duplicated: bool = False


class MerkleLevelView(BaseModel):
    """One level of a Merkle tree, ordered from left to right."""

    level: int
    label: str
    nodes: list[MerkleNodeView] = Field(default_factory=list)


class MerkleTreeView(BaseModel):
    """The recomputed tree data needed by the portal's tree visualization."""

    root: str
    signed_root: str | None = None
    root_matches_signed: bool | None = None
    leaf_count: int
    proof_entry_id: int | None = None
    proof_valid: bool | None = None
    levels: list[MerkleLevelView] = Field(default_factory=list)


class VerificationTrace(BaseModel):
    """A complete, forensic trace returned even when individual checks fail."""

    action_id: str | None = None
    overall_valid: bool
    links: list[LinkResult] = Field(default_factory=list)
    timestamp_verified: bool = False
    merkle_tree: MerkleTreeView | None = None
