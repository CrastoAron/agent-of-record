import pytest

from ledger_core import Ledger, build_merkle_tree, verify_merkle_proof


def _ledger_with_entries(count: int) -> Ledger:
    ledger = Ledger()
    for index in range(count):
        ledger.append("context", {"message": f"message {index}"})
    return ledger


def test_merkle_root_changes_when_content_changes() -> None:
    original = _ledger_with_entries(3)
    modified = Ledger()
    modified.append("context", {"message": "message 0"})
    modified.append("context", {"message": "changed message"})
    modified.append("context", {"message": "message 2"})

    assert build_merkle_tree(original.all_entries()).root() != build_merkle_tree(
        modified.all_entries()
    ).root()


def test_inclusion_proof_verifies_against_its_root() -> None:
    ledger = _ledger_with_entries(5)
    tree = build_merkle_tree(ledger.all_entries())
    entry = ledger.get_entry(3)

    assert verify_merkle_proof(entry.leaf_hash, tree.get_proof(entry.entry_id), tree.root())


def test_proof_fails_for_tampered_leaf_proof_or_root() -> None:
    ledger = _ledger_with_entries(4)
    tree = build_merkle_tree(ledger.all_entries())
    entry = ledger.get_entry(2)
    proof = tree.get_proof(entry.entry_id)

    altered_leaf = bytes([entry.leaf_hash[0] ^ 1]) + entry.leaf_hash[1:]
    altered_proof = proof.copy()
    altered_proof[0] = altered_proof[0][:-1] + bytes([altered_proof[0][-1] ^ 1])
    wrong_root = bytes([tree.root()[0] ^ 1]) + tree.root()[1:]

    assert not verify_merkle_proof(altered_leaf, proof, tree.root())
    assert not verify_merkle_proof(entry.leaf_hash, altered_proof, tree.root())
    assert not verify_merkle_proof(entry.leaf_hash, proof, wrong_root)


@pytest.mark.parametrize("count", [1, 3, 5])
def test_single_and_odd_sized_ledgers_build_valid_trees(count: int) -> None:
    ledger = _ledger_with_entries(count)
    tree = build_merkle_tree(ledger.all_entries())

    assert len(tree.root()) == 32
    for entry in ledger.all_entries():
        assert verify_merkle_proof(entry.leaf_hash, tree.get_proof(entry.entry_id), tree.root())


def test_empty_tree_is_rejected() -> None:
    with pytest.raises(ValueError, match="no entries"):
        build_merkle_tree([])
