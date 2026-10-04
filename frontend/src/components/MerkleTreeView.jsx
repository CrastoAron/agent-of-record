function shortHash(hash) {
  if (!hash) return "—";
  return `${hash.slice(0, 10)}…${hash.slice(-8)}`;
}

function rootStatus(tree) {
  if (tree.root_matches_signed === true) return { className: "pass", label: "Signed root matches" };
  if (tree.root_matches_signed === false) return { className: "fail", label: "Signed root mismatch" };
  return { className: "pending", label: "Signed root unavailable" };
}

export default function MerkleTreeView({ tree }) {
  if (!tree?.levels?.length) return null;

  const status = rootStatus(tree);
  const levels = [...tree.levels].reverse();

  return (
    <section className="merkle-view" aria-label="Merkle tree visualization">
      <div className="merkle-view-header">
        <div>
          <p className="eyebrow">Context integrity</p>
          <h2>Merkle Tree</h2>
          <p className="merkle-description">
            Recomputed from the captured ledger at verification time. Leaf content stays private; only committed hashes are shown.
          </p>
        </div>
        <span className={`status-badge ${status.className}`}>{status.label}</span>
      </div>

      <div className="merkle-summary">
        <div>
          <span className="merkle-summary-label">Leaves</span>
          <strong>{tree.leaf_count}</strong>
        </div>
        <div>
          <span className="merkle-summary-label">Proof</span>
          <strong>
            {tree.proof_valid === true ? `✓ Entry #${tree.proof_entry_id}` : tree.proof_valid === false ? "× Invalid" : "—"}
          </strong>
        </div>
        <div className="merkle-root-summary">
          <span className="merkle-summary-label">Computed root</span>
          <code title={tree.root}>{shortHash(tree.root)}</code>
        </div>
      </div>

      <div className="merkle-tree-scroll">
        <div className="merkle-levels">
          {levels.map((level) => (
            <div className="merkle-level" key={level.level}>
              <div className="merkle-level-label">{level.label}</div>
              <div className="merkle-nodes">
                {level.nodes.map((node, index) => (
                  <article
                    className={`merkle-node ${level.label === "Root" ? "root" : ""} ${node.duplicated ? "duplicated" : ""}`}
                    key={`${level.level}-${index}-${node.hash}`}
                    title={node.hash}
                  >
                    <div className="merkle-node-topline">
                      <span>{level.label === "Leaves" ? `Entry #${node.entry_id}` : level.label}</span>
                      {node.duplicated && <small>duplicated</small>}
                    </div>
                    <code>{shortHash(node.hash)}</code>
                  </article>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {tree.signed_root && (
        <p className={`merkle-signed-root ${status.className}`}>
          Signed PoI root: <code title={tree.signed_root}>{shortHash(tree.signed_root)}</code>
        </p>
      )}
    </section>
  );
}
