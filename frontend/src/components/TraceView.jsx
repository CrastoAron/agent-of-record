import MerkleTreeView from "./MerkleTreeView";

const symbolFor = (link) => (link.passed ? "✓" : link.status === "unavailable" ? "—" : "×");

export default function TraceView({ trace }) {
  const hasFailedChecks = trace.links.some((link) => link.status === "failed");
  const hasUnavailableChecks = trace.links.some((link) => link.status === "unavailable");
  const incomplete = !trace.overall_valid && !hasFailedChecks && hasUnavailableChecks;
  const bannerClass = trace.overall_valid ? "verified" : incomplete ? "incomplete" : "invalid";
  const bannerText = trace.overall_valid
    ? "✓ VERIFIED"
    : incomplete
      ? "! VERIFICATION INCOMPLETE"
      : "⚠ VERIFICATION FAILED";

  return (
    <section className="trace" aria-live="polite">
      <div className={`banner ${bannerClass}`}>{bannerText}</div>
      {trace.action_id && (
        <p className="action-id">
          Action ID: <code>{trace.action_id}</code>
        </p>
      )}
      <div className="trace-table">
        {trace.links.map((link) => (
          <article
            key={link.link_name}
            className={`trace-row ${link.passed ? "pass" : link.status === "unavailable" ? "unavailable" : "fail"}`}
          >
            <span className="symbol" aria-label={link.passed ? "passed" : link.status}>
              {symbolFor(link)}
            </span>
            <div className="trace-row-content">
              <strong>{link.link_name.replaceAll("_", " ")}</strong>
              <p>{link.detail}</p>
            </div>
            <span className={`status-badge ${link.passed ? "pass" : link.status === "unavailable" ? "unavailable" : "fail"}`}>
              {link.status}
            </span>
          </article>
        ))}
      </div>
      <MerkleTreeView tree={trace.merkle_tree} />
    </section>
  );
}
