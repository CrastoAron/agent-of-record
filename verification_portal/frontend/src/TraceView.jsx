const symbolFor = (link) => link.passed ? "✓" : "×";

export default function TraceView({ trace }) {
  return (
    <section className="trace" aria-live="polite">
      <div className={`banner ${trace.overall_valid ? "verified" : "invalid"}`}>
        {trace.overall_valid ? "VERIFIED" : "TAMPERED / INVALID"}
      </div>
      {trace.action_id && <p className="action-id">Action ID: <code>{trace.action_id}</code></p>}
      <div className="trace-table">
        {trace.links.map((link) => (
          <article key={link.link_name} className={`trace-row ${link.passed ? "pass" : "fail"}`}>
            <span className="symbol" aria-label={link.passed ? "passed" : "failed"}>{symbolFor(link)}</span>
            <div><strong>{link.link_name.replaceAll("_", " ")}</strong><p>{link.detail}</p></div>
            <span className="status">{link.status}</span>
          </article>
        ))}
      </div>
    </section>
  );
}
