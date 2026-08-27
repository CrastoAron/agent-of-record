import { useState } from "react";
import TraceView from "./TraceView";

const API_BASE = import.meta.env.VITE_PORTAL_API_URL ?? "http://127.0.0.1:8001";

export default function App() {
  const [file, setFile] = useState(null);
  const [actionId, setActionId] = useState("");
  const [trace, setTrace] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function verify(event) {
    event.preventDefault();
    if (!file && !actionId.trim()) {
      setError("Choose an .eml file or enter an action ID.");
      return;
    }
    setBusy(true); setError(""); setTrace(null);
    try {
      let response;
      if (file) {
        const form = new FormData(); form.append("file", file);
        response = await fetch(`${API_BASE}/verify`, { method: "POST", body: form });
      } else {
        response = await fetch(`${API_BASE}/verify`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action_id: actionId.trim() }) });
      }
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Verification request failed");
      setTrace(data);
    } catch (requestError) { setError(requestError.message); }
    finally { setBusy(false); }
  }

  return <main>
    <h1>Agent-of-Record Verification Portal</h1>
    <p className="intro">Verify the signed chain from user intent through the executed action.</p>
    <form onSubmit={verify}>
      <label>Upload a Stage 7 <code>.eml</code> artifact<input type="file" accept=".eml,message/rfc822" onChange={(event) => { setFile(event.target.files?.[0] ?? null); if (event.target.files?.[0]) setActionId(""); }} /></label>
      <div className="or">or</div>
      <label>Action ID<input value={actionId} placeholder="&lt;...@aor.local&gt;" onChange={(event) => { setActionId(event.target.value); if (event.target.value) setFile(null); }} /></label>
      <button disabled={busy}>{busy ? "Verifying…" : "Verify"}</button>
    </form>
    {error && <p className="error">{error}</p>}
    {trace && <TraceView trace={trace} />}
  </main>;
}
