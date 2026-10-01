import { useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Modal, Spinner, useUi } from "./ui";
import { VersionResult, type Version } from "./Pipeline";

/** Runs validate/apply requests and shows the pipeline result in a modal. */
export function useConfigAction() {
  const qc = useQueryClient();
  const { apiError } = useUi();
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Version | null>(null);
  const run = async (label: string, fn: () => Promise<any>, pick: (r: any) => Version | null = (r) => r.data) => {
    setBusy(label);
    try {
      const r = await fn();
      const v = pick(r);
      if (v) setResult(v);
      qc.invalidateQueries();
      return r;
    } catch (e) { apiError(e, `${label} failed`); } finally { setBusy(null); }
  };
  const node: ReactNode = <>
    {busy && (
      <Modal title={busy} onClose={() => { /* running */ }}>
        <div className="stack"><Spinner label="Generating configuration, validating with Nagios, backing up and reloading. This can take up to a minute..." /></div>
      </Modal>
    )}
    {result && <Modal title="Configuration result" size="wide" onClose={() => setResult(null)} footer={<button className="btn primary" onClick={() => setResult(null)}>Close</button>}><VersionResult v={result} /></Modal>}
  </>;
  return {
    busy, node, run,
    validateAll: () => run("Validate configuration", () => api.post("/api/config/validate")),
    applyAll: () => run("Apply configuration", () => api.post("/api/config/apply")),
  };
}
