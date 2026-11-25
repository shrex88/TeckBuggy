import { useEffect, useState } from 'react'
import { Check, FileText, Play, RotateCcw, ScanLine, ShieldCheck, Sparkles, WandSparkles } from 'lucide-react'
import { sentinelApi, type FindingRecord, type ProposalRecord, type ScanRecord } from './api'

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '0.6rem 0.8rem',
  borderRadius: '10px',
  border: '1px solid rgba(148, 163, 184, 0.25)',
  background: 'rgba(15, 23, 42, 0.6)',
  color: 'inherit',
  fontSize: '0.9rem',
}

export function NewScanView({ onScanComplete }: { onScanComplete: () => void }) {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000')
  const [profile, setProfile] = useState('Fintech / Payment Application')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ scan_id: number; security_score: number; total_findings: number } | null>(null)

  const handleScan = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await sentinelApi.runScan(targetUrl, profile)
      setResult(res)
      onScanComplete()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2>New Security Scan</h2>
          <p>Authorised local-only assessment (localhost, 127.0.0.1, ::1, allowlisted Docker)</p>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.35rem' }}>Target URL</label>
          <input style={inputStyle} value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} />
        </div>
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.35rem' }}>Application Profile</label>
          <select style={inputStyle} value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option>Fintech / Payment Application</option>
            <option>Customer Portal</option>
            <option>General Web Application</option>
          </select>
        </div>
      </div>
      <button className="button button-primary" onClick={handleScan} disabled={loading}>
        <ScanLine size={16} /> {loading ? 'Scanning target...' : 'Start Security Scan'}
      </button>
      {error && <p style={{ color: '#ff3b5c', marginTop: '0.9rem' }}>{error}</p>}
      {result && (
        <p style={{ color: '#10b981', marginTop: '0.9rem' }}>
          Scan #{result.scan_id} completed — Score: {result.security_score}/100 | Findings: {result.total_findings}
        </p>
      )}
    </div>
  )
}

export function VulnerabilitiesView() {
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [severity, setSeverity] = useState('All')
  const [selected, setSelected] = useState<FindingRecord | null>(null)

  useEffect(() => {
    sentinelApi.getFindings({ severity }).then((d) => {
      setFindings(d.findings)
      setSelected(d.findings[0] ?? null)
    }).catch(() => {})
  }, [severity])

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div className="panel" style={{ padding: '1.25rem' }}>
        <div className="panel-heading">
          <div>
            <h2>Vulnerabilities ({findings.length})</h2>
            <p>Genuine findings persisted in SQLite with OWASP Top 10:2025 mapping</p>
          </div>
          <select style={{ ...inputStyle, width: '180px' }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {['All', 'Critical', 'High', 'Medium', 'Low'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>OWASP 2025</th>
                <th>Path</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 25).map((f) => (
                <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor: 'pointer' }}>
                  <td><b>{f.rule_id}</b></td>
                  <td>{f.title}</td>
                  <td>{f.severity}</td>
                  <td>{f.risk_score}</td>
                  <td>{f.owasp_category}</td>
                  <td><code>{f.target_path}</code></td>
                  <td>{f.finding_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div className="panel" style={{ padding: '1.25rem' }}>
          <h3>{selected.rule_id} · {selected.title}</h3>
          <p style={{ opacity: 0.85, marginTop: '0.5rem' }}>{selected.evidence}</p>
          <p style={{ color: '#00f0ff', marginTop: '0.5rem' }}><b>Remediation:</b> {selected.remediation}</p>
        </div>
      )}
    </div>
  )
}

export function AiCopilotView({ onUpdated }: { onUpdated: () => void }) {
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [findingId, setFindingId] = useState<number>(0)
  const [framework, setFramework] = useState('Flask')
  const [loading, setLoading] = useState(false)
  const [proposal, setProposal] = useState<ProposalRecord | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  useEffect(() => {
    sentinelApi.getFindings().then((d) => {
      setFindings(d.findings)
      if (d.findings.length > 0) setFindingId(d.findings[0].id)
    }).catch(() => {})
  }, [])

  const handleGenerate = async () => {
    if (!findingId) return
    setLoading(true)
    setMsg(null)
    try {
      const p = await sentinelApi.generateProposal(findingId, framework)
      setProposal(p)
      onUpdated()
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Failed to generate proposal')
    } finally {
      setLoading(false)
    }
  }

  const handleApprove = async () => {
    if (!proposal) return
    await sentinelApi.decideProposal(proposal.id, 'Approved')
    setProposal({ ...proposal, approval_status: 'Approved' })
    setMsg(`Proposal #${proposal.id} approved!`)
    onUpdated()
  }

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2><Sparkles size={18} /> AI Remediation Copilot</h2>
          <p>Generate structured Gemini AI remediation proposals with deterministic fallback</p>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        <select style={inputStyle} value={findingId} onChange={(e) => setFindingId(Number(e.target.value))}>
          {findings.map((f) => (
            <option key={f.id} value={f.id}>
              #{f.id} · [{f.severity}] {f.rule_id} — {f.title}
            </option>
          ))}
        </select>
        <select style={inputStyle} value={framework} onChange={(e) => setFramework(e.target.value)}>
          {['Flask', 'Django', 'Apache', 'Nginx', 'Express'].map((fw) => (
            <option key={fw}>{fw}</option>
          ))}
        </select>
      </div>
      <button className="button button-primary" onClick={handleGenerate} disabled={loading || !findingId}>
        <WandSparkles size={16} /> {loading ? 'Generating AI Fix...' : 'Generate AI Fix'}
      </button>
      {msg && <p style={{ color: '#10b981', marginTop: '0.75rem' }}>{msg}</p>}
      {proposal && (
        <div style={{ marginTop: '1.25rem', display: 'grid', gap: '0.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>Proposal #{proposal.id} · Action: <code>{proposal.action_id}</code> ({proposal.source})</strong>
            <span className="preview-label">{proposal.approval_status}</span>
          </div>
          <p><b>Explanation:</b> {proposal.technical_explanation}</p>
          <p><b>Recommended Fix:</b> {proposal.recommended_correction}</p>
          <pre style={{ padding: '0.85rem', borderRadius: '10px', background: 'rgba(2,6,23,0.75)', overflowX: 'auto' }}>
            {proposal.secure_code_example}
          </pre>
          {proposal.approval_status === 'Pending Review' && (
            <button className="button button-primary" onClick={handleApprove}>
              <Check size={16} /> Approve Proposal
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export function ApprovalCentreView({ onUpdated }: { onUpdated: () => void }) {
  const [proposals, setProposals] = useState<ProposalRecord[]>([])
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000')
  const [feedback, setFeedback] = useState<string | null>(null)

  const reload = () => {
    sentinelApi.getProposals().then((d) => setProposals(d.proposals)).catch(() => {})
  }
  useEffect(reload, [])

  const runAction = async (fn: () => Promise<unknown>) => {
    setFeedback(null)
    try {
      await fn()
      reload()
      onUpdated()
    } catch (e) {
      setFeedback(e instanceof Error ? e.message : 'Action failed')
    }
  }

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2>Developer Approval Centre</h2>
          <p>Human-in-the-loop governance for authorised local applications</p>
        </div>
      </div>
      <div style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '0.35rem' }}>Authorised Local Target URL</label>
        <input style={inputStyle} value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} />
      </div>
      {feedback && <p style={{ color: '#f5c542', marginBottom: '1rem' }}>{feedback}</p>}
      <div style={{ display: 'grid', gap: '0.9rem' }}>
        {proposals.map((p) => (
          <div key={p.id} className="panel" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
              <strong>#{p.id} · {p.rule_id} — {p.finding_title}</strong>
              <span className="preview-label">{p.approval_status}</span>
            </div>
            <p style={{ fontSize: '0.85rem', opacity: 0.85, marginBottom: '0.6rem' }}>{p.recommended_correction}</p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button className="button" onClick={() => runAction(() => sentinelApi.decideProposal(p.id, 'Approved'))}>Approve</button>
              <button className="button" onClick={() => runAction(() => sentinelApi.decideProposal(p.id, 'Rejected'))}>Reject</button>
              <button className="button button-primary" onClick={() => runAction(() => sentinelApi.applyProposal(p.id, targetUrl))}>Apply Approved Fix</button>
              {p.approval_status === 'Approved' && (
                <button className="button" onClick={() => runAction(() => sentinelApi.decideProposal(p.id, 'Verification Pending'))}>
                  Mark Applied Manually
                </button>
              )}
              {(p.approval_status === 'Verification Pending' || p.approval_status === 'Verification Failed') && (
                <button className="button" onClick={() => runAction(() => sentinelApi.verifyProposal(p.id, targetUrl))}>
                  <Play size={14} /> Verify Fix
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export function ConfidenceView() {
  const [proposals, setProposals] = useState<ProposalRecord[]>([])
  const [selectedId, setSelectedId] = useState<number>(0)
  const [evalRes, setEvalRes] = useState<Awaited<ReturnType<typeof sentinelApi.evaluateProposal>> | null>(null)

  useEffect(() => {
    sentinelApi.getProposals().then((d) => {
      setProposals(d.proposals)
      if (d.proposals.length > 0) setSelectedId(d.proposals[0].id)
    }).catch(() => {})
  }, [])

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2>Remediation Confidence Engine</h2>
          <p>Deterministic validation, application safety, and 7-factor confidence scoring</p>
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
        <select style={inputStyle} value={selectedId} onChange={(e) => setSelectedId(Number(e.target.value))}>
          {proposals.map((p) => (
            <option key={p.id} value={p.id}>Proposal #{p.id} · {p.rule_id} ({p.action_id})</option>
          ))}
        </select>
        <button
          className="button button-primary"
          disabled={!selectedId}
          onClick={() => sentinelApi.evaluateProposal(selectedId).then(setEvalRes)}
        >
          Evaluate
        </button>
      </div>
      {evalRes && (
        <div style={{ display: 'grid', gap: '0.75rem' }}>
          <p>
            <b>Confidence:</b> {evalRes.confidence_score}/100 ({evalRes.confidence_level}) ·{' '}
            <b>Safety:</b> {evalRes.application_safety} · <b>Verification:</b> {evalRes.verification_status}
          </p>
          <p style={{ opacity: 0.85 }}>{evalRes.explanation}</p>
        </div>
      )}
    </div>
  )
}

export function SecurityProofView() {
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [baseId, setBaseId] = useState<number>(0)
  const [followId, setFollowId] = useState<number>(0)
  const [proof, setProof] = useState<Awaited<ReturnType<typeof sentinelApi.runSecurityProof>> | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    sentinelApi.getScans().then((d) => {
      setScans(d.scans)
      if (d.scans.length >= 2) {
        setFollowId(d.scans[0].id)
        setBaseId(d.scans[1].id)
      }
    }).catch(() => {})
  }, [])

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2><ShieldCheck size={18} /> Security Proof</h2>
          <p>Before-and-after verification using genuine completed scans</p>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
        <select style={inputStyle} value={baseId} onChange={(e) => setBaseId(Number(e.target.value))}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>Baseline #{s.id} · {s.target_url} ({s.security_score}/100)</option>
          ))}
        </select>
        <select style={inputStyle} value={followId} onChange={(e) => setFollowId(Number(e.target.value))}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>Follow-Up #{s.id} · {s.target_url} ({s.security_score}/100)</option>
          ))}
        </select>
      </div>
      <button
        className="button button-primary"
        disabled={scans.length < 2}
        onClick={() => {
          setErr(null)
          sentinelApi.runSecurityProof(baseId, followId).then(setProof).catch((e) => setErr(e.message))
        }}
      >
        Verify Security Proof
      </button>
      {err && <p style={{ color: '#ff3b5c', marginTop: '0.75rem' }}>{err}</p>}
      {proof && (
        <div style={{ marginTop: '1rem' }}>
          <p>
            <b>Original Score:</b> {proof.original_security_score}/100 → <b>Updated Score:</b> {proof.updated_security_score}/100 ·{' '}
            <b>Fixed:</b> {proof.fixed_vulnerabilities.length} · <b>Improvement:</b> {proof.percentage_improvement}%
          </p>
        </div>
      )}
    </div>
  )
}

export function ScanHistoryView() {
  const [scans, setScans] = useState<ScanRecord[]>([])
  useEffect(() => {
    sentinelApi.getScans().then((d) => setScans(d.scans)).catch(() => {})
  }, [])
  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2>Scan History ({scans.length})</h2>
          <p>Chronological audit ledger persisted in SQLite</p>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>ID</th><th>Target</th><th>Date</th><th>Score</th><th>Findings</th><th>Status</th></tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>#{s.id}</td><td><b>{s.target_url}</b></td><td>{s.scan_date}</td>
                <td>{s.security_score ?? '—'}</td><td>{s.total_findings}</td><td>{s.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export function ReportsView() {
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [reports, setReports] = useState<Array<{ id: number; scan_id: number; generated_at: string; report_path: string }>>([])
  const [scanId, setScanId] = useState<number>(0)

  const reload = () => {
    sentinelApi.getScans().then((d) => {
      setScans(d.scans)
      if (d.scans.length > 0 && !scanId) setScanId(d.scans[0].id)
    }).catch(() => {})
    sentinelApi.getReports().then((d) => setReports(d.reports)).catch(() => {})
  }
  useEffect(reload, [])

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2><FileText size={18} /> Evidence-Based PDF Reports</h2>
          <p>Generate and download 16-section branded PDF reports from SQLite</p>
        </div>
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
        <select style={inputStyle} value={scanId} onChange={(e) => setScanId(Number(e.target.value))}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>Scan #{s.id} · {s.target_url} ({s.security_score}/100)</option>
          ))}
        </select>
        <button className="button button-primary" disabled={!scanId} onClick={() => sentinelApi.generatePdf(scanId).then(reload)}>
          Generate PDF
        </button>
      </div>
      <div style={{ display: 'grid', gap: '0.5rem' }}>
        {reports.map((r) => (
          <div key={r.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Report #{r.id} · Scan #{r.scan_id} ({r.generated_at})</span>
            <a className="button" href={`/api/reports/${r.id}/download`} target="_blank" rel="noreferrer">
              Download PDF
            </a>
          </div>
        ))}
      </div>
    </div>
  )
}

export function AuditHistoryView() {
  const [data, setData] = useState<Awaited<ReturnType<typeof sentinelApi.getAudit>> | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const reload = () => { sentinelApi.getAudit().then(setData).catch(() => {}) }
  useEffect(reload, [])

  const handleRollback = async (backupUid: string) => {
    setMsg(null)
    try {
      const res = await sentinelApi.rollbackBackup(backupUid)
      setMsg(`Rolled back ${res.setting_key} to ${res.restored_value}`)
      reload()
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Rollback failed')
    }
  }

  return (
    <div className="panel" style={{ padding: '1.5rem' }}>
      <div className="panel-heading">
        <div>
          <h2><RotateCcw size={18} /> Remediation History & Audit Trail</h2>
          <p>Configuration backups, rollback controls, and governance audit log</p>
        </div>
      </div>
      {msg && <p style={{ color: '#10b981', marginBottom: '0.75rem' }}>{msg}</p>}
      {data && data.backups.length > 0 && (
        <div style={{ marginBottom: '1rem', display: 'grid', gap: '0.5rem' }}>
          <strong>Configuration Backups</strong>
          {data.backups.map((b) => (
            <div key={b.backup_uid} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0', borderBottom: '1px solid rgba(148,163,184,0.12)' }}>
              <span><code>{b.backup_uid}</code> · {b.setting_key}: {b.original_value} → {b.applied_value}</span>
              <button className="button" onClick={() => void handleRollback(b.backup_uid)}>Rollback</button>
            </div>
          ))}
        </div>
      )}
      {data && data.audit_logs.slice(0, 15).map((a) => (
        <div key={a.id} style={{ padding: '0.5rem 0', borderBottom: '1px solid rgba(148,163,184,0.12)' }}>
          <b>[{a.status}]</b> {a.event_type} · {a.details} <small style={{ opacity: 0.7 }}>({a.created_at})</small>
        </div>
      ))}
    </div>
  )
}
