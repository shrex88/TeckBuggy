export interface DashboardSnapshot {
  has_scans: boolean
  total_scans: number
  overall_security_score: number | null
  total_vulnerabilities: number
  critical_findings: number
  high_findings: number
  severity_counts: Record<string, number>
  owasp_counts: Record<string, number>
  recent_scans: Array<{
    id: number
    target_url: string
    scan_date: string
    security_score: number | null
    total_findings: number
    status: string
  }>
  priority_findings: Array<{
    id: number
    rule_id: string
    title: string
    target_path: string
    severity: string
    risk_score: number
    owasp_category: string
    finding_status: string
  }>
  security_alerts: Array<{
    id: number
    title: string
    severity: string
    target_path: string
    risk_score: number
    status: string
  }>
  total_reports: number
  gemini_configured?: boolean
}

export interface ScanRecord {
  id: number
  target_url: string
  scan_date: string
  security_score: number | null
  total_findings: number
  critical_findings?: number
  status: string
}

export interface FindingRecord {
  id: number
  scan_id: number
  rule_id: string
  target_path: string
  title: string
  severity: string
  risk_score: number
  evidence: string
  owasp_category: string
  remediation: string
  finding_status: string
}

export interface ProposalRecord {
  id: number
  finding_id: number
  rule_id: string
  finding_title: string
  severity: string
  risk_score: number
  target_path: string
  action_id: string
  source: string
  framework: string
  technical_explanation: string
  security_impact: string
  root_cause: string
  recommended_correction: string
  original_config: string
  corrected_config: string
  secure_code_example: string
  verification_instructions: string
  remediation_priority: string
  approval_status: string
  created_at: string
  gemini_status?: string
}

async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    ...init,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`)
  }
  return data as T
}

export const sentinelApi = {
  getHealth: () =>
    apiJson<{ status: string; gemini_configured: boolean; gemini_status: string; profiles: string[] }>('/api/health'),
  getDashboard: () => apiJson<DashboardSnapshot>('/api/dashboard'),
  getScans: () => apiJson<{ scans: ScanRecord[] }>('/api/scans'),
  runScan: (target_url: string, application_profile: string) =>
    apiJson<{ scan_id: number; target_url: string; security_score: number; total_findings: number }>('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ target_url, application_profile }),
    }),
  getFindings: (params?: { scan_id?: number; severity?: string }) => {
    const q = new URLSearchParams()
    if (params?.scan_id) q.set('scan_id', String(params.scan_id))
    if (params?.severity && params.severity !== 'All') q.set('severity', params.severity)
    const qs = q.toString()
    return apiJson<{ findings: FindingRecord[] }>(`/api/findings${qs ? `?${qs}` : ''}`)
  },
  getProposals: () => apiJson<{ proposals: ProposalRecord[] }>('/api/proposals'),
  generateProposal: (finding_id: number, framework: string) =>
    apiJson<ProposalRecord>('/api/proposals/generate', {
      method: 'POST',
      body: JSON.stringify({ finding_id, framework }),
    }),
  decideProposal: (proposalId: number, decision: string, notes = '') =>
    apiJson<{ proposal_id: number; approval_status: string }>(`/api/proposals/${proposalId}/decision`, {
      method: 'POST',
      body: JSON.stringify({ decision, notes }),
    }),
  evaluateProposal: (proposalId: number) =>
    apiJson<{
      evaluation_id: number
      confidence_score: number
      confidence_level: string
      application_safety: string
      verification_status: string
      factors: Array<{ factor_name: string; raw_score: number; weight: number; weighted_score: number }>
      validation_checks: Array<{ check_name: string; passed: boolean; details: string }>
      explanation: string
    }>(`/api/proposals/${proposalId}/evaluate`, { method: 'POST' }),
  applyProposal: (proposalId: number, target_url: string) =>
    apiJson<{ action_id: string; backup_uid: string; approval_status: string }>(
      `/api/proposals/${proposalId}/apply`,
      { method: 'POST', body: JSON.stringify({ target_url }) },
    ),
  verifyProposal: (proposalId: number, target_url: string) =>
    apiJson<{ verified: boolean; approval_status: string; followup_scan_id: number }>(
      `/api/proposals/${proposalId}/verify`,
      { method: 'POST', body: JSON.stringify({ target_url }) },
    ),
  runSecurityProof: (baseline_scan_id: number, followup_scan_id: number) =>
    apiJson<{
      original_security_score: number
      updated_security_score: number
      risk_reduction: number
      percentage_improvement: number
      fixed_vulnerabilities: FindingRecord[]
      remaining_vulnerabilities: FindingRecord[]
    }>('/api/security-proof', {
      method: 'POST',
      body: JSON.stringify({ baseline_scan_id, followup_scan_id }),
    }),
  runRegressionCheck: (baseline_scan_id: number, latest_scan_id: number) =>
    apiJson<{
      score_delta: number
      returning_fixed_vulnerabilities: Array<{ rule_id: string; title: string; severity: string }>
      newly_introduced_vulnerabilities: Array<{ rule_id: string; title: string; severity: string }>
      alerts_generated: number
    }>('/api/regression-guard', {
      method: 'POST',
      body: JSON.stringify({ baseline_scan_id, latest_scan_id }),
    }),
  getAudit: () =>
    apiJson<{
      audit_logs: Array<{ id: number; event_type: string; action_id: string; status: string; details: string; created_at: string }>
      backups: Array<{ backup_uid: string; action_id: string; setting_key: string; original_value: string; applied_value: string }>
    }>('/api/audit'),
  rollbackBackup: (backup_uid: string) =>
    apiJson<{ setting_key: string; restored_value: string; restored_verified: boolean }>('/api/rollback', {
      method: 'POST',
      body: JSON.stringify({ backup_uid }),
    }),
  getReports: () =>
    apiJson<{ reports: Array<{ id: number; scan_id: number; generated_at: string; report_path: string }> }>('/api/reports'),
  generatePdf: (scanId: number) =>
    apiJson<{ scan_id: number; file_name: string }>(`/api/reports/${scanId}/pdf`, { method: 'POST' }),
}
