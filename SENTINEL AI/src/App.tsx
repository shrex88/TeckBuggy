import { useEffect, useState, type ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Bell,
  Bot,
  BookOpen,
  Box,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Command,
  Cookie,
  FlaskConical,
  FileCheck2,
  FileText,
  Gauge,
  GraduationCap,
  HelpCircle,
  History,
  Layers3,
  LayoutDashboard,
  Lightbulb,
  LockKeyhole,
  Menu,
  Moon,
  Play,
  Plus,
  Radar,
  RotateCcw,
  ScanLine,
  Send,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Sun,
  Terminal,
  TrendingUp,
  Trophy,
  User,
  WandSparkles,
  X,
  Zap,
  type LucideIcon,
} from 'lucide-react'

type Theme = 'dark' | 'light' | 'system'
type View = 'landing' | 'dashboard'

const features = [
  {
    icon: ScanLine,
    title: 'Security Scanner',
    text: 'Continuously inspect code, APIs and cloud configurations for exploitable weaknesses.',
    accent: 'cyan',
  },
  {
    icon: BrainIcon,
    title: 'AI Risk Intelligence',
    text: 'Prioritise what matters with contextual risk, exploitability and business impact.',
    accent: 'violet',
  },
  {
    icon: Box,
    title: 'Security Digital Twin',
    text: 'Model your application and safely simulate attack paths before they reach production.',
    accent: 'violet',
  },
  {
    icon: BadgeCheck,
    title: 'Remediation Confidence',
    text: 'Validate every proposed fix against security, functionality and regression risk.',
    accent: 'cyan',
  },
  {
    icon: Bot,
    title: 'AI Copilot',
    text: 'Generate secure, context-aware fixes your engineering team can understand and approve.',
    accent: 'cyan',
  },
  {
    icon: FileCheck2,
    title: 'Security Proof',
    text: 'Create verifiable evidence for every finding, decision and resolved vulnerability.',
    accent: 'violet',
  },
]

const workflow = [
  ['01', 'Scan', 'Discover weaknesses'],
  ['02', 'Analyse', 'Prioritise true risk'],
  ['03', 'Simulate', 'Test attack paths'],
  ['04', 'Approve', 'Keep humans in control'],
  ['05', 'Fix', 'Apply trusted patches'],
  ['06', 'Verify', 'Prove remediation'],
]

const sidebarItems: [LucideIcon, string][] = [
  [LayoutDashboard, 'Dashboard'],
  [Plus, 'New Scan'],
  [ShieldAlert, 'Vulnerabilities'],
  [BrainIcon, 'AI Risk Intelligence'],
  [History, 'Scan History'],
  [Box, 'Security Digital Twin'],
  [BadgeCheck, 'Remediation Confidence'],
  [Bot, 'AI Remediation Copilot'],
  [GraduationCap, 'Security Learning'],
  [User, 'Developer Approval'],
  [WandSparkles, 'Remediation Centre'],
  [FileCheck2, 'Security Proof'],
  [FileText, 'Reports'],
  [Settings, 'Settings'],
]

function BrainIcon(props: React.ComponentProps<LucideIcon>) {
  return <Lightbulb {...props} />
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <button className="brand" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
      <span className="brand-mark">
        <ShieldCheck size={compact ? 18 : 20} strokeWidth={2.2} />
      </span>
      {!compact && (
        <span>
          SENTINEL <b>AI</b>
        </span>
      )}
    </button>
  )
}

function ThemeSwitcher({
  theme,
  setTheme,
  compact = false,
}: {
  theme: Theme
  setTheme: (theme: Theme) => void
  compact?: boolean
}) {
  const [open, setOpen] = useState(false)
  const currentIcon = theme === 'light' ? Sun : theme === 'dark' ? Moon : Command
  const CurrentIcon = currentIcon
  return (
    <div className="theme-picker">
      <button
        className={compact ? 'icon-button' : 'theme-trigger'}
        onClick={() => setOpen((value) => !value)}
        aria-label="Change color theme"
        aria-expanded={open}
      >
        <CurrentIcon size={16} />
        {!compact && <span>{theme[0].toUpperCase() + theme.slice(1)}</span>}
        {!compact && <ChevronDown size={14} />}
      </button>
      {open && (
        <div className="theme-menu">
          {([
            ['light', Sun],
            ['dark', Moon],
            ['system', Command],
          ] as const).map(([value, Icon]) => (
            <button
              key={value}
              className={theme === value ? 'active' : ''}
              onClick={() => {
                setTheme(value)
                setOpen(false)
              }}
            >
              <Icon size={15} />
              <span>{value[0].toUpperCase() + value.slice(1)}</span>
              {theme === value && <Check size={14} />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function Landing({
  openDashboard,
  theme,
  setTheme,
}: {
  openDashboard: () => void
  theme: Theme
  setTheme: (theme: Theme) => void
}) {
  const [mobileMenu, setMobileMenu] = useState(false)

  return (
    <div className="landing">
      <nav className="site-nav">
        <Brand />
        <div className="nav-links">
          <a href="#features">Features</a>
          <a href="#workflow">How It Works</a>
          <button className="text-button" onClick={openDashboard}>
            Login
          </button>
        </div>
        <div className="nav-actions">
          <ThemeSwitcher theme={theme} setTheme={setTheme} />
          <button className="button button-primary button-sm" onClick={openDashboard}>
            Get Started <ArrowRight size={15} />
          </button>
          <button className="icon-button mobile-menu-button" onClick={() => setMobileMenu(!mobileMenu)}>
            {mobileMenu ? <X size={19} /> : <Menu size={19} />}
          </button>
        </div>
        {mobileMenu && (
          <div className="mobile-nav">
            <a href="#features" onClick={() => setMobileMenu(false)}>
              Features
            </a>
            <a href="#workflow" onClick={() => setMobileMenu(false)}>
              How It Works
            </a>
            <button onClick={openDashboard}>Login</button>
            <ThemeSwitcher theme={theme} setTheme={setTheme} />
          </div>
        )}
      </nav>

      <main>
        <section className="hero">
          <div className="hero-grid" aria-hidden="true" />
          <div className="orb orb-one" aria-hidden="true" />
          <div className="orb orb-two" aria-hidden="true" />
          <div className="hero-content">
            <div className="eyebrow">
              <Sparkles size={14} />
              AI-NATIVE APPLICATION SECURITY
            </div>
            <h1>
              See Beyond Vulnerabilities.
              <span>Build Applications That Are Secure.</span>
            </h1>
            <p>
              Sentinel AI detects vulnerabilities, understands real-world risk and delivers
              verified remediation—so security and engineering teams can move faster, together.
            </p>
            <div className="hero-actions">
              <button className="button button-primary button-lg" onClick={openDashboard}>
                Launch Dashboard <ArrowRight size={17} />
              </button>
              <a className="button button-secondary button-lg" href="#features">
                <Play size={16} fill="currentColor" /> Explore Features
              </a>
            </div>
            <div className="hero-proof">
              <div className="proof-avatars">
                <span>MK</span>
                <span>AL</span>
                <span>JR</span>
              </div>
              <div>
                <div className="stars">★★★★★</div>
                <small>Trusted by security teams building critical software</small>
              </div>
            </div>
          </div>

          <div className="hero-visual" aria-label="Sentinel AI security overview preview">
            <div className="visual-topbar">
              <div className="visual-dots">
                <i />
                <i />
                <i />
              </div>
              <span>Production environment</span>
              <span className="live-pill">
                <i /> Protected
              </span>
            </div>
            <div className="visual-body">
              <div className="visual-sidebar">
                <Brand compact />
                {[LayoutDashboard, Radar, ShieldAlert, Box, BarChart3].map((Icon, index) => (
                  <span className={index === 0 ? 'active' : ''} key={index}>
                    <Icon size={17} />
                  </span>
                ))}
              </div>
              <div className="visual-main">
                <div className="visual-heading">
                  <div>
                    <small>SECURITY POSTURE</small>
                    <strong>Command Centre</strong>
                  </div>
                  <button>New scan</button>
                </div>
                <div className="mini-stats">
                  <div>
                    <small>Security score</small>
                    <strong className="score">92</strong>
                    <span className="positive">+8.4%</span>
                  </div>
                  <div>
                    <small>Active findings</small>
                    <strong>24</strong>
                    <span>12 resolved</span>
                  </div>
                  <div>
                    <small>Assets protected</small>
                    <strong>1,284</strong>
                    <span className="positive">100% monitored</span>
                  </div>
                </div>
                <div className="visual-chart">
                  <div className="chart-copy">
                    <small>RISK EXPOSURE</small>
                    <strong>Threats neutralised</strong>
                  </div>
                  <svg viewBox="0 0 520 165" preserveAspectRatio="none">
                    <defs>
                      <linearGradient id="lineFill" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stopColor="var(--cyan)" stopOpacity=".24" />
                        <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0" />
                      </linearGradient>
                    </defs>
                    <path
                      className="area"
                      d="M0 134 C45 130, 62 112, 96 117 S154 93, 194 99 S248 71, 284 76 S337 44, 376 57 S440 32, 520 20 L520 165 L0 165Z"
                    />
                    <path
                      className="line"
                      d="M0 134 C45 130, 62 112, 96 117 S154 93, 194 99 S248 71, 284 76 S337 44, 376 57 S440 32, 520 20"
                    />
                  </svg>
                </div>
                <div className="scan-complete">
                  <CheckCircle2 size={17} />
                  <div>
                    <strong>Scan complete</strong>
                    <span>12 issues analysed · 9 auto-triaged</span>
                  </div>
                  <span>Just now</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="trust-strip">
          <span>ENGINEERED FOR MODERN SECURITY TEAMS</span>
          <div>
            <b>
              <Command /> VERCEL
            </b>
            <b>
              <CircleDot /> NORTHSTAR
            </b>
            <b>
              <Zap /> LUMEN
            </b>
            <b>
              <Box /> CUBIC
            </b>
            <b>
              <Activity /> VECTOR
            </b>
          </div>
        </section>

        <section className="section features-section" id="features">
          <div className="section-heading">
            <div>
              <span className="section-kicker">INTELLIGENCE AT EVERY LAYER</span>
              <h2>From signal to secure, in one platform.</h2>
            </div>
            <p>
              Replace fragmented security tools with one intelligent system that sees context,
              proves risk and guides every fix.
            </p>
          </div>
          <div className="feature-grid">
            {features.map(({ icon: Icon, title, text, accent }) => (
              <article className="feature-card" key={title}>
                <div className={`feature-icon ${accent}`}>
                  <Icon size={21} />
                </div>
                <h3>{title}</h3>
                <p>{text}</p>
                <a href="#workflow">
                  Learn more <ArrowRight size={15} />
                </a>
              </article>
            ))}
          </div>
        </section>

        <section className="section workflow-section" id="workflow">
          <div className="workflow-intro">
            <span className="section-kicker">CLOSED-LOOP SECURITY</span>
            <h2>Every finding. Fully resolved.</h2>
            <p>
              Sentinel AI connects discovery, decision and remediation in a continuous,
              human-governed workflow.
            </p>
            <button className="button button-secondary" onClick={openDashboard}>
              See it in action <ArrowRight size={16} />
            </button>
          </div>
          <div className="workflow-list">
            {workflow.map(([number, title, text], index) => (
              <div className="workflow-item" key={title}>
                <span>{number}</span>
                <div className="workflow-icon">
                  {index === 0 && <ScanLine />}
                  {index === 1 && <BrainIcon />}
                  {index === 2 && <Box />}
                  {index === 3 && <BadgeCheck />}
                  {index === 4 && <WandSparkles />}
                  {index === 5 && <ShieldCheck />}
                </div>
                <div>
                  <h3>{title}</h3>
                  <p>{text}</p>
                </div>
                {index < workflow.length - 1 && <ChevronRight size={17} />}
              </div>
            ))}
          </div>
        </section>

        <section className="cta-section">
          <div>
            <span className="section-kicker">THE FUTURE OF APPSEC IS HERE</span>
            <h2>Move fast. Stay secure.</h2>
            <p>Start finding and fixing what matters in minutes—not weeks.</p>
          </div>
          <button className="button button-primary button-lg" onClick={openDashboard}>
            Start securing now <ArrowRight size={17} />
          </button>
        </section>
      </main>

      <footer>
        <div className="footer-main">
          <div>
            <Brand />
            <p>Intelligent security for software that matters.</p>
          </div>
          <div>
            <b>Platform</b>
            <a href="#features">Features</a>
            <a href="#workflow">How it works</a>
            <button onClick={openDashboard}>Dashboard</button>
          </div>
          <div>
            <b>Company</b>
            <a href="#">About</a>
            <a href="#">Trust Centre</a>
            <a href="#">Contact</a>
          </div>
          <div>
            <b>Resources</b>
            <a href="#">Documentation</a>
            <a href="#">Security</a>
            <a href="#">Status</a>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© 2025 Sentinel AI, Inc.</span>
          <div>
            <a href="#">Privacy</a>
            <a href="#">Terms</a>
            <span className="status">
              <i /> All systems operational
            </span>
          </div>
        </div>
      </footer>
    </div>
  )
}

function MetricCard({
  icon: Icon,
  label,
  value,
  trend,
  tone = 'default',
}: {
  icon: LucideIcon
  label: string
  value: string
  trend: string
  tone?: 'default' | 'danger' | 'warning'
}) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-top">
        <span>{label}</span>
        <span className="metric-icon">
          <Icon size={17} />
        </span>
      </div>
      <strong>{value}</strong>
      <small>{trend}</small>
    </div>
  )
}

function ModuleHeader({
  eyebrow,
  title,
  description,
  icon: Icon,
  actions,
}: {
  eyebrow: string
  title: string
  description: string
  icon: LucideIcon
  actions?: ReactNode
}) {
  return (
    <div className="module-header">
      <div className="module-title">
        <span className="module-icon">
          <Icon size={20} />
        </span>
        <div>
          <span className="module-eyebrow">{eyebrow}</span>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </div>
      {actions && <div className="module-actions">{actions}</div>}
    </div>
  )
}

function SettingToggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string
  description: string
  checked: boolean
  onChange: () => void
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <span>{description}</span>
      </div>
      <button
        className={`switch ${checked ? 'on' : ''}`}
        onClick={onChange}
        role="switch"
        aria-checked={checked}
        aria-label={`Toggle ${label}`}
      >
        <i />
      </button>
    </div>
  )
}

function SecurityDigitalTwin() {
  const [secure, setSecure] = useState(true)
  const [httpOnly, setHttpOnly] = useState(true)
  const [sameSite, setSameSite] = useState(true)
  const [running, setRunning] = useState(false)
  const [completed, setCompleted] = useState(true)
  const [view, setView] = useState<'config' | 'results' | 'history'>('config')

  const runSimulation = () => {
    setRunning(true)
    setCompleted(false)
    window.setTimeout(() => {
      setRunning(false)
      setCompleted(true)
      setView('results')
    }, 1200)
  }

  return (
    <div className="module-page page-enter">
      <ModuleHeader
        eyebrow="ISOLATED SECURITY ENVIRONMENT"
        title="Security Digital Twin"
        description="Model and validate security changes against a virtual replica of your application."
        icon={Box}
        actions={
          <>
            <button className="button button-secondary">
              <RotateCcw size={15} /> Reset
            </button>
            <button className={`button button-primary ${running ? 'is-loading' : ''}`} onClick={runSimulation}>
              {running ? <CircleDot size={15} /> : <Play size={15} fill="currentColor" />}
              {running ? 'Simulating…' : 'Run simulation'}
            </button>
          </>
        }
      />

      <div className="simulation-banner">
        <span className="simulation-pulse">
          <FlaskConical size={18} />
        </span>
        <div>
          <strong>VIRTUAL SIMULATION – ORIGINAL APPLICATION UNCHANGED</strong>
          <p>All changes run inside an isolated twin. No production files or services are modified.</p>
        </div>
        <span className="isolation-badge">
          <LockKeyhole size={12} /> Isolated
        </span>
      </div>

      <div className="module-tabs">
        {[
          ['config', 'Configuration'],
          ['results', 'Simulation Results'],
          ['history', 'History'],
        ].map(([id, label]) => (
          <button className={view === id ? 'active' : ''} onClick={() => setView(id as typeof view)} key={id}>
            {label}
            {id === 'results' && <span>6</span>}
          </button>
        ))}
      </div>

      {view === 'config' && (
        <div className="twin-grid tab-enter">
          <section className="panel config-compare">
            <div className="panel-heading">
              <div>
                <h2>Configuration comparison</h2>
                <p>Review proposed changes before running a simulation</p>
              </div>
              <span className="changes-badge">4 proposed changes</span>
            </div>
            <div className="compare-head">
              <span>Security control</span>
              <span>Original configuration</span>
              <span>Proposed configuration</span>
            </div>
            {[
              ['Content Security Policy', "default-src 'self' 'unsafe-inline'", "default-src 'self'; script-src 'self'"],
              ['X-Frame-Options', 'Not configured', 'DENY'],
              ['Referrer-Policy', 'origin', 'strict-origin-when-cross-origin'],
              ['Permissions-Policy', 'Not configured', 'camera=(), microphone=()'],
            ].map(([label, original, proposed], index) => (
              <div className="compare-row" key={label}>
                <div>
                  <span className="control-icon">{index === 0 ? <Shield size={14} /> : <Code2 size={14} />}</span>
                  <strong>{label}</strong>
                </div>
                <code className={original === 'Not configured' ? 'missing' : ''}>{original}</code>
                <code className="proposed">
                  <Plus size={11} /> {proposed}
                </code>
              </div>
            ))}
          </section>

          <aside className="twin-side">
            <section className="panel">
              <div className="panel-heading compact-heading">
                <div>
                  <h2>Cookie security</h2>
                  <p>Session cookie attributes</p>
                </div>
                <Cookie size={17} />
              </div>
              <div className="settings-list">
                <SettingToggle
                  label="Secure"
                  description="HTTPS transmission only"
                  checked={secure}
                  onChange={() => setSecure(!secure)}
                />
                <SettingToggle
                  label="HttpOnly"
                  description="Block client-side access"
                  checked={httpOnly}
                  onChange={() => setHttpOnly(!httpOnly)}
                />
                <SettingToggle
                  label="SameSite"
                  description="Strict cross-site policy"
                  checked={sameSite}
                  onChange={() => setSameSite(!sameSite)}
                />
              </div>
            </section>
            <section className="panel csp-card">
              <div className="panel-heading compact-heading">
                <div>
                  <h2>CSP configuration</h2>
                  <p>Proposed production policy</p>
                </div>
                <SlidersHorizontal size={17} />
              </div>
              <div className="code-editor">
                <span>1</span>
                <code>default-src <b>'self'</b>;</code>
                <span>2</span>
                <code>script-src <b>'self'</b> cdn.sentinel.dev;</code>
                <span>3</span>
                <code>img-src <b>'self'</b> data: https:;</code>
                <span>4</span>
                <code>frame-ancestors <b>'none'</b>;</code>
              </div>
            </section>
          </aside>
        </div>
      )}

      {view === 'results' && (
        <div className="results-grid tab-enter">
          <section className="panel projected-score">
            <div className="panel-heading">
              <div>
                <h2>Projected security score</h2>
                <p>Estimated impact if proposed configuration is deployed</p>
              </div>
              <span className="simulation-status">
                <CheckCircle2 size={13} /> Simulation complete
              </span>
            </div>
            <div className="score-projection">
              <div>
                <span>Current</span>
                <strong>74</strong>
              </div>
              <div className="projection-line">
                <i />
                <ArrowRight size={16} />
              </div>
              <div className="projected">
                <span>Projected</span>
                <strong>91</strong>
              </div>
              <span className="score-gain">
                <TrendingUp size={13} /> +17 points
              </span>
            </div>
            <div className="score-meter">
              <i style={{ width: completed ? '91%' : '0%' }} />
            </div>
          </section>
          <section className="panel checks-panel">
            <div className="panel-heading">
              <div>
                <h2>Security checks</h2>
                <p>Automated validation across proposed controls</p>
              </div>
              <b className="checks-total">5 / 6 passed</b>
            </div>
            <div className="check-list">
              {[
                ['CSP blocks inline script execution', 'Passed', 'pass'],
                ['Session cookies resist theft', 'Passed', 'pass'],
                ['Clickjacking protection enabled', 'Passed', 'pass'],
                ['Third-party payment widget', 'Compatibility warning', 'warn'],
                ['Security header syntax valid', 'Passed', 'pass'],
                ['Browser coverage maintained', 'Passed', 'pass'],
              ].map(([name, status, tone]) => (
                <div key={name}>
                  <span className={tone}>
                    {tone === 'pass' ? <Check size={13} /> : <AlertTriangle size={13} />}
                  </span>
                  <strong>{name}</strong>
                  <small className={tone}>{status}</small>
                </div>
              ))}
            </div>
          </section>
          <section className="panel compatibility-panel">
            <div className="panel-heading">
              <div>
                <h2>Compatibility warning</h2>
                <p>Potential functional impact detected</p>
              </div>
              <AlertTriangle size={18} />
            </div>
            <div className="warning-content">
              <strong>Payment iframe may be blocked</strong>
              <p>
                The proposed <code>frame-src</code> directive does not include
                <code> https://checkout.stripe.com</code>. Add this origin before deployment.
              </p>
              <button className="button button-secondary button-sm">Apply recommended exception</button>
            </div>
          </section>
        </div>
      )}

      {view === 'history' && (
        <section className="panel simulation-history tab-enter">
          <div className="panel-heading">
            <div>
              <h2>Simulation history</h2>
              <p>Previous virtual runs for Customer Portal</p>
            </div>
            <button className="link-button">Export history</button>
          </div>
          {[
            ['CSP & cookie hardening', '91', '+17', '6 checks', 'Today, 10:42'],
            ['Security header baseline', '86', '+12', '8 checks', 'Yesterday, 16:08'],
            ['Strict transport policy', '82', '+8', '4 checks', '18 Jun, 09:15'],
          ].map((item) => (
            <div className="history-row" key={item[0]}>
              <span className="history-icon">
                <FlaskConical size={15} />
              </span>
              <div>
                <strong>{item[0]}</strong>
                <span>{item[4]}</span>
              </div>
              <span>Projected score <b>{item[1]}</b></span>
              <span className="positive-text">{item[2]} points</span>
              <span>{item[3]}</span>
              <ChevronRight size={15} />
            </div>
          ))}
        </section>
      )}
    </div>
  )
}

function ConfidenceRing({ score }: { score: number }) {
  return (
    <div className="confidence-ring" style={{ '--score': `${score * 3.6}deg` } as React.CSSProperties}>
      <div>
        <strong>{score}</strong>
        <span>/ 100</span>
      </div>
    </div>
  )
}

function RemediationConfidence() {
  const [level, setLevel] = useState('High')
  const profiles: Record<string, { score: number; copy: string }> = {
    High: { score: 92, copy: 'Strong evidence supports this remediation across the current application context.' },
    Moderate: { score: 73, copy: 'Most evidence supports the fix, with some environmental assumptions remaining.' },
    Low: { score: 46, copy: 'Material uncertainty remains. Additional tests and application context are required.' },
    'Insufficient Evidence': { score: 22, copy: 'There is not enough verified evidence to recommend this fix for deployment.' },
  }
  const metrics = [
    ['Technical Correctness', 96, 'Static analysis + CVE guidance'],
    ['Application Safety', 88, '38 integration tests evaluated'],
    ['Configuration Validity', 94, 'Schema and runtime validated'],
    ['Framework Compatibility', 91, 'Next.js 15.2 compatibility'],
    ['Evidence Completeness', 82, '2 evidence gaps identified'],
    ['Regression Risk', 18, 'Low predicted regression risk'],
  ] as const
  const selected = profiles[level]

  return (
    <div className="module-page page-enter">
      <ModuleHeader
        eyebrow="EVIDENCE-BASED FIX ANALYSIS"
        title="Remediation Confidence Engine"
        description="Evaluate whether a proposed fix is correct, safe and suitable for this application."
        icon={BadgeCheck}
        actions={
          <button className="button button-secondary">
            <FileText size={15} /> Export analysis
          </button>
        }
      />

      <div className="ai-boundary-banner">
        <Sparkles size={17} />
        <div>
          <strong>AI confidence is not verification</strong>
          <p>
            Confidence estimates the reliability of this proposed fix. A verified security improvement requires
            successful testing, deployment and a follow-up scan.
          </p>
        </div>
        <button>
          Learn about evidence <ArrowRight size={13} />
        </button>
      </div>

      <div className="confidence-levels">
        {[
          ['High', '85–100', 'high'],
          ['Moderate', '65–84', 'moderate'],
          ['Low', '35–64', 'low'],
          ['Insufficient Evidence', '0–34', 'insufficient'],
        ].map(([name, range, tone]) => (
          <button className={`${tone} ${level === name ? 'active' : ''}`} onClick={() => setLevel(name)} key={name}>
            <i />
            <span>
              <strong>{name}</strong>
              <small>{range}</small>
            </span>
            {level === name && <CheckCircle2 size={15} />}
          </button>
        ))}
      </div>

      <div className="confidence-grid">
        <section className="panel confidence-summary">
          <div className="panel-heading">
            <div>
              <h2>AI confidence score</h2>
              <p>Proposed fix: Replace vulnerable JWT verification</p>
            </div>
            <span className={`confidence-tag ${level.toLowerCase().replace(' ', '-')}`}>{level}</span>
          </div>
          <div className="confidence-hero">
            <ConfidenceRing score={selected.score} />
            <div>
              <span className="analysis-label">
                <CircleDot size={11} /> ANALYSIS COMPLETE
              </span>
              <h3>{selected.copy}</h3>
              <p>Assessed using 14 evidence sources, project context and framework-specific security guidance.</p>
            </div>
          </div>
          <div className="evidence-strip">
            <div>
              <strong>14</strong>
              <span>Evidence sources</span>
            </div>
            <div>
              <strong>38</strong>
              <span>Tests evaluated</span>
            </div>
            <div>
              <strong>2</strong>
              <span>Open assumptions</span>
            </div>
          </div>
        </section>

        <section className="panel confidence-metrics">
          <div className="panel-heading">
            <div>
              <h2>Confidence factors</h2>
              <p>Weighted signals used in this assessment</p>
            </div>
            <SlidersHorizontal size={16} />
          </div>
          <div className="factor-list">
            {metrics.map(([label, value, detail]) => {
              const displayed = level === 'High' ? value : Math.max(12, value - (92 - selected.score))
              return (
                <div className="factor-row" key={label}>
                  <div>
                    <strong>{label}</strong>
                    <span>{detail}</span>
                  </div>
                  <div className="factor-bar">
                    <i style={{ width: `${displayed}%` }} />
                  </div>
                  <b>{displayed}%</b>
                </div>
              )
            })}
          </div>
        </section>

        <section className="panel confidence-explanation">
          <div className="panel-heading">
            <div>
              <h2>Why this result?</h2>
              <p>AI-generated explanation grounded in observed evidence</p>
            </div>
            <BrainIcon size={17} />
          </div>
          <div className="explanation-body">
            <p>
              The proposed fix replaces manual token parsing with the framework's verified JWT API. It removes the
              signature-bypass path while preserving all existing claim validation behavior.
            </p>
            <div className="reason-item positive">
              <CheckCircle2 size={15} />
              <div>
                <strong>Strong technical evidence</strong>
                <span>Matches vendor guidance and resolves the vulnerable code path.</span>
              </div>
            </div>
            <div className="reason-item positive">
              <CheckCircle2 size={15} />
              <div>
                <strong>Application tests remain stable</strong>
                <span>38 related tests passed in the isolated security twin.</span>
              </div>
            </div>
            <div className="reason-item caution">
              <AlertTriangle size={15} />
              <div>
                <strong>Runtime assumption requires verification</strong>
                <span>One legacy worker still uses Node.js 18 and should be tested separately.</span>
              </div>
            </div>
          </div>
          <div className="verification-path">
            <span>AI assessment</span>
            <i />
            <span>Developer approval</span>
            <i />
            <span>Deploy & verify</span>
            <ShieldCheck size={15} />
          </div>
        </section>
      </div>
    </div>
  )
}

function SecurityLearning() {
  const [level, setLevel] = useState('Intermediate')
  const [activeLesson, setActiveLesson] = useState('Content Security Policy')
  const [quizAnswer, setQuizAnswer] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [chat, setChat] = useState(['Ask me to explain a concept, review an answer or give you a practical hint.'])
  const lessons = [
    ['Content Security Policy', '18 min', 72, Shield],
    ['Secure Cookies', '12 min', 100, Cookie],
    ['HttpOnly', '8 min', 100, LockKeyhole],
    ['SameSite', '14 min', 45, Layers3],
    ['Security Headers', '20 min', 0, SlidersHorizontal],
    ['TLS Fundamentals', '16 min', 0, LockKeyhole],
    ['Exposed Configuration Files', '22 min', 0, FileText],
  ] as const

  const sendTutorMessage = () => {
    if (!message.trim()) return
    setChat([
      ...chat,
      message,
      'Good question. Start by thinking about which browser trust boundary the directive controls, then test the narrowest policy in report-only mode.',
    ])
    setMessage('')
  }

  return (
    <div className="module-page learning-page page-enter">
      <ModuleHeader
        eyebrow="DEVELOPER SECURITY ACADEMY"
        title="Security Learning Mode"
        description="Build practical AppSec skills through focused lessons, code exercises and AI-guided feedback."
        icon={GraduationCap}
        actions={
          <div className="learning-streak">
            <Zap size={15} />
            <strong>7 day streak</strong>
          </div>
        }
      />

      <div className="learning-overview">
        <section className="learning-progress-card">
          <div className="progress-ring" style={{ '--progress': '245deg' } as React.CSSProperties}>
            <div>
              <strong>68%</strong>
              <span>complete</span>
            </div>
          </div>
          <div>
            <span className="module-eyebrow">CURRENT PATH</span>
            <h2>Application Security Foundations</h2>
            <p>12 of 18 lessons complete · Approximately 2h 14m remaining</p>
            <div className="learning-progress-line">
              <i />
            </div>
          </div>
          <div className="xp-block">
            <Trophy size={20} />
            <strong>2,480 XP</strong>
            <span>Top 12% this month</span>
          </div>
        </section>
        <div className="achievement-row">
          {[
            [ShieldCheck, 'Header Architect', 'Completed all header labs'],
            [Terminal, 'Secure by Default', '5 perfect exercises'],
            [Zap, 'Fast Learner', '7-day learning streak'],
          ].map(([Icon, name, detail]) => (
            <div key={name as string}>
              <span>
                <Icon size={17} />
              </span>
              <div>
                <strong>{name as string}</strong>
                <small>{detail as string}</small>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="level-selector">
        <span>Learning level</span>
        {['Beginner', 'Intermediate', 'Advanced'].map((item) => (
          <button className={level === item ? 'active' : ''} onClick={() => setLevel(item)} key={item}>
            {item}
            {item === 'Intermediate' && <span>Recommended</span>}
          </button>
        ))}
      </div>

      <div className="learning-grid">
        <section className="panel lesson-library">
          <div className="panel-heading">
            <div>
              <h2>{level} curriculum</h2>
              <p>Practical security concepts for modern applications</p>
            </div>
            <span className="lesson-count">7 lessons</span>
          </div>
          <div className="lesson-list">
            {lessons.map(([title, time, progress, Icon], index) => (
              <button
                className={activeLesson === title ? 'active' : ''}
                onClick={() => setActiveLesson(title)}
                key={title}
              >
                <span className={`lesson-number ${progress === 100 ? 'done' : ''}`}>
                  {progress === 100 ? <Check size={13} /> : String(index + 1).padStart(2, '0')}
                </span>
                <span className="lesson-symbol">
                  <Icon size={15} />
                </span>
                <span className="lesson-copy">
                  <strong>{title}</strong>
                  <small>
                    <Clock3 size={10} /> {time} · {progress === 100 ? 'Completed' : progress ? 'In progress' : 'Not started'}
                  </small>
                </span>
                <span className="mini-progress">
                  <i style={{ width: `${progress}%` }} />
                </span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
        </section>

        <section className="panel lesson-workspace">
          <div className="lesson-hero">
            <span className="lesson-type">
              <BookOpen size={12} /> INTERACTIVE LESSON
            </span>
            <h2>{activeLesson}</h2>
            <p>
              Learn how browser-enforced security controls reduce attack surface without breaking legitimate
              application behavior.
            </p>
            <div>
              <span>Lesson 1 of 7</span>
              <span>18 minutes</span>
              <span>{level}</span>
            </div>
          </div>
          <div className="lesson-body">
            <h3>Knowledge check</h3>
            <p>Which CSP directive controls the sources allowed to execute JavaScript?</p>
            <div className="quiz-options">
              {["default-src", "script-src", "connect-src", "frame-ancestors"].map((answer, index) => (
                <button
                  className={`${quizAnswer === answer ? 'selected' : ''} ${
                    quizAnswer && answer === 'script-src' ? 'correct' : ''
                  }`}
                  onClick={() => setQuizAnswer(answer)}
                  key={answer}
                >
                  <span>{String.fromCharCode(65 + index)}</span>
                  <code>{answer}</code>
                  {quizAnswer && answer === 'script-src' && <CheckCircle2 size={15} />}
                </button>
              ))}
            </div>
            {quizAnswer && (
              <div className={`quiz-feedback ${quizAnswer === 'script-src' ? 'correct' : 'incorrect'}`}>
                {quizAnswer === 'script-src' ? <CheckCircle2 size={16} /> : <HelpCircle size={16} />}
                <div>
                  <strong>{quizAnswer === 'script-src' ? 'Correct' : 'Not quite'}</strong>
                  <p>
                    <code>script-src</code> specifically defines valid sources for JavaScript. When absent, the
                    browser falls back to <code>default-src</code>.
                  </p>
                </div>
              </div>
            )}
            <div className="exercise-card">
              <div>
                <Terminal size={17} />
                <span>
                  <strong>Practical exercise</strong>
                  <small>Harden a CSP without blocking the application</small>
                </span>
              </div>
              <span>+120 XP</span>
              <button className="button button-primary button-sm">
                Open lab <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </section>

        <aside className="panel ai-tutor">
          <div className="tutor-heading">
            <span>
              <Bot size={17} />
            </span>
            <div>
              <strong>Sentinel AI Tutor</strong>
              <small>
                <i /> Online · Learning context enabled
              </small>
            </div>
            <Sparkles size={15} />
          </div>
          <div className="tutor-chat">
            {chat.map((item, index) => (
              <div className={index % 2 ? 'student-message' : 'tutor-message'} key={`${item}-${index}`}>
                {index % 2 === 0 && (
                  <span>
                    <Bot size={12} />
                  </span>
                )}
                <p>{item}</p>
              </div>
            ))}
          </div>
          <div className="tutor-prompts">
            <button onClick={() => setMessage('Explain CSP nonces')}>Explain CSP nonces</button>
            <button onClick={() => setMessage('Give me a hint')}>Give me a hint</button>
          </div>
          <div className="tutor-input">
            <input
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              onKeyDown={(event) => event.key === 'Enter' && sendTutorMessage()}
              placeholder="Ask your AI tutor…"
            />
            <button onClick={sendTutorMessage} aria-label="Send message">
              <Send size={14} />
            </button>
          </div>
        </aside>
      </div>
    </div>
  )
}

function Dashboard({
  goHome,
  theme,
  setTheme,
}: {
  goHome: () => void
  theme: Theme
  setTheme: (theme: Theme) => void
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [active, setActive] = useState('Dashboard')
  const scans = [
    ['API Gateway', 'Production', 'Completed', '92', '2 min ago'],
    ['Customer Portal', 'main', 'Completed', '87', '34 min ago'],
    ['Payment Service', 'release/v2.4', 'Review needed', '74', '2 hours ago'],
    ['Auth Service', 'Production', 'Completed', '96', 'Yesterday'],
  ]

  return (
    <div className="dashboard-shell">
      {sidebarOpen && <button className="sidebar-scrim" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <Brand />
          <button className="sidebar-close" onClick={() => setSidebarOpen(false)}>
            <X size={18} />
          </button>
        </div>
        <button className="new-scan">
          <Plus size={16} /> New security scan
        </button>
        <nav className="sidebar-nav">
          {sidebarItems.map(([Icon, label], index) => (
            <button
              key={label}
              className={active === label ? 'active' : ''}
              onClick={() => {
                setActive(label)
                setSidebarOpen(false)
              }}
            >
              <Icon size={17} />
              <span>{label}</span>
              {index === 2 && <small>24</small>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="workspace-avatar">NS</div>
          <div>
            <strong>Northstar Labs</strong>
            <span>Enterprise workspace</span>
          </div>
          <ChevronDown size={15} />
        </div>
      </aside>

      <div className="dashboard-content">
        <header className="dashboard-header">
          <div className="dashboard-header-left">
            <button className="icon-button sidebar-toggle" onClick={() => setSidebarOpen(true)}>
              <Menu size={19} />
            </button>
            <button className="breadcrumb-home" onClick={goHome}>
              Sentinel AI
            </button>
            <ChevronRight size={14} />
            <span>{active}</span>
          </div>
          <div className="dashboard-header-actions">
            <div className="environment-select">
              <i /> Production <ChevronDown size={14} />
            </div>
            <ThemeSwitcher compact theme={theme} setTheme={setTheme} />
            <button className="icon-button notification-button">
              <Bell size={17} />
              <i />
            </button>
            <button className="profile-button">AM</button>
          </div>
        </header>

        <main className="dashboard-main">
          {active === 'Security Digital Twin' ? (
            <SecurityDigitalTwin />
          ) : active === 'Remediation Confidence' ? (
            <RemediationConfidence />
          ) : active === 'Security Learning' ? (
            <SecurityLearning />
          ) : active !== 'Dashboard' ? (
            <div className="empty-page">
              <div className="empty-icon">
                {(() => {
                  const ItemIcon = sidebarItems.find(([, label]) => label === active)?.[0] ?? Shield
                  return <ItemIcon size={26} />
                })()}
              </div>
              <span className="preview-label">MODULE PREVIEW</span>
              <h1>{active}</h1>
              <p>
                Connect a repository or run your first scan to populate this workspace with live
                security data.
              </p>
              <button className="button button-primary" onClick={() => setActive('New Scan')}>
                <Plus size={16} /> Start a new scan
              </button>
            </div>
          ) : (
            <>
              <div className="dashboard-title">
                <div>
                  <div className="title-line">
                    <h1>Security Overview</h1>
                    <span className="preview-label">PREVIEW DATA</span>
                  </div>
                  <p>Monitor your application security posture and prioritise what matters.</p>
                </div>
                <button className="button button-primary" onClick={() => setActive('New Scan')}>
                  <ScanLine size={16} /> New scan
                </button>
              </div>

              <div className="metric-grid">
                <MetricCard
                  icon={ShieldCheck}
                  label="Overall security score"
                  value="87"
                  trend="↑ 4 points from last week"
                />
                <MetricCard
                  icon={ShieldAlert}
                  label="Total vulnerabilities"
                  value="24"
                  trend="↓ 12 resolved this month"
                />
                <MetricCard
                  icon={AlertTriangle}
                  label="Critical findings"
                  value="3"
                  trend="1 requires immediate action"
                  tone="danger"
                />
                <MetricCard
                  icon={TrendingUp}
                  label="High-risk findings"
                  value="7"
                  trend="↓ 2 since last scan"
                  tone="warning"
                />
              </div>

              <div className="dashboard-grid top-charts">
                <section className="panel score-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Security score</h2>
                      <p>Overall posture across monitored assets</p>
                    </div>
                    <button className="more-button">···</button>
                  </div>
                  <div className="gauge-wrap">
                    <div className="gauge">
                      <svg viewBox="0 0 220 135">
                        <path className="gauge-track" d="M25 115 A88 88 0 0 1 195 115" />
                        <path className="gauge-value" d="M25 115 A88 88 0 0 1 195 115" pathLength="100" />
                      </svg>
                      <div>
                        <strong>87</strong>
                        <span>Excellent</span>
                      </div>
                    </div>
                    <div className="score-change">
                      <span>
                        <TrendingUp size={14} /> 4.8%
                      </span>
                      <small>vs. previous period</small>
                    </div>
                  </div>
                  <div className="score-footer">
                    <div>
                      <span>Code</span>
                      <b>91</b>
                    </div>
                    <div>
                      <span>Dependencies</span>
                      <b>84</b>
                    </div>
                    <div>
                      <span>Cloud</span>
                      <b>86</b>
                    </div>
                  </div>
                </section>

                <section className="panel vulnerability-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Vulnerability distribution</h2>
                      <p>Open findings by severity</p>
                    </div>
                    <select aria-label="Vulnerability period" defaultValue="30 days">
                      <option>30 days</option>
                      <option>7 days</option>
                    </select>
                  </div>
                  <div className="donut-layout">
                    <div className="donut">
                      <div>
                        <strong>24</strong>
                        <span>Total</span>
                      </div>
                    </div>
                    <div className="donut-legend">
                      {[
                        ['Critical', '3', '12.5%', 'critical'],
                        ['High', '7', '29.2%', 'high'],
                        ['Medium', '9', '37.5%', 'medium'],
                        ['Low', '5', '20.8%', 'low'],
                      ].map(([label, value, percent, color]) => (
                        <div key={label}>
                          <i className={color} />
                          <span>{label}</span>
                          <b>{value}</b>
                          <small>{percent}</small>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>

                <section className="panel owasp-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>OWASP Top 10</h2>
                      <p>Findings mapped by category</p>
                    </div>
                    <button className="link-button">View report</button>
                  </div>
                  <div className="bar-chart">
                    {[
                      ['A01', 82, 7],
                      ['A02', 56, 5],
                      ['A03', 69, 6],
                      ['A04', 32, 3],
                      ['A05', 45, 4],
                      ['A06', 22, 2],
                      ['A07', 34, 3],
                    ].map(([name, width, count]) => (
                      <div className="bar-row" key={name}>
                        <span>{name}</span>
                        <div>
                          <i style={{ width: `${width}%` }} />
                        </div>
                        <b>{count}</b>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <div className="dashboard-grid lower-grid">
                <section className="panel scans-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Recent scans</h2>
                      <p>Latest security activity across your assets</p>
                    </div>
                    <button className="link-button" onClick={() => setActive('Scan History')}>
                      View all <ArrowRight size={14} />
                    </button>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Target</th>
                          <th>Branch / Env</th>
                          <th>Status</th>
                          <th>Score</th>
                          <th>Started</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {scans.map(([target, branch, status, score, time]) => (
                          <tr key={target}>
                            <td>
                              <span className="target-icon">
                                <Code2 size={15} />
                              </span>
                              <b>{target}</b>
                            </td>
                            <td>
                              <code>{branch}</code>
                            </td>
                            <td>
                              <span className={`scan-status ${status === 'Review needed' ? 'review' : ''}`}>
                                <i /> {status}
                              </span>
                            </td>
                            <td>
                              <span className={`score-badge score-${score}`}>{score}</span>
                            </td>
                            <td>{time}</td>
                            <td>
                              <ChevronRight size={15} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>

                <section className="panel alerts-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Security alerts</h2>
                      <p>Recent events requiring attention</p>
                    </div>
                    <button className="icon-button">
                      <Settings size={15} />
                    </button>
                  </div>
                  <div className="alerts-list">
                    <div className="alert-item critical">
                      <span>
                        <AlertTriangle size={16} />
                      </span>
                      <div>
                        <strong>SQL injection path detected</strong>
                        <p>Payment Service · /api/v2/checkout</p>
                        <small>
                          <Clock3 size={12} /> 18 minutes ago
                        </small>
                      </div>
                      <ChevronRight size={15} />
                    </div>
                    <div className="alert-item warning">
                      <span>
                        <LockKeyhole size={16} />
                      </span>
                      <div>
                        <strong>Exposed access token</strong>
                        <p>Customer Portal · main branch</p>
                        <small>
                          <Clock3 size={12} /> 1 hour ago
                        </small>
                      </div>
                      <ChevronRight size={15} />
                    </div>
                    <div className="alert-item info">
                      <span>
                        <Sparkles size={16} />
                      </span>
                      <div>
                        <strong>AI remediation ready</strong>
                        <p>Fix generated with 94% confidence</p>
                        <small>
                          <Clock3 size={12} /> 3 hours ago
                        </small>
                      </div>
                      <ChevronRight size={15} />
                    </div>
                  </div>
                  <div className="live-data-note">
                    <CircleDot size={13} />
                    Live alerts appear here after your first connected scan.
                  </div>
                </section>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  )
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('sentinel-theme')
    return saved === 'dark' || saved === 'light' || saved === 'system' ? saved : 'dark'
  })
  const [view, setView] = useState<View>('landing')

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const applyTheme = () => {
      document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme
    }
    applyTheme()
    localStorage.setItem('sentinel-theme', theme)
    media.addEventListener('change', applyTheme)
    return () => media.removeEventListener('change', applyTheme)
  }, [theme])

  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [view])

  return view === 'landing' ? (
    <Landing openDashboard={() => setView('dashboard')} theme={theme} setTheme={setTheme} />
  ) : (
    <Dashboard goHome={() => setView('landing')} theme={theme} setTheme={setTheme} />
  )
}
