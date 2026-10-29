import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Path to mounted reports directory
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, 'reports');
const BUILDS_DIR = path.join(REPORTS_DIR, 'builds');

app.use(cors());
app.use(express.json());

// Helper to safely read JSON files
function readJsonFile(filePath, defaultValue = null) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error(`Error reading ${filePath}:`, err.message);
  }
  return defaultValue;
}

// API: List of applications supported in the lab
app.get('/api/apps', (req, res) => {
  const apps = [
    {
      id: 'vulnerable-node-app',
      name: 'Vulnerable Node.js Service (Demo)',
      repo: 'sample-app',
      runtime: 'Node.js 16 (Express)',
      status: 'Active Scan Target',
      hasReports: fs.existsSync(path.join(REPORTS_DIR, 'semgrep-results.json'))
    }
  ];
  res.json(apps);
});

// API: List available builds for history & comparison
app.get('/api/builds', (req, res) => {
  const builds = [];

  if (fs.existsSync(BUILDS_DIR)) {
    try {
      const entries = fs.readdirSync(BUILDS_DIR, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const buildDir = path.join(BUILDS_DIR, entry.name);
          const meta = readJsonFile(path.join(buildDir, 'meta.json'), {});
          const sca = readJsonFile(path.join(buildDir, 'trivy-sca-results.json'), {});
          const sast = readJsonFile(path.join(buildDir, 'semgrep-ai-triaged.json'), {});
          const container = readJsonFile(path.join(buildDir, 'trivy-container-results.json'), {});

          // Quick counts
          let scaCount = 0;
          if (sca?.Results) {
            sca.Results.forEach(r => scaCount += (r.Vulnerabilities || []).length);
          }

          let containerCount = 0;
          if (container?.Results) {
            container.Results.filter(r => r.Class === 'os-pkgs' || r.Type !== 'node-pkg')
              .forEach(r => containerCount += (r.Vulnerabilities || []).length);
          }

          const sastSummary = sast?.summary || {};

          builds.push({
            buildNumber: entry.name,
            timestamp: meta.timestamp || fs.statSync(buildDir).mtime.toISOString(),
            commit: meta.commit || 'unknown',
            notes: meta.notes || '',
            sast_total: sastSummary.total_findings || 0,
            sast_tp: sastSummary.true_positives || 0,
            sast_fp: sastSummary.false_positives || 0,
            sca_total: scaCount,
            container_total: containerCount
          });
        }
      }
    } catch (err) {
      console.error('Error scanning builds directory:', err);
    }
  }

  // Sort by buildNumber (numeric if possible) descending
  builds.sort((a, b) => {
    const numA = parseInt(a.buildNumber, 10);
    const numB = parseInt(b.buildNumber, 10);
    if (!isNaN(numA) && !isNaN(numB)) {
      return numB - numA;
    }
    return b.buildNumber.localeCompare(a.buildNumber);
  });

  if (builds.length > 0) {
    builds[0].isLatest = true;
  }

  res.json(builds);
});

// Helper to resolve directory for a requested build
function getTargetReportDir(buildNumber) {
  if (buildNumber && buildNumber !== 'latest') {
    const specificDir = path.join(BUILDS_DIR, String(buildNumber));
    if (fs.existsSync(specificDir)) {
      return specificDir;
    }
  }
  return REPORTS_DIR;
}

// API: Aggregated reports for selected app & build
app.get('/api/reports', (req, res) => {
  const appId = req.query.app || 'vulnerable-node-app';
  const buildQuery = req.query.build || 'latest';

  const targetDir = getTargetReportDir(buildQuery);

  const semgrepAiPath = path.join(targetDir, 'semgrep-ai-triaged.json');
  const semgrepRawPath = path.join(targetDir, 'semgrep-results.json');
  const trivyScaPath = path.join(targetDir, 'trivy-sca-results.json');
  const trivyContainerPath = path.join(targetDir, 'trivy-container-results.json');
  const remediationPrPath = path.join(targetDir, 'remediation-pr.json');
  const metaPath = path.join(targetDir, 'meta.json');

  const sastAi = readJsonFile(semgrepAiPath, { summary: {}, triaged_findings: [] });
  const sastRaw = readJsonFile(semgrepRawPath, { results: [] });
  const trivySca = readJsonFile(trivyScaPath, {});
  const trivyContainer = readJsonFile(trivyContainerPath, {});
  const remediationPr = readJsonFile(remediationPrPath, null);
  const meta = readJsonFile(metaPath, { build_number: buildQuery });

  // Parse Trivy SCA (npm packages)
  let scaVulnerabilities = [];
  if (trivySca && Array.isArray(trivySca.Results)) {
    for (const target of trivySca.Results) {
      if (Array.isArray(target.Vulnerabilities)) {
        for (const v of target.Vulnerabilities) {
          scaVulnerabilities.push({
            cve: v.VulnerabilityID,
            pkgName: v.PkgName,
            installedVersion: v.InstalledVersion,
            fixedVersion: v.FixedVersion || 'No Fix Available',
            severity: v.Severity,
            title: v.Title || v.Description || 'No description provided',
            target: target.Target
          });
        }
      }
    }
  }

  // Parse Trivy Container OS vulnerabilities (Strictly OS packages)
  let containerVulnerabilities = [];
  if (trivyContainer && Array.isArray(trivyContainer.Results)) {
    for (const target of trivyContainer.Results) {
      if (target.Class === 'os-pkgs' || (target.Type && target.Type !== 'node-pkg')) {
        if (Array.isArray(target.Vulnerabilities)) {
          for (const v of target.Vulnerabilities) {
            containerVulnerabilities.push({
              cve: v.VulnerabilityID,
              pkgName: v.PkgName,
              installedVersion: v.InstalledVersion,
              fixedVersion: v.FixedVersion || 'None',
              severity: v.Severity,
              title: v.Title || v.Description || 'OS package vulnerability',
              target: target.Target,
              class: target.Class || 'os-pkgs'
            });
          }
        }
      }
    }
  }

  const payload = {
    appId,
    build: {
      buildNumber: meta.build_number || buildQuery,
      timestamp: meta.timestamp || new Date().toISOString(),
      commit: meta.commit || 'unknown'
    },
    sast: {
      summary: sastAi.summary || {},
      findings: sastAi.triaged_findings || []
    },
    sca: {
      total: scaVulnerabilities.length,
      vulnerabilities: scaVulnerabilities,
      remediation_pr: remediationPr
    },
    container: {
      total: containerVulnerabilities.length,
      vulnerabilities: containerVulnerabilities
    }
  };

  res.json(payload);
});

// API: 1-Click Automated Remediation PR Generator
app.post('/api/remediate', async (req, res) => {
  const { mode = 'all' } = req.body;
  const remMode = ['sca', 'container', 'all'].includes(mode) ? mode : 'all';

  console.log(`[Remediation API] Triggered 1-click PR for target mode: ${remMode}`);

  const workspaceDir = process.env.WORKSPACE || path.resolve(__dirname, '..');
  const botScript = path.join(workspaceDir, 'scripts', 'remediation_bot.py');
  const reportsDir = process.env.REPORTS_DIR || path.join(workspaceDir, 'reports');
  const sampleAppDir = path.join(workspaceDir, 'sample-app');

  // Command to execute
  const cmd = `python3 "${botScript}" --mode "${remMode}" --sca-report "${path.join(reportsDir, 'trivy-sca-results.json')}" --container-report "${path.join(reportsDir, 'trivy-container-results.json')}" --package-json "${path.join(sampleAppDir, 'package.json')}" --dockerfile "${path.join(sampleAppDir, 'Dockerfile')}" --output "${path.join(reportsDir, 'remediation-pr.json')}"`;

  try {
    const { stdout, stderr } = await execPromise(cmd, { cwd: workspaceDir });
    console.log('[Remediation Bot Output]:\n', stdout);

    const prResultFile = path.join(reportsDir, 'remediation-pr.json');
    const resultData = readJsonFile(prResultFile, {
      status: 'SUCCESS',
      message: 'Remediation completed successfully',
      rawOutput: stdout
    });

    res.json({
      success: true,
      ...resultData
    });
  } catch (error) {
    console.error('[Remediation Error]:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      stderr: error.stderr
    });
  }
});

// API: Shannon AI Pentest Report Endpoint
app.get('/api/pentest-report', (req, res) => {
  const shannonDir = path.join(REPORTS_DIR, 'shannon');
  const reconFile = path.join(shannonDir, 'recon_deliverable.md');
  const preReconFile = path.join(shannonDir, 'pre_recon_deliverable.md');

  let rawRecon = '';
  let rawPreRecon = '';
  let hasReports = false;

  if (fs.existsSync(reconFile)) {
    rawRecon = fs.readFileSync(reconFile, 'utf8');
    hasReports = true;
  }
  if (fs.existsSync(preReconFile)) {
    rawPreRecon = fs.readFileSync(preReconFile, 'utf8');
  }

  const findings = [
    {
      id: "SHANNON-01",
      title: "Command Injection via exec()",
      category: "Command Injection",
      severity: "CRITICAL",
      endpoint: "GET /api/ping",
      parameter: "host",
      file: "sample-app/server.js",
      line: 33,
      triggerCode: "exec(`ping -c 1 ${host}`, ...)",
      pocPayload: "/api/ping?host=127.0.0.1; whoami",
      description: "Direct string concatenation into shell executor without validation allows arbitrary system command execution.",
      remediation: "Use child_process.execFile with parameter array or strict IP regex validation.",
      aiConfidence: 0.99
    },
    {
      id: "SHANNON-02",
      title: "SQL Injection in User Lookup",
      category: "SQL Injection",
      severity: "HIGH",
      endpoint: "GET /api/users",
      parameter: "username",
      file: "sample-app/server.js",
      line: 44,
      triggerCode: "SELECT * FROM users WHERE username = '\" + username + \"'",
      pocPayload: "/api/users?username=admin' OR '1'='1",
      description: "Unsanitized user-supplied parameter is concatenated directly into SQL query string.",
      remediation: "Use parameterized queries or prepared statements to separate code from user data.",
      aiConfidence: 0.98
    },
    {
      id: "SHANNON-03",
      title: "Reflected Cross-Site Scripting (XSS)",
      category: "Cross-Site Scripting",
      severity: "MEDIUM",
      endpoint: "GET /api/greet",
      parameter: "name",
      file: "sample-app/server.js",
      line: 56,
      triggerCode: "res.send(`<h1>Hello, ${name}!</h1>`)",
      pocPayload: "/api/greet?name=<script>alert('XSS')</script>",
      description: "Reflected user input in HTTP response body without context-aware HTML encoding.",
      remediation: "Encode HTML entities or use safe templating libraries (EJS with <%= %> escaping).",
      aiConfidence: 0.95
    },
    {
      id: "SHANNON-04",
      title: "Arbitrary File Read / Path Traversal",
      category: "Path Traversal",
      severity: "HIGH",
      endpoint: "GET /api/view-log",
      parameter: "file",
      file: "sample-app/server.js",
      line: 62,
      triggerCode: "fs.readFileSync(path.join(__dirname, 'logs', filename), 'utf8')",
      pocPayload: "/api/view-log?file=../../../../etc/passwd",
      description: "Attacker can supply relative dot-dot-slash sequence to read files outside the designated log directory.",
      remediation: "Validate filenames against an allowlist and check path.resolve() does not escape root.",
      aiConfidence: 0.96
    },
    {
      id: "SHANNON-05",
      title: "Prototype Pollution via Lodash Merge",
      category: "Prototype Pollution",
      severity: "HIGH",
      endpoint: "POST /api/merge",
      parameter: "req.body",
      file: "sample-app/server.js",
      line: 73,
      triggerCode: "_.merge(target, req.body)",
      pocPayload: "POST /api/merge with {\"__proto__\": {\"polluted\": true}}",
      description: "Unsanitized recursive object merge on vulnerable Lodash allows modifying Object.prototype.",
      remediation: "Upgrade lodash to latest non-vulnerable version (>=4.17.21) or filter __proto__ keys.",
      aiConfidence: 0.94
    },
    {
      id: "SHANNON-06",
      title: "Guarded Input Whitelist (Safe Control)",
      category: "Input Validation Guard",
      severity: "SAFE",
      endpoint: "GET /api/system-status",
      parameter: "service",
      file: "sample-app/server.js",
      line: 93,
      triggerCode: "if (!ALLOWED_SERVICES.includes(requestedService)) return res.status(400)...",
      pocPayload: "N/A - Whitelist enforcer verified",
      description: "AI Pentester AST verification confirmed that user input is restricted to a strict whitelist before reaching exec().",
      remediation: "Confirmed secure pattern.",
      aiConfidence: 1.0
    }
  ];

  const inventory = [
    { method: "GET", path: "/api/greet", role: "anon", param: "name", vuln: "Reflected XSS", file: "server.js:56" },
    { method: "POST", path: "/api/merge", role: "anon", param: "req.body", vuln: "Prototype Pollution", file: "server.js:73" },
    { method: "GET", path: "/api/ping", role: "anon", param: "host", vuln: "Command Injection", file: "server.js:33" },
    { method: "GET", path: "/api/system-status", role: "anon", param: "service", vuln: "Guarded (Safe)", file: "server.js:93" },
    { method: "GET", path: "/api/users", role: "anon", param: "username", vuln: "SQL Injection", file: "server.js:44" },
    { method: "GET", path: "/api/view-log", role: "anon", param: "file", vuln: "Path Traversal", file: "server.js:62" },
    { method: "POST", path: "/api/login", role: "anon", param: "username, password", vuln: "Hardcoded Secret Signing", file: "server.js:134" }
  ];

  res.json({
    hasReports,
    targetUrl: "http://host.docker.internal:3000",
    framework: "Shannon AI Pentester v3.5.0 (Keygraph)",
    aiModel: "OpenAI GPT-4o Protocol -> LiteLLM Proxy -> Google Gemini Pool",
    scanType: "White-Box Hybrid (Repository AST Code Analysis + Live Dynamic Probing)",
    timestamp: fs.existsSync(reconFile) ? fs.statSync(reconFile).mtime.toISOString() : new Date().toISOString(),
    stats: {
      totalVectors: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      safeGuards: findings.filter(f => f.severity === 'SAFE').length
    },
    findings,
    inventory,
    rawRecon,
    rawPreRecon
  });
});


// Serve frontend build static files in production
const distPath = path.join(__dirname, 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      }
    }
  }));
  app.get('*', (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 DevSecOps Dashboard Server running on http://0.0.0.0:${PORT}`);
  console.log(`📁 Monitoring reports at: ${REPORTS_DIR}`);
});
