import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Path to mounted reports directory
const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, 'reports');

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

// API: Aggregated reports for selected app
app.get('/api/reports', (req, res) => {
  const appId = req.query.app || 'vulnerable-node-app';

  const semgrepAiPath = path.join(REPORTS_DIR, 'semgrep-ai-triaged.json');
  const semgrepRawPath = path.join(REPORTS_DIR, 'semgrep-results.json');
  const trivyScaPath = path.join(REPORTS_DIR, 'trivy-sca-results.json');
  const trivyContainerPath = path.join(REPORTS_DIR, 'trivy-container-results.json');

  const sastAi = readJsonFile(semgrepAiPath, { summary: {}, triaged_findings: [] });
  const sastRaw = readJsonFile(semgrepRawPath, { results: [] });
  const trivySca = readJsonFile(trivyScaPath, {});
  const trivyContainer = readJsonFile(trivyContainerPath, {});

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

  // Parse Trivy Container OS vulnerabilities (Strictly OS packages to eliminate duplicates with SCA)
  let containerVulnerabilities = [];
  if (trivyContainer && Array.isArray(trivyContainer.Results)) {
    for (const target of trivyContainer.Results) {
      // Exclude language-specific packages (lang-pkgs / node-pkg) which are already handled by SCA
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

  const remediationPrPath = path.join(REPORTS_DIR, 'remediation-pr.json');
  const remediationPr = readJsonFile(remediationPrPath, null);

  const payload = {
    appId,
    timestamp: new Date().toISOString(),
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

// Serve frontend build static files in production
const distPath = path.join(__dirname, 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 DevSecOps Dashboard Server running on http://0.0.0.0:${PORT}`);
  console.log(`📁 Monitoring reports at: ${REPORTS_DIR}`);
});
