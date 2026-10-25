import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Wrench, ShieldAlert, ExternalLink, Check, Copy, ArrowRight, Zap } from 'lucide-react';

// Severity weight for sorting
const SEVERITY_WEIGHT = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

export function groupVulnerabilitiesIntoActions(vulnerabilities = [], type = 'npm') {
  const groups = {};

  vulnerabilities.forEach((v) => {
    const key = v.pkgName;
    if (!groups[key]) {
      groups[key] = {
        pkgName: v.pkgName,
        installedVersion: v.installedVersion || 'unknown',
        fixedVersions: new Set(),
        cves: [],
        maxSeverity: 'INFO',
        target: v.target || ''
      };
    }

    if (v.fixedVersion && v.fixedVersion !== 'None' && v.fixedVersion !== 'No Fix Available') {
      // Clean and split comma separated versions if any
      v.fixedVersion.split(',').forEach((ver) => {
        const trimmed = ver.trim();
        if (trimmed) groups[key].fixedVersions.add(trimmed);
      });
    }

    groups[key].cves.push(v);

    // Track max severity
    const currentWeight = SEVERITY_WEIGHT[(v.severity || 'INFO').toUpperCase()] || 0;
    const maxWeight = SEVERITY_WEIGHT[groups[key].maxSeverity.toUpperCase()] || 0;
    if (currentWeight > maxWeight) {
      groups[key].maxSeverity = (v.severity || 'INFO').toUpperCase();
    }
  });

  return Object.values(groups).map((group) => {
    // Determine recommended target version
    const fixes = Array.from(group.fixedVersions);
    let recommendedVersion = 'Son Kararlı Sürüm (Latest)';
    if (fixes.length > 0) {
      // Pick the last/highest listed version
      recommendedVersion = fixes[fixes.length - 1];
    }

    // Command suggestion
    let command = '';
    if (type === 'npm') {
      command = `npm install ${group.pkgName}@${recommendedVersion.split(' ')[0].replace('>=', '')}`;
    } else {
      command = `apk add --upgrade ${group.pkgName}`;
    }

    return {
      pkgName: group.pkgName,
      installedVersion: group.installedVersion,
      recommendedVersion,
      fixedVersionsList: fixes,
      cveCount: group.cves.length,
      maxSeverity: group.maxSeverity,
      cves: group.cves,
      command,
      target: group.target
    };
  }).sort((a, b) => {
    // Sort by maxSeverity descending, then by cveCount descending
    const diffSev = (SEVERITY_WEIGHT[b.maxSeverity] || 0) - (SEVERITY_WEIGHT[a.maxSeverity] || 0);
    if (diffSev !== 0) return diffSev;
    return b.cveCount - a.cveCount;
  });
}

export default function ActionItemsList({ vulnerabilities = [], type = 'npm' }) {
  const [expandedPkgs, setExpandedPkgs] = useState({});
  const [copiedCmd, setCopiedCmd] = useState(null);

  const actions = groupVulnerabilitiesIntoActions(vulnerabilities, type);

  const toggleExpand = (pkg) => {
    setExpandedPkgs((prev) => ({
      ...prev,
      [pkg]: !prev[pkg]
    }));
  };

  const copyToClipboard = (cmd, pkg) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(pkg);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    if (s === 'CRITICAL') return <span className="badge badge-critical">CRITICAL</span>;
    if (s === 'HIGH') return <span className="badge badge-high">HIGH</span>;
    if (s === 'MEDIUM') return <span className="badge badge-medium">MEDIUM</span>;
    return <span className="badge badge-low">LOW</span>;
  };

  if (actions.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
        Herhangi bir iyileştirme aksiyonu gerekmiyor. Tüm paketler güncel.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {actions.map((action) => {
        const isExpanded = !!expandedPkgs[action.pkgName];
        const isCopied = copiedCmd === action.pkgName;

        return (
          <div
            key={action.pkgName}
            className="glass-panel"
            style={{
              padding: '16px 20px',
              borderLeft: `4px solid ${
                action.maxSeverity === 'CRITICAL'
                  ? '#ef4444'
                  : action.maxSeverity === 'HIGH'
                  ? '#f97316'
                  : '#eab308'
              }`,
              transition: 'background 0.2s ease'
            }}
          >
            {/* Action Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  background: 'rgba(99, 102, 241, 0.15)',
                  color: '#818cf8',
                  padding: '8px',
                  borderRadius: '8px',
                  display: 'flex'
                }}>
                  <Wrench size={20} />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <h4 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
                      {action.pkgName}
                    </h4>
                    {getSeverityBadge(action.maxSeverity)}
                    <span style={{
                      background: 'rgba(6, 182, 212, 0.15)',
                      color: '#22d3ee',
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: '12px',
                      border: '1px solid rgba(6, 182, 212, 0.3)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}>
                      <Zap size={12} />
                      {action.cveCount} Zafiyet Giderilecek
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px', fontSize: '13px', color: '#94a3b8' }}>
                    <span>Mevcut Sürüm: <code style={{ color: '#f87171' }}>{action.installedVersion}</code></span>
                    <ArrowRight size={14} color="#64748b" />
                    <span>Hedef Sürüm: <code style={{ color: '#34d399', fontWeight: 600 }}>{action.recommendedVersion}</code></span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  className="btn-inspect"
                  onClick={() => copyToClipboard(action.command, action.pkgName)}
                  title="Yükseltme Komutunu Kopyala"
                  style={{
                    background: isCopied ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.06)',
                    borderColor: isCopied ? '#10b981' : 'var(--border-color)',
                    color: isCopied ? '#34d399' : '#e2e8f0'
                  }}
                >
                  {isCopied ? <Check size={14} /> : <Copy size={14} />}
                  <span>{isCopied ? 'Komut Kopyalandı' : 'Komutu Kopyala'}</span>
                </button>

                <button
                  className="btn-inspect"
                  onClick={() => toggleExpand(action.pkgName)}
                  style={{ background: 'rgba(255, 255, 255, 0.06)', color: '#fff' }}
                >
                  <span>{isExpanded ? 'Detayları Gizle' : `CVE'leri Gör (${action.cveCount})`}</span>
                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>

            {/* Drill-down: Expanded CVE Table */}
            {isExpanded && (
              <div style={{
                marginTop: '16px',
                paddingTop: '16px',
                borderTop: '1px solid rgba(255, 255, 255, 0.08)'
              }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: '#94a3b8', marginBottom: '8px' }}>
                  Bu yükseltme ile tek seferde kapatılacak zafiyetler:
                </div>
                <div className="table-wrapper">
                  <table className="security-table" style={{ fontSize: '12px' }}>
                    <thead>
                      <tr>
                        <th style={{ width: '140px' }}>CVE Kimliği</th>
                        <th style={{ width: '90px' }}>Önem</th>
                        <th style={{ width: '130px' }}>Giderildiği Sürüm</th>
                        <th>Zafiyet Başlığı & Açıklama</th>
                      </tr>
                    </thead>
                    <tbody>
                      {action.cves.map((cveItem, idx) => (
                        <tr key={`${cveItem.cve}-${idx}`}>
                          <td>
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${cveItem.cve}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ color: '#38bdf8', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}
                            >
                              {cveItem.cve}
                              <ExternalLink size={11} />
                            </a>
                          </td>
                          <td>{getSeverityBadge(cveItem.severity)}</td>
                          <td>
                            <code style={{ color: '#34d399' }}>{cveItem.fixedVersion}</code>
                          </td>
                          <td style={{ color: '#cbd5e1', lineHeight: '1.4' }}>
                            {cveItem.title}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
