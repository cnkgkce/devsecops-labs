import React, { useState } from 'react';
import { Server, ExternalLink, Search, Zap, ListFilter, GitPullRequest } from 'lucide-react';
import ActionItemsList, { groupVulnerabilitiesIntoActions } from './ActionItemsList';

export default function ContainerView({ containerData = { vulnerabilities: [] }, onOpenRemediation }) {
  const [viewMode, setViewMode] = useState('ACTIONS'); // 'ACTIONS' or 'RAW'
  const [search, setSearch] = useState('');
  const vulns = containerData.vulnerabilities || [];

  const actions = groupVulnerabilitiesIntoActions(vulns, 'os');

  const filtered = vulns.filter((v) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      v.cve.toLowerCase().includes(q) ||
      v.pkgName.toLowerCase().includes(q) ||
      v.title.toLowerCase().includes(q)
    );
  });

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    if (s === 'CRITICAL') return <span className="badge badge-critical">CRITICAL</span>;
    if (s === 'HIGH') return <span className="badge badge-high">HIGH</span>;
    if (s === 'MEDIUM') return <span className="badge badge-medium">MEDIUM</span>;
    return <span className="badge badge-low">LOW</span>;
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      {/* Header and View Mode Switcher */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <h3 style={{ fontSize: '17px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={20} color="#a855f7" />
            <span>Konteyner İmajı & İşletim Sistemi Güvenliği (Trivy image)</span>
          </h3>
          <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '3px' }}>
            <code>vulnerable-node-app:latest</code> (Alpine Linux) taban imajındaki <strong>{vulns.length} zafiyet</strong>, <strong>{actions.length} paket güncellemesi</strong> ile kapatılabilir.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {onOpenRemediation && (
            <button
              className="btn-inspect"
              onClick={() => onOpenRemediation('container')}
              style={{
                background: 'linear-gradient(135deg, #a855f7 0%, #7c3aed 100%)',
                color: '#fff',
                border: 'none',
                fontWeight: 600,
                boxShadow: '0 2px 10px rgba(168, 85, 247, 0.3)'
              }}
            >
              <GitPullRequest size={14} />
              <span>Dockerfile Fix PR Aç</span>
            </button>
          )}

          {/* View Mode Switcher */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#090d16', padding: '4px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
            <button
              className="btn-inspect"
              onClick={() => setViewMode('ACTIONS')}
              style={{
                background: viewMode === 'ACTIONS' ? 'var(--accent-indigo)' : 'transparent',
                color: viewMode === 'ACTIONS' ? '#fff' : '#94a3b8',
                border: 'none'
              }}
            >
              <Zap size={14} />
              <span>Toplu Aksiyon Listesi ({actions.length})</span>
            </button>

            <button
              className="btn-inspect"
              onClick={() => setViewMode('RAW')}
              style={{
                background: viewMode === 'RAW' ? 'var(--accent-indigo)' : 'transparent',
                color: viewMode === 'RAW' ? '#fff' : '#94a3b8',
                border: 'none'
              }}
            >
              <ListFilter size={14} />
              <span>Tüm CVE'ler ({vulns.length})</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mode 1: Consolidated Action Items (Recommended) */}
      {viewMode === 'ACTIONS' && (
        <ActionItemsList vulnerabilities={vulns} type="os" />
      )}

      {/* Mode 2: Raw CVE List */}
      {viewMode === 'RAW' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#1e293b', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '6px 12px' }}>
              <Search size={14} color="#94a3b8" />
              <input
                type="text"
                placeholder="CVE veya OS paketi ara..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ background: 'none', border: 'none', color: '#fff', fontSize: '13px', outline: 'none', width: '220px' }}
              />
            </div>
          </div>

          <div className="table-wrapper">
            <table className="security-table">
              <thead>
                <tr>
                  <th style={{ width: '150px' }}>CVE Kimliği</th>
                  <th style={{ width: '100px' }}>Önem</th>
                  <th>OS Paketi</th>
                  <th>Mevcut Sürüm</th>
                  <th>Düzeltilmiş Sürüm</th>
                  <th>Açıklama</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length > 0 ? (
                  filtered.map((v, i) => (
                    <tr key={`${v.cve}-${i}`}>
                      <td>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cve}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: '#38bdf8', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}
                        >
                          {v.cve}
                          <ExternalLink size={11} />
                        </a>
                      </td>
                      <td>{getSeverityBadge(v.severity)}</td>
                      <td>
                        <strong style={{ color: '#f1f5f9' }}>{v.pkgName}</strong>
                      </td>
                      <td>
                        <code style={{ color: '#f87171' }}>{v.installedVersion}</code>
                      </td>
                      <td>
                        <code style={{ color: v.fixedVersion !== 'None' ? '#34d399' : '#64748b' }}>
                          {v.fixedVersion}
                        </code>
                      </td>
                      <td style={{ color: '#cbd5e1', maxWidth: '400px', lineHeight: '1.4' }}>
                        {v.title}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '32px', color: '#64748b' }}>
                      Arama kriterlerine uygun konteyner zafiyeti bulunamadı.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
