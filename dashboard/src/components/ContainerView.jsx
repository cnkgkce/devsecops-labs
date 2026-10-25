import React, { useState } from 'react';
import { Server, ExternalLink, Search } from 'lucide-react';

export default function ContainerView({ containerData = { vulnerabilities: [] } }) {
  const [search, setSearch] = useState('');
  const vulns = containerData.vulnerabilities || [];

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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={18} color="#a855f7" />
            <span>Konteyner İmajı & İşletim Sistemi Güvenliği (Trivy image)</span>
          </h3>
          <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '2px' }}>
            <code>vulnerable-node-app:latest</code> (Alpine Linux) taban imaj zafiyetleri
          </p>
        </div>

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
    </div>
  );
}
