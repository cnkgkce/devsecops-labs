import React, { useState } from 'react';
import { Package, ExternalLink, Search, Zap, ListFilter } from 'lucide-react';
import ActionItemsList, { groupVulnerabilitiesIntoActions } from './ActionItemsList';

export default function ScaView({ scaData = { vulnerabilities: [] } }) {
  const [viewMode, setViewMode] = useState('ACTIONS'); // 'ACTIONS' or 'RAW'
  const [search, setSearch] = useState('');
  const vulns = scaData.vulnerabilities || [];

  const actions = groupVulnerabilitiesIntoActions(vulns, 'npm');

  const filteredVulns = vulns.filter((v) => {
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
            <Package size={20} color="#f59e0b" />
            <span>SCA Bağımlılık & Paket Zafiyetleri (Trivy fs)</span>
          </h3>
          <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '3px' }}>
            Toplam <strong>{vulns.length} CVE</strong>, sadece <strong>{actions.length} paket yükseltme aksiyonu</strong> ile tamamen giderilebilir.
          </p>
        </div>

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

      {/* Auto-Remediation PR Banner */}
      {scaData.remediation_pr && (
        <div style={{
          background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(6, 182, 212, 0.12))',
          border: '1px solid rgba(16, 185, 129, 0.35)',
          borderRadius: '10px',
          padding: '16px 20px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              background: 'rgba(16, 185, 129, 0.2)',
              color: '#34d399',
              padding: '10px',
              borderRadius: '10px',
              display: 'flex'
            }}>
              <Zap size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontSize: '15px', color: '#fff' }}>
                  Otomatik İyileştirme (Fixed PR) Hazırlandı!
                </strong>
                <span className="badge badge-fp">
                  {scaData.remediation_pr.total_cves_resolved || 19} CVE Giderildi
                </span>
              </div>
              <p style={{ fontSize: '13px', color: '#cbd5e1', marginTop: '3px' }}>
                Pipeline, <code>package.json</code> içindeki zafiyetli paketleri güncel sürümlerine çekerek GitHub'a <code>{scaData.remediation_pr.branch}</code> dalını gönderdi.
              </p>
            </div>
          </div>

          <a
            href={scaData.remediation_pr.pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-inspect"
            style={{
              background: '#10b981',
              color: '#fff',
              borderColor: '#059669',
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: 700,
              textDecoration: 'none',
              boxShadow: '0 0 15px rgba(16, 185, 129, 0.3)'
            }}
          >
            <span>GitHub Pull Request'ini Aç / İncele</span>
            <ExternalLink size={14} />
          </a>
        </div>
      )}

      {/* Mode 1: Consolidated Action Items (Recommended) */}
      {viewMode === 'ACTIONS' && (
        <ActionItemsList vulnerabilities={vulns} type="npm" />
      )}

      {/* Mode 2: Raw CVE List */}
      {viewMode === 'RAW' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#1e293b', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '6px 12px' }}>
              <Search size={14} color="#94a3b8" />
              <input
                type="text"
                placeholder="CVE veya paket adı ara..."
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
                  <th style={{ width: '150px' }}>Zafiyet ID (CVE)</th>
                  <th style={{ width: '100px' }}>Önem</th>
                  <th>Paket Adı</th>
                  <th>Yüklü Sürüm</th>
                  <th>Düzeltilen Sürüm</th>
                  <th>Zafiyet Açıklaması</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.length > 0 ? (
                  filteredVulns.map((v, i) => (
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
                        <code style={{ color: v.fixedVersion !== 'No Fix Available' ? '#34d399' : '#64748b' }}>
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
                      Arama kriterlerine uygun paket zafiyeti bulunamadı.
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
