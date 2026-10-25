import React, { useState } from 'react';
import { Eye, ShieldAlert, CheckCircle, Search, Filter } from 'lucide-react';

export default function SastAiView({ findings = [], onInspectFinding }) {
  const [filterType, setFilterType] = useState('ALL'); // ALL, TP, FP
  const [searchQuery, setSearchQuery] = useState('');

  const filteredFindings = findings.filter((f) => {
    const isFP = f.triage?.is_false_positive;
    if (filterType === 'TP' && isFP) return false;
    if (filterType === 'FP' && !isFP) return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchCheckId = f.check_id.toLowerCase().includes(q);
      const matchPath = f.path.toLowerCase().includes(q);
      const matchSink = (f.sink_info?.code || '').toLowerCase().includes(q);
      const matchReasoning = (f.triage?.reasoning || '').toLowerCase().includes(q);
      return matchCheckId || matchPath || matchSink || matchReasoning;
    }
    return true;
  });

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    if (s === 'ERROR' || s === 'CRITICAL') return <span className="badge badge-critical">CRITICAL</span>;
    if (s === 'WARNING' || s === 'HIGH') return <span className="badge badge-high">HIGH</span>;
    if (s === 'MEDIUM') return <span className="badge badge-medium">MEDIUM</span>;
    return <span className="badge badge-low">LOW</span>;
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      {/* Controls Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            className={`btn-inspect ${filterType === 'ALL' ? 'active' : ''}`}
            style={{ background: filterType === 'ALL' ? 'var(--accent-indigo)' : 'rgba(255,255,255,0.06)', color: '#fff' }}
            onClick={() => setFilterType('ALL')}
          >
            Tümü ({findings.length})
          </button>
          <button
            className="btn-inspect"
            style={{
              background: filterType === 'TP' ? '#ef4444' : 'rgba(239, 68, 68, 0.1)',
              borderColor: 'rgba(239, 68, 68, 0.3)',
              color: filterType === 'TP' ? '#fff' : '#f87171'
            }}
            onClick={() => setFilterType('TP')}
          >
            Sadece Gerçek Açıklar (TP)
          </button>
          <button
            className="btn-inspect"
            style={{
              background: filterType === 'FP' ? '#10b981' : 'rgba(16, 185, 129, 0.1)',
              borderColor: 'rgba(16, 185, 129, 0.3)',
              color: filterType === 'FP' ? '#fff' : '#34d399'
            }}
            onClick={() => setFilterType('FP')}
          >
            AI ile Elenen Yanlış Alarmlar (FP)
          </button>
        </div>

        {/* Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#1e293b', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '6px 12px' }}>
          <Search size={14} color="#94a3b8" />
          <input
            type="text"
            placeholder="Kural, dosya veya sink ara..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ background: 'none', border: 'none', color: '#fff', fontSize: '13px', outline: 'none', width: '220px' }}
          />
        </div>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <table className="security-table">
          <thead>
            <tr>
              <th style={{ width: '130px' }}>AI Kararı</th>
              <th style={{ width: '90px' }}>Önem</th>
              <th>Kural Kimliği & Açıklama</th>
              <th>Dosya & Satır (Sink)</th>
              <th>Zafiyetli Kod Satırı (Sink)</th>
              <th style={{ width: '110px' }}>AI Güven</th>
              <th style={{ width: '120px', textAlign: 'right' }}>İşlem</th>
            </tr>
          </thead>
          <tbody>
            {filteredFindings.length > 0 ? (
              filteredFindings.map((finding) => {
                const isFP = finding.triage?.is_false_positive;
                const sinkCode = finding.sink_info?.code || finding.snippet || '-';
                return (
                  <tr key={finding.finding_id}>
                    <td>
                      <span className={`badge ${isFP ? 'badge-fp' : 'badge-tp'}`}>
                        {isFP ? <CheckCircle size={12} /> : <ShieldAlert size={12} />}
                        {isFP ? 'FALSE POS' : 'TRUE POS'}
                      </span>
                    </td>
                    <td>{getSeverityBadge(finding.severity)}</td>
                    <td>
                      <div style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '13px' }}>
                        {finding.check_id}
                      </div>
                      <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '2px', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {finding.message}
                      </div>
                    </td>
                    <td>
                      <code style={{ color: '#38bdf8', fontSize: '12px' }}>
                        {finding.path}:{finding.line}
                      </code>
                    </td>
                    <td>
                      <div style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        background: 'rgba(0,0,0,0.3)',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        maxWidth: '280px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        color: isFP ? '#6ee7b7' : '#fca5a5',
                        borderLeft: `2px solid ${isFP ? '#10b981' : '#ef4444'}`
                      }}>
                        {sinkCode}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: isFP ? '#34d399' : '#f87171' }}>
                        %{finding.triage?.confidence_score || 0}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-inspect"
                        onClick={() => onInspectFinding(finding)}
                        title="Zafiyetli Pattern & Sink İncele"
                      >
                        <Eye size={13} />
                        <span>Kodu İncele</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '32px', color: '#64748b' }}>
                  Filtreye uygun SAST bulgusu bulunamadı.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
