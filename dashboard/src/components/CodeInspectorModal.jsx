import React from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Terminal, Code2, Sparkles } from 'lucide-react';

export default function CodeInspectorModal({ finding, onClose }) {
  if (!finding) return null;

  const isFP = finding.triage?.is_false_positive;
  const confidence = finding.triage?.confidence_score || 0;
  const sinkInfo = finding.sink_info || {};

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              background: isFP ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
              color: isFP ? '#34d399' : '#f87171',
              padding: '8px',
              borderRadius: '8px',
              display: 'flex'
            }}>
              {isFP ? <CheckCircle size={22} /> : <ShieldAlert size={22} />}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
                  {finding.check_id}
                </h3>
                <span className={`badge ${isFP ? 'badge-fp' : 'badge-tp'}`}>
                  {isFP ? 'FALSE POSITIVE (ELENDİ)' : 'TRUE POSITIVE (EYLEM GEREKLİ)'}
                </span>
              </div>
              <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '2px' }}>
                Dosya: <code style={{ color: '#38bdf8' }}>{finding.path}</code> (Hedef Satır / Sink: <strong>{finding.line}</strong>)
              </p>
            </div>
          </div>
          <button className="close-btn" onClick={onClose} title="Kapat">
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div className="modal-body">
          {/* Sink Info Banner */}
          <div style={{
            background: isFP ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${isFP ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
            borderRadius: '10px',
            padding: '14px 18px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Terminal size={18} color={isFP ? '#34d399' : '#f87171'} />
              <div>
                <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 600 }}>
                  Zafiyetli Pattern & Sink Tespiti
                </span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: '#fff', marginTop: '2px' }}>
                  Satır {finding.line}: <code>{sinkInfo.code || finding.snippet || 'Pattern matched'}</code>
                </div>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>AI Güven Skoru</span>
              <div style={{ fontSize: '18px', fontWeight: 800, color: isFP ? '#34d399' : '#f87171' }}>
                %{confidence}
              </div>
            </div>
          </div>

          {/* Code Viewer with Sink Line Highlight */}
          <div className="code-viewer-container">
            <div className="code-viewer-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Code2 size={16} />
                <span>Kaynak Kod & Taint Bağlamı</span>
              </div>
              <span>{finding.path}</span>
            </div>
            <div className="code-lines-list">
              {finding.code_lines && finding.code_lines.length > 0 ? (
                finding.code_lines.map((item) => (
                  <div
                    key={item.line}
                    className={`code-line-row ${
                      item.is_sink ? (isFP ? 'safe-highlight' : 'sink-highlight') : ''
                    }`}
                  >
                    <span className="code-line-num">{item.line}</span>
                    <span className="code-line-text">{item.code}</span>
                    {item.is_sink && (
                      <span className={isFP ? 'safe-tag' : 'sink-tag'}>
                        {isFP ? 'SAFE SINK (KORUMALI)' : 'VULNERABLE SINK (PATLAMA NOKTASI)'}
                      </span>
                    )}
                  </div>
                ))
              ) : (
                <div style={{ padding: '16px', color: '#64748b' }}>
                  Kod bağlamı bulunamadı: {finding.code_context || finding.message}
                </div>
              )}
            </div>
          </div>

          {/* AI Analysis Reasoning Card */}
          <div className="ai-analysis-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a855f7', fontWeight: 700, fontSize: '14px' }}>
              <Sparkles size={18} />
              <span>AI Karar Analizi & False Positive Eliminasyon Mantığı</span>
            </div>
            <p className="ai-reasoning-text">
              {finding.triage?.reasoning || 'AI analizi bulunamadı.'}
            </p>

            {finding.triage?.remediation_advice && (
              <div className="ai-remediation-box">
                <strong>💡 AppSec İyileştirme Önerisi: </strong>
                {finding.triage.remediation_advice}
              </div>
            )}
          </div>

          {/* Rule Message & Metadata */}
          <div style={{
            background: 'rgba(15, 23, 42, 0.5)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '14px 18px',
            fontSize: '13px'
          }}>
            <div style={{ color: '#94a3b8', fontWeight: 600, marginBottom: '4px' }}>
              Semgrep Kural Açıklaması:
            </div>
            <div style={{ color: '#cbd5e1', lineHeight: '1.5' }}>
              {finding.message}
            </div>
            {finding.cwe && finding.cwe.length > 0 && (
              <div style={{ marginTop: '8px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {finding.cwe.map((c, i) => (
                  <span key={i} className="badge badge-low">{c}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
