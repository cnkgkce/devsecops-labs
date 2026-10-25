import React, { useState } from 'react';
import { X, GitPullRequest, ShieldCheck, CheckCircle2, AlertCircle, Loader2, ArrowRight, Server, Package, ExternalLink, Sparkles } from 'lucide-react';

export default function RemediationModal({ isOpen, onClose, initialMode = 'all', onRemediationComplete }) {
  if (!isOpen) return null;

  const [mode, setMode] = useState(initialMode);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleRemediate = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Otomatik PR oluşturulurken bir hata oluştu.');
      }

      setResult(data);
      if (onRemediationComplete) {
        onRemediationComplete(data);
      }
    } catch (err) {
      console.error('Remediation error:', err);
      setError(err.message || 'Bilinmeyen bir hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(5, 7, 15, 0.82)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '20px'
    }}>
      <div style={{
        background: '#0d1322',
        border: '1px solid #2a3449',
        borderRadius: '16px',
        width: '100%',
        maxWidth: '620px',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 35px rgba(99, 102, 241, 0.2)',
        overflow: 'hidden',
        animation: 'fadeIn 0.2s ease-out'
      }}>
        {/* Header */}
        <div style={{
          padding: '18px 24px',
          borderBottom: '1px solid #1e293b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'linear-gradient(90deg, rgba(99, 102, 241, 0.12) 0%, rgba(168, 85, 247, 0.08) 100%)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
              padding: '8px',
              borderRadius: '10px',
              color: '#fff',
              display: 'flex'
            }}>
              <GitPullRequest size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', margin: 0, display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>1-Click Otomatik Remediation PR Motoru</span>
                <Sparkles size={14} color="#f59e0b" />
              </h3>
              <p style={{ fontSize: '12px', color: '#94a3b8', margin: '2px 0 0 0' }}>
                Zafiyetleri kapatan güvenli branch oluşturup GitHub'a otomatik PR açar
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px',
              display: 'flex'
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '24px' }}>
          {!result ? (
            <>
              {/* Target Mode Selector */}
              <label style={{ fontSize: '13px', fontWeight: 600, color: '#cbd5e1', marginBottom: '10px', display: 'block' }}>
                Düzeltme Kapsamını Seçin:
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '20px' }}>
                <button
                  type="button"
                  onClick={() => setMode('all')}
                  style={{
                    padding: '12px 10px',
                    borderRadius: '10px',
                    border: mode === 'all' ? '2px solid #6366f1' : '1px solid #1e293b',
                    background: mode === 'all' ? 'rgba(99, 102, 241, 0.15)' : '#090d16',
                    color: mode === 'all' ? '#fff' : '#94a3b8',
                    cursor: 'pointer',
                    textAlign: 'center',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: '13px', color: mode === 'all' ? '#818cf8' : '#e2e8f0' }}>⚡ Tümü (Hepsi)</div>
                  <div style={{ fontSize: '11px', marginTop: '4px', opacity: 0.8 }}>SCA + Container</div>
                </button>

                <button
                  type="button"
                  onClick={() => setMode('container')}
                  style={{
                    padding: '12px 10px',
                    borderRadius: '10px',
                    border: mode === 'container' ? '2px solid #a855f7' : '1px solid #1e293b',
                    background: mode === 'container' ? 'rgba(168, 85, 247, 0.15)' : '#090d16',
                    color: mode === 'container' ? '#fff' : '#94a3b8',
                    cursor: 'pointer',
                    textAlign: 'center',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: '13px', color: mode === 'container' ? '#c084fc' : '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
                    <Server size={14} /> Konteyner
                  </div>
                  <div style={{ fontSize: '11px', marginTop: '4px', opacity: 0.8 }}>Dockerfile Base Image</div>
                </button>

                <button
                  type="button"
                  onClick={() => setMode('sca')}
                  style={{
                    padding: '12px 10px',
                    borderRadius: '10px',
                    border: mode === 'sca' ? '2px solid #f59e0b' : '1px solid #1e293b',
                    background: mode === 'sca' ? 'rgba(245, 158, 11, 0.15)' : '#090d16',
                    color: mode === 'sca' ? '#fff' : '#94a3b8',
                    cursor: 'pointer',
                    textAlign: 'center',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: '13px', color: mode === 'sca' ? '#fbbf24' : '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
                    <Package size={14} /> SCA Paketleri
                  </div>
                  <div style={{ fontSize: '11px', marginTop: '4px', opacity: 0.8 }}>package.json / Lock</div>
                </button>
              </div>

              {/* Actions Preview Box */}
              <div style={{
                background: '#090d16',
                border: '1px solid #1e293b',
                borderRadius: '10px',
                padding: '16px',
                marginBottom: '20px'
              }}>
                <div style={{ fontSize: '12px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                  Uygulanacak Güvenlik İyileştirmeleri Önizlemesi:
                </div>

                {(mode === 'all' || mode === 'container') && (
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', marginBottom: '12px' }}>
                    <Server size={16} color="#a855f7" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <div style={{ fontSize: '13px' }}>
                      <div style={{ color: '#fff', fontWeight: 600 }}>Dockerfile Taban İmajı Güncellemesi:</div>
                      <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '3px' }}>
                        <code>node:16.14.0-alpine</code> (Alpine 3.15 EOL) ➡️ <code>node:20-alpine</code> (LTS)
                      </div>
                      <div style={{ color: '#10b981', fontSize: '11px', marginTop: '2px' }}>
                        ✓ 13 adet OS CVE'sini (zlib, OpenSSL 1.1, busybox) ve root kullanıcı açığını kapatır.
                      </div>
                    </div>
                  </div>
                )}

                {(mode === 'all' || mode === 'sca') && (
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                    <Package size={16} color="#f59e0b" style={{ marginTop: '2px', flexShrink: 0 }} />
                    <div style={{ fontSize: '13px' }}>
                      <div style={{ color: '#fff', fontWeight: 600 }}>NPM Bağımlılıkları Semver Güncellemesi:</div>
                      <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '3px' }}>
                        <code>axios</code>, <code>express</code>, <code>lodash</code>, <code>moment</code> en yüksek temiz sürüme kilitlenir.
                      </div>
                      <div style={{ color: '#10b981', fontSize: '11px', marginTop: '2px' }}>
                        ✓ 25 adet uygulama bağımlılık zafiyetini (SSRF, Prototype Pollution vb.) tamamen sıfırlar.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {error && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid #ef4444',
                  borderRadius: '8px',
                  padding: '12px',
                  marginBottom: '18px',
                  color: '#f87171',
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <span>{error}</span>
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button
                  type="button"
                  onClick={onClose}
                  disabled={loading}
                  style={{
                    background: '#1e293b',
                    color: '#94a3b8',
                    border: 'none',
                    padding: '10px 18px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  İptal
                </button>

                <button
                  type="button"
                  onClick={handleRemediate}
                  disabled={loading}
                  style={{
                    background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
                    color: '#fff',
                    border: 'none',
                    padding: '10px 22px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    fontWeight: 700,
                    cursor: loading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)'
                  }}
                >
                  {loading ? (
                    <>
                      <Loader2 size={16} className="spin" />
                      <span>Branch & PR Hazırlanıyor...</span>
                    </>
                  ) : (
                    <>
                      <GitPullRequest size={16} />
                      <span>🚀 Otomatik PR Oluştur</span>
                    </>
                  )}
                </button>
              </div>
            </>
          ) : (
            /* Result Screen */
            <div style={{ textAlign: 'center', padding: '10px 0' }}>
              <div style={{
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                width: '60px',
                height: '60px',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px auto'
              }}>
                <CheckCircle2 size={36} />
              </div>

              <h4 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', margin: '0 0 6px 0' }}>
                🎉 Pull Request Başarıyla Hazırlandı!
              </h4>
              <p style={{ fontSize: '13px', color: '#94a3b8', margin: '0 0 20px 0' }}>
                Güvenlik yamaları içeren branch GitHub'a pushlandı ve Pull Request bağlantısı oluşturuldu.
              </p>

              <div style={{
                background: '#090d16',
                border: '1px solid #1e293b',
                borderRadius: '10px',
                padding: '16px',
                textAlign: 'left',
                marginBottom: '24px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px' }}>
                  <span style={{ color: '#94a3b8' }}>Hedef Git Branch:</span>
                  <code style={{ color: '#38bdf8' }}>{result.branch}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px' }}>
                  <span style={{ color: '#94a3b8' }}>Kapatılan Zafiyet Sayısı:</span>
                  <strong style={{ color: '#10b981' }}>{result.total_cves_resolved || 0} CVE</strong>
                </div>
                {result.smoke_test && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px' }}>
                    <span style={{ color: '#94a3b8' }}>Build & Runtime Testi:</span>
                    <span style={{ color: result.smoke_test.passed ? '#10b981' : '#ef4444', fontWeight: 600 }}>
                      {result.smoke_test.passed ? '✅ Docker Build & Health Check PASSED' : '❌ Test Başarısız'}
                    </span>
                  </div>
                )}
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: '#94a3b8' }}>Durum:</span>
                  <span style={{ color: '#6366f1', fontWeight: 600 }}>{result.status || 'PR_READY'}</span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
                {result.pr_url && (
                  <a
                    href={result.pr_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                      color: '#fff',
                      textDecoration: 'none',
                      padding: '11px 22px',
                      borderRadius: '8px',
                      fontSize: '13px',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      boxShadow: '0 4px 14px rgba(16, 185, 129, 0.4)'
                    }}
                  >
                    <span>GitHub'da PR'ı Görüntüle</span>
                    <ExternalLink size={15} />
                  </a>
                )}

                <button
                  onClick={onClose}
                  style={{
                    background: '#1e293b',
                    color: '#fff',
                    border: 'none',
                    padding: '11px 20px',
                    borderRadius: '8px',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Kapat
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
