import React from 'react';
import { ShieldAlert, ShieldCheck, Filter, Package, Server, Sparkles, GitPullRequest } from 'lucide-react';

export default function KpiCards({ data, onOpenRemediation }) {
  const sastSummary = data?.sast?.summary || {};
  const totalFindings = sastSummary.total_findings || 0;
  const truePositives = sastSummary.true_positives || 0;
  const falsePositives = sastSummary.false_positives || 0;
  const reductionRate = sastSummary.false_positive_reduction_rate || '0.0%';

  const scaTotal = data?.sca?.total || 0;
  const containerTotal = data?.container?.total || 0;

  return (
    <div className="kpi-grid">
      {/* 1. SAST Total */}
      <div className="glass-panel kpi-card">
        <div className="kpi-title">
          <span>SAST Ham Bulgular</span>
          <ShieldAlert size={18} color="#94a3b8" />
        </div>
        <div className="kpi-value">{totalFindings}</div>
        <span style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
          Semgrep statik kod analizi
        </span>
      </div>

      {/* 2. Actionable True Positives */}
      <div className="glass-panel kpi-card" style={{ borderColor: 'rgba(239, 68, 68, 0.3)' }}>
        <div className="kpi-title">
          <span style={{ color: '#f87171' }}>Gerçek Açıklar (TP)</span>
          <ShieldAlert size={18} color="#ef4444" />
        </div>
        <div className="kpi-value" style={{ color: '#ef4444' }}>{truePositives}</div>
        <span style={{ fontSize: '12px', color: '#fca5a5', marginTop: '6px' }}>
          Doğrulanan kritik tehditler
        </span>
      </div>

      {/* 3. AI Filtered False Positives */}
      <div className="glass-panel kpi-card" style={{ borderColor: 'rgba(16, 185, 129, 0.3)' }}>
        <div className="kpi-title">
          <span style={{ color: '#34d399' }}>AI Elenen (FP)</span>
          <ShieldCheck size={18} color="#10b981" />
        </div>
        <div className="kpi-value" style={{ color: '#10b981' }}>{falsePositives}</div>
        <span style={{ fontSize: '12px', color: '#6ee7b7', marginTop: '6px' }}>
          Gürültü olarak elenen alarmlar
        </span>
      </div>

      {/* 4. AI Noise Reduction Rate */}
      <div className="glass-panel kpi-card" style={{ background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12), rgba(6, 182, 212, 0.12))' }}>
        <div className="kpi-title">
          <span style={{ color: '#38bdf8' }}>AI Gürültü Azaltma</span>
          <Sparkles size={18} color="#38bdf8" />
        </div>
        <div className="kpi-value" style={{ color: '#38bdf8' }}>{reductionRate}</div>
        <span style={{ fontSize: '12px', color: '#7dd3fc', marginTop: '6px' }}>
          Geliştirici zaman tasarrufu
        </span>
      </div>

      {/* 5. SCA Vulnerabilities */}
      <div className="glass-panel kpi-card" style={{ position: 'relative' }}>
        <div className="kpi-title">
          <span>SCA Paket Açıkları</span>
          <Package size={18} color="#f59e0b" />
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
          <div className="kpi-value" style={{ color: '#f59e0b' }}>{scaTotal}</div>
          {onOpenRemediation && (
            <button
              type="button"
              onClick={() => onOpenRemediation('sca')}
              style={{
                background: 'rgba(245, 158, 11, 0.18)',
                color: '#fbbf24',
                border: '1px solid rgba(245, 158, 11, 0.4)',
                borderRadius: '6px',
                padding: '4px 8px',
                fontSize: '11px',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                transition: 'all 0.2s'
              }}
              title="SCA paketleri için otomatik fix PR oluştur"
            >
              <span>⚡ Fix PR</span>
            </button>
          )}
        </div>
        <span style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
          Trivy fs (npm kütüphaneleri)
        </span>
      </div>

      {/* 6. Container Image CVEs */}
      <div className="glass-panel kpi-card" style={{ position: 'relative' }}>
        <div className="kpi-title">
          <span>Container OS Açıkları</span>
          <Server size={18} color="#a855f7" />
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
          <div className="kpi-value" style={{ color: '#a855f7' }}>{containerTotal}</div>
          {onOpenRemediation && (
            <button
              type="button"
              onClick={() => onOpenRemediation('container')}
              style={{
                background: 'rgba(168, 85, 247, 0.18)',
                color: '#c084fc',
                border: '1px solid rgba(168, 85, 247, 0.4)',
                borderRadius: '6px',
                padding: '4px 8px',
                fontSize: '11px',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                transition: 'all 0.2s'
              }}
              title="Dockerfile base image için otomatik fix PR oluştur"
            >
              <span>⚡ Fix PR</span>
            </button>
          )}
        </div>
        <span style={{ fontSize: '12px', color: '#64748b', marginTop: '6px' }}>
          Trivy image (Docker CVE'leri)
        </span>
      </div>
    </div>
  );
}
