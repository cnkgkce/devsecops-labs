import React from 'react';
import { History, GitCommit, Clock, TrendingDown, CheckCircle, ArrowRight, ShieldCheck, Sparkles } from 'lucide-react';

export default function BuildCompareBanner({ currentBuildInfo, builds = [], onOpenRemediation }) {
  if (!currentBuildInfo) return null;

  const effectiveBuildNumber = (currentBuildInfo.buildNumber === 'latest' && builds.length > 0)
    ? builds[0].buildNumber
    : currentBuildInfo.buildNumber;

  const currentMeta = builds.find(b => b.buildNumber === String(effectiveBuildNumber)) || {};

  // Find previous build if available
  const currentIndex = builds.findIndex(b => b.buildNumber === String(effectiveBuildNumber));
  const previousBuild = currentIndex >= 0 && currentIndex + 1 < builds.length ? builds[currentIndex + 1] : null;

  let scaDiff = 0;
  let hasComparison = false;
  if (previousBuild && currentMeta.sca_total !== undefined && previousBuild.sca_total !== undefined) {
    scaDiff = currentMeta.sca_total - previousBuild.sca_total;
    hasComparison = true;
  }

  return (
    <div style={{
      background: 'rgba(15, 23, 42, 0.65)',
      border: '1px solid var(--border-color)',
      borderRadius: '10px',
      padding: '12px 18px',
      marginBottom: '20px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'wrap',
      gap: '12px'
    }}>
      {/* Current Build Details */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontWeight: 700, fontSize: '14px' }}>
          <History size={16} color="var(--accent-indigo)" />
          <span>Aktif Build:</span>
          <span style={{
            background: 'var(--accent-indigo)',
            color: '#fff',
            padding: '2px 8px',
            borderRadius: '6px',
            fontSize: '12px'
          }}>
            #{effectiveBuildNumber}
          </span>
        </div>

        {currentBuildInfo.commit && currentBuildInfo.commit !== 'unknown' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: '#94a3b8' }}>
            <GitCommit size={14} />
            <span>Commit:</span>
            <code style={{ color: '#38bdf8' }}>{currentBuildInfo.commit.slice(0, 7)}</code>
          </div>
        )}

        {currentBuildInfo.timestamp && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: '#94a3b8' }}>
            <Clock size={14} />
            <span>Tarih:</span>
            <span>{new Date(currentBuildInfo.timestamp).toLocaleString('tr-TR')}</span>
          </div>
        )}
      </div>

      {/* Comparison with Previous Build (Diff) */}
      {hasComparison && previousBuild && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '12px', color: '#94a3b8' }}>
            Build #{previousBuild.buildNumber} ile karşılaştırma:
          </span>

          {scaDiff < 0 ? (
            <span style={{
              background: 'rgba(16, 185, 129, 0.2)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: '8px',
              padding: '4px 10px',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <CheckCircle size={14} />
              {Math.abs(scaDiff)} Zafiyet Giderildi! ({previousBuild.sca_total} ➔ {currentMeta.sca_total})
            </span>
          ) : scaDiff > 0 ? (
            <span style={{
              background: 'rgba(239, 68, 68, 0.2)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              borderRadius: '8px',
              padding: '4px 10px',
              fontSize: '12px',
              fontWeight: 700
            }}>
              +{scaDiff} Yeni Zafiyet Eklendi
            </span>
          ) : (
            <span style={{
              background: 'rgba(255, 255, 255, 0.08)',
              color: '#cbd5e1',
              borderRadius: '8px',
              padding: '4px 10px',
              fontSize: '12px'
            }}>
              Zafiyet sayısı değişmedi ({currentMeta.sca_total})
            </span>
          )}
        </div>
      )}

      {/* 1-Click Remediation Button */}
      {onOpenRemediation && (
        <button
          type="button"
          onClick={() => onOpenRemediation('all')}
          style={{
            background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
            color: '#fff',
            border: 'none',
            borderRadius: '8px',
            padding: '7px 14px',
            fontSize: '12px',
            fontWeight: 700,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '7px',
            boxShadow: '0 2px 10px rgba(99, 102, 241, 0.35)',
            transition: 'all 0.2s'
          }}
        >
          <Sparkles size={14} color="#fcd34d" />
          <span>1-Click Otomatik PR Aç (SCA & Container)</span>
        </button>
      )}
    </div>
  );
}
