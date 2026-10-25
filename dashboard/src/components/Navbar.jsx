import React from 'react';
import { Shield, RefreshCw, Layers, History, GitCommit } from 'lucide-react';

export default function Navbar({
  apps = [],
  selectedApp,
  onSelectApp,
  builds = [],
  selectedBuild,
  onSelectBuild,
  onRefresh,
  loading
}) {
  return (
    <header className="navbar">
      <div className="nav-brand">
        <div className="brand-icon">
          <Shield size={20} />
        </div>
        <div>
          <h1 className="brand-title">DevSecOps Lab</h1>
          <p className="brand-subtitle">AI-Powered Security Pipeline & Build History</p>
        </div>
      </div>

      <div className="app-switcher-container">
        {/* App Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#94a3b8', fontSize: '13px' }}>
          <Layers size={15} />
          <span>Uygulama:</span>
        </div>
        <select
          className="app-select"
          value={selectedApp}
          onChange={(e) => onSelectApp(e.target.value)}
        >
          {apps.map((app) => (
            <option key={app.id} value={app.id}>
              {app.name} ({app.runtime})
            </option>
          ))}
        </select>

        {/* Build Selector (Per-Build History) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#94a3b8', fontSize: '13px', marginLeft: '6px' }}>
          <History size={15} />
          <span>Build:</span>
        </div>
        <select
          className="app-select"
          value={selectedBuild || 'latest'}
          onChange={(e) => onSelectBuild(e.target.value)}
          style={{ background: '#111827', borderColor: 'rgba(99, 102, 241, 0.4)', fontWeight: 600, color: '#a5b4fc' }}
        >
          <option value="latest">Son Çalışan (Latest)</option>
          {builds.map((b) => (
            <option key={b.buildNumber} value={b.buildNumber}>
              Build #{b.buildNumber} {b.isLatest ? '(En Son)' : ''} ({b.commit ? b.commit.slice(0, 7) : ''})
            </option>
          ))}
        </select>

        {/* Refresh Button */}
        <button className="refresh-btn" onClick={onRefresh} disabled={loading} title="Raporları ve Buildleri Yenile">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>{loading ? 'Yenileniyor...' : 'Yenile'}</span>
        </button>
      </div>
    </header>
  );
}
