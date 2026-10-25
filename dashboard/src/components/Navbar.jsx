import React from 'react';
import { Shield, RefreshCw, Layers } from 'lucide-react';

export default function Navbar({ apps, selectedApp, onSelectApp, onRefresh, loading }) {
  return (
    <header className="navbar">
      <div className="nav-brand">
        <div className="brand-icon">
          <Shield size={20} />
        </div>
        <div>
          <h1 className="brand-title">DevSecOps Lab</h1>
          <p className="brand-subtitle">AI-Powered Security Pipeline & Triage</p>
        </div>
      </div>

      <div className="app-switcher-container">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8', fontSize: '13px' }}>
          <Layers size={16} />
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

        <button className="refresh-btn" onClick={onRefresh} disabled={loading} title="Raporları Yenile">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>{loading ? 'Yenileniyor...' : 'Yenile'}</span>
        </button>
      </div>
    </header>
  );
}
