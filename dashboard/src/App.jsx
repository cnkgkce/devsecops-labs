import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import KpiCards from './components/KpiCards';
import SastAiView from './components/SastAiView';
import ScaView from './components/ScaView';
import ContainerView from './components/ContainerView';
import CodeInspectorModal from './components/CodeInspectorModal';
import { ShieldCheck, Package, Server, Code2 } from 'lucide-react';

export default function App() {
  const [apps, setApps] = useState([]);
  const [selectedApp, setSelectedApp] = useState('vulnerable-node-app');
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('SAST_AI'); // SAST_AI, SCA, CONTAINER
  const [inspectedFinding, setInspectedFinding] = useState(null);

  // Load apps list
  useEffect(() => {
    fetch('/api/apps')
      .then((res) => res.json())
      .then((data) => {
        setApps(data);
        if (data.length > 0 && !selectedApp) {
          setSelectedApp(data[0].id);
        }
      })
      .catch((err) => console.error('Error loading apps:', err));
  }, []);

  // Load report data when selectedApp changes
  const loadReports = () => {
    setLoading(true);
    fetch(`/api/reports?app=${selectedApp}`)
      .then((res) => res.json())
      .then((data) => {
        setReportData(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Error loading reports:', err);
        setLoading(false);
      });
  };

  useEffect(() => {
    if (selectedApp) {
      loadReports();
    }
  }, [selectedApp]);

  const sastCount = reportData?.sast?.findings?.length || 0;
  const scaCount = reportData?.sca?.total || 0;
  const containerCount = reportData?.container?.total || 0;

  return (
    <div className="app-container">
      <Navbar
        apps={apps}
        selectedApp={selectedApp}
        onSelectApp={setSelectedApp}
        onRefresh={loadReports}
        loading={loading}
      />

      <main className="main-content">
        {/* KPI Metric Overview */}
        <KpiCards data={reportData} />

        {/* Navigation Tabs */}
        <div className="tabs-nav">
          <button
            className={`tab-btn ${activeTab === 'SAST_AI' ? 'active' : ''}`}
            onClick={() => setActiveTab('SAST_AI')}
          >
            <ShieldCheck size={16} />
            <span>SAST & AI Triage (Semgrep)</span>
            <span className="tab-badge">{sastCount}</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'SCA' ? 'active' : ''}`}
            onClick={() => setActiveTab('SCA')}
          >
            <Package size={16} />
            <span>SCA Paket Bağımlılıkları (Trivy fs)</span>
            <span className="tab-badge">{scaCount}</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'CONTAINER' ? 'active' : ''}`}
            onClick={() => setActiveTab('CONTAINER')}
          >
            <Server size={16} />
            <span>Konteyner Güvenliği (Trivy image)</span>
            <span className="tab-badge">{containerCount}</span>
          </button>
        </div>

        {/* Tab Content */}
        {loading ? (
          <div className="glass-panel" style={{ padding: '60px', textAlign: 'center', color: '#94a3b8' }}>
            <div className="animate-spin" style={{ display: 'inline-block', marginBottom: '12px' }}>
              🌀
            </div>
            <p>Zafiyet raporları yükleniyor...</p>
          </div>
        ) : (
          <>
            {activeTab === 'SAST_AI' && (
              <SastAiView
                findings={reportData?.sast?.findings || []}
                onInspectFinding={(finding) => setInspectedFinding(finding)}
              />
            )}

            {activeTab === 'SCA' && (
              <ScaView scaData={reportData?.sca || {}} />
            )}

            {activeTab === 'CONTAINER' && (
              <ContainerView containerData={reportData?.container || {}} />
            )}
          </>
        )}
      </main>

      {/* Code & Sink Inspector Modal */}
      {inspectedFinding && (
        <CodeInspectorModal
          finding={inspectedFinding}
          onClose={() => setInspectedFinding(null)}
        />
      )}
    </div>
  );
}
