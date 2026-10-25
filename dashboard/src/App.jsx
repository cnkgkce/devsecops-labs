import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import KpiCards from './components/KpiCards';
import BuildCompareBanner from './components/BuildCompareBanner';
import SastAiView from './components/SastAiView';
import ScaView from './components/ScaView';
import ContainerView from './components/ContainerView';
import CodeInspectorModal from './components/CodeInspectorModal';
import RemediationModal from './components/RemediationModal';
import { ShieldCheck, Package, Server } from 'lucide-react';

export default function App() {
  const [apps, setApps] = useState([]);
  const [selectedApp, setSelectedApp] = useState('vulnerable-node-app');
  const [builds, setBuilds] = useState([]);
  const [selectedBuild, setSelectedBuild] = useState('latest');
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('SAST_AI'); // SAST_AI, SCA, CONTAINER
  const [inspectedFinding, setInspectedFinding] = useState(null);
  const [remediationModalOpen, setRemediationModalOpen] = useState(false);
  const [remediationTargetMode, setRemediationTargetMode] = useState('all');

  const handleOpenRemediation = (mode = 'all') => {
    setRemediationTargetMode(mode);
    setRemediationModalOpen(true);
  };

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

  // Load builds list
  const loadBuilds = () => {
    fetch('/api/builds')
      .then((res) => res.json())
      .then((data) => {
        setBuilds(data);
      })
      .catch((err) => console.error('Error loading builds:', err));
  };

  useEffect(() => {
    loadBuilds();
  }, []);

  // Load report data when selectedApp or selectedBuild changes
  const loadReports = () => {
    setLoading(true);
    const buildParam = selectedBuild && selectedBuild !== 'latest' ? `&build=${selectedBuild}` : '';
    fetch(`/api/reports?app=${selectedApp}${buildParam}`)
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
      loadBuilds();
    }
  }, [selectedApp, selectedBuild]);

  const sastCount = reportData?.sast?.findings?.length || 0;
  const scaCount = reportData?.sca?.total || 0;
  const containerCount = reportData?.container?.total || 0;

  return (
    <div className="app-container">
      <Navbar
        apps={apps}
        selectedApp={selectedApp}
        onSelectApp={setSelectedApp}
        builds={builds}
        selectedBuild={selectedBuild}
        onSelectBuild={setSelectedBuild}
        onRefresh={() => {
          loadBuilds();
          loadReports();
        }}
        loading={loading}
      />

      <main className="main-content">
        {/* Active Build & Comparison Banner */}
        <BuildCompareBanner
          currentBuildInfo={reportData?.build}
          builds={builds}
          onOpenRemediation={handleOpenRemediation}
        />

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
              <ScaView
                scaData={reportData?.sca || {}}
                onOpenRemediation={handleOpenRemediation}
              />
            )}

            {activeTab === 'CONTAINER' && (
              <ContainerView
                containerData={reportData?.container || {}}
                onOpenRemediation={handleOpenRemediation}
              />
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

      {/* 1-Click Automated Remediation Modal */}
      <RemediationModal
        isOpen={remediationModalOpen}
        onClose={() => setRemediationModalOpen(false)}
        initialMode={remediationTargetMode}
        onRemediationComplete={() => {
          loadBuilds();
          loadReports();
        }}
      />
    </div>
  );
}
