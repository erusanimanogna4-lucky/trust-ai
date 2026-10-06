import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { MetricCards } from './components/MetricCards';
import { LiveInspector } from './components/LiveInspector';
import { TrustScoreGauge } from './components/TrustScoreGauge';
import { ThreatVisualizer } from './components/ThreatVisualizer';
import { AuditLogsTable } from './components/AuditLogsTable';
import { api, getApiBaseUrl } from './services/api';
import {
  ScanResponse,
  AuditLogEntry,
  MetricsResponse,
  PresetAttack,
} from './types';
import { Shield, Sparkles, Terminal, Activity, ShieldAlert, Cpu } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'inspector' | 'analytics' | 'audit'>('inspector');
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [backendLatency, setBackendLatency] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [currentScan, setCurrentScan] = useState<ScanResponse | null>(null);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [presets, setPresets] = useState<PresetAttack[]>([]);

  // Health and connectivity check
  const checkHealth = async () => {
    const startTime = performance.now();
    try {
      await api.checkHealth();
      const latency = Math.round(performance.now() - startTime);
      setIsBackendConnected(true);
      setBackendLatency(latency);
    } catch {
      setIsBackendConnected(false);
      setBackendLatency(null);
    }
  };

  // Load initial telemetry and presets
  const loadInitialData = async () => {
    await checkHealth();
    try {
      const [fetchedLogs, fetchedMetrics, fetchedPresets] = await Promise.all([
        api.getAuditLogs(50),
        api.getMetrics(),
        api.getPresets(),
      ]);
      setLogs(fetchedLogs);
      setMetrics(fetchedMetrics);
      setPresets(fetchedPresets);
    } catch (err) {
      console.warn('Initial data load warning:', err);
    }
  };

  useEffect(() => {
    loadInitialData();
    const interval = setInterval(checkHealth, 30000); // 30s heartbeat
    return () => clearInterval(interval);
  }, []);

  // When a scan completes in LiveInspector
  const handleScanComplete = (res: ScanResponse) => {
    setCurrentScan(res);
    // Refresh audit logs and metrics dynamically
    api.getAuditLogs(50).then(setLogs).catch(() => {});
    api.getMetrics().then(setMetrics).catch(() => {});
  };

  return (
    <div className="min-h-screen bg-cyber-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isBackendConnected={isBackendConnected}
        backendLatency={backendLatency}
        onRefreshHealth={checkHealth}
        apiBaseUrl={getApiBaseUrl()}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Metric Cards Top Overview */}
        <MetricCards metrics={metrics} />

        {/* Tab 1: Live Inspector (Split Pane Cockpit) */}
        {activeTab === 'inspector' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Live Inspector Dual Pane */}
              <div className="lg:col-span-2">
                <LiveInspector
                  onScanComplete={handleScanComplete}
                  presets={presets}
                  currentScan={currentScan}
                  loading={loading}
                  setLoading={setLoading}
                />
              </div>

              {/* Right 1 Col: Real-time Trust Score Gauge & Badges */}
              <div className="lg:col-span-1">
                <TrustScoreGauge
                  score={currentScan ? currentScan.trust_score : 100}
                  breakdown={currentScan?.breakdown}
                  threatAnalysis={currentScan?.threat_analysis}
                  decision={currentScan?.decision || 'ALLOW'}
                  piiCount={currentScan?.entities_detected.length || 0}
                />
              </div>
            </div>

            {/* Recent Audit Telemetry Preview below the cockpit */}
            <div className="mt-8">
              <AuditLogsTable logs={logs.slice(0, 5)} loading={false} onRefresh={loadInitialData} />
            </div>
          </div>
        )}

        {/* Tab 2: Threat Analytics & Radar */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <ThreatVisualizer metrics={metrics} currentScan={currentScan} />
          </div>
        )}

        {/* Tab 3: Complete Audit Trail */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            <AuditLogsTable logs={logs} loading={false} onRefresh={loadInitialData} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="w-full border-t border-cyber-800 bg-cyber-950/90 py-5 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 font-mono">
          <div className="flex items-center space-x-2 mb-2 sm:mb-0">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>SENTINEL-AI ZERO-TRUST RUNTIME PROXY • PRODUCTION READY</span>
          </div>
          <div className="flex items-center space-x-4">
            <span>Client: Vercel SPA</span>
            <span>•</span>
            <span>API: Render FastAPI</span>
            <span>•</span>
            <span>OWASP & NIST Compliant</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
