import React from 'react';
import { Shield, Activity, Terminal, ShieldAlert, Cpu, ExternalLink, RefreshCw } from 'lucide-react';

interface NavbarProps {
  activeTab: 'inspector' | 'analytics' | 'audit';
  setActiveTab: (tab: 'inspector' | 'analytics' | 'audit') => void;
  isBackendConnected: boolean;
  backendLatency: number | null;
  onRefreshHealth: () => void;
  apiBaseUrl: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isBackendConnected,
  backendLatency,
  onRefreshHealth,
  apiBaseUrl,
}) => {
  return (
    <header className="sticky top-0 z-50 w-full glass-panel border-b border-cyber-700 bg-cyber-950/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Logo & Tag */}
        <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-indigo-500/20 to-emerald-500/20 border border-cyan-500/40 glow-cyan">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold tracking-tight text-white font-mono">
                SENTINEL<span className="text-cyan-400">.AI</span>
              </span>
              <span className="px-2 py-0.5 text-[10px] font-semibold tracking-wider uppercase rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                v1.0 Gateway
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Zero-Trust AI Privacy, Threat Detection & Governance Proxy
            </p>
          </div>
        </div>

        {/* View Navigation Tabs */}
        <nav className="flex items-center space-x-1 sm:space-x-2 bg-cyber-900/90 p-1 rounded-xl border border-cyber-700">
          <button
            onClick={() => setActiveTab('inspector')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'inspector'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Live Inspector</span>
          </button>

          <button
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'analytics'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Threat Analytics</span>
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'audit'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Audit Trail</span>
          </button>
        </nav>

        {/* Status Indicators & Server Status */}
        <div className="flex items-center space-x-3">
          {/* Connection Status Pill */}
          <div
            className={`flex items-center space-x-2 px-2.5 py-1 rounded-full text-[11px] font-mono border ${
              isBackendConnected
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
            }`}
            title={`Backend: ${apiBaseUrl}`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isBackendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="hidden md:inline">
              {isBackendConnected ? 'GATEWAY LIVE' : 'CONNECTING / COLD WAKE'}
            </span>
            {backendLatency !== null && (
              <span className="text-[10px] opacity-75">({backendLatency}ms)</span>
            )}
          </div>

          <button
            onClick={onRefreshHealth}
            title="Check Gateway Health"
            className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-cyber-800 rounded-lg transition-colors border border-transparent hover:border-cyber-700"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>

          {/* GitHub Repo Link */}
          <a
            href="https://github.com/erusanimanogna4-lucky/trust-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-cyber-800 hover:bg-cyber-700 rounded-lg border border-cyber-600 transition-colors"
            title="View on GitHub"
          >
            <svg className="w-3.5 h-3.5 fill-current text-slate-300" viewBox="0 0 24 24">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            <span className="hidden sm:inline">GitHub</span>
          </a>

          {/* API Docs Link */}
          <a
            href={`${apiBaseUrl}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="hidden lg:flex items-center space-x-1.5 px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-cyber-800 hover:bg-cyber-700 rounded-lg border border-cyber-600 transition-colors"
          >
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>OpenAPI</span>
            <ExternalLink className="w-3 h-3 opacity-60" />
          </a>
        </div>
      </div>
    </header>
  );
};
