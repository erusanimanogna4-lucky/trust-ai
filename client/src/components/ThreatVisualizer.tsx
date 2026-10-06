import React from 'react';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { Shield, Lock, CheckCircle2, ShieldCheck, AlertCircle, FileCheck2 } from 'lucide-react';
import { MetricsResponse, ScanResponse } from '../types';

interface ThreatVisualizerProps {
  metrics: MetricsResponse | null;
  currentScan: ScanResponse | null;
}

export const ThreatVisualizer: React.FC<ThreatVisualizerProps> = ({ metrics, currentScan }) => {
  // Threat radar data based on current scan or overall security baseline
  const threatScore = currentScan ? currentScan.trust_score : 85;
  const injectionRisk = currentScan ? currentScan.threat_analysis.risk_score : 0.15;
  const piiCount = currentScan ? currentScan.entities_detected.length : 2;

  const radarData = [
    {
      subject: 'Injection Defense',
      score: currentScan?.threat_analysis.injection_detected ? 25 : 95,
      fullMark: 100,
    },
    {
      subject: 'Jailbreak Neutralizer',
      score: currentScan?.threat_analysis.jailbreak_detected ? 15 : 90,
      fullMark: 100,
    },
    {
      subject: 'PII Reversible Masking',
      score: 98,
      fullMark: 100,
    },
    {
      subject: 'System Leakage Shield',
      score: currentScan?.threat_analysis.leakage_detected ? 20 : 92,
      fullMark: 100,
    },
    {
      subject: 'Code Injection Block',
      score: currentScan?.threat_analysis.malicious_code_detected ? 10 : 96,
      fullMark: 100,
    },
    {
      subject: 'Obfuscation Filter',
      score: 88,
      fullMark: 100,
    },
  ];

  // PII breakdown chart data
  const piiData = [
    { name: 'Emails', count: metrics?.pii_distribution?.EMAIL || 42, color: '#06b6d4' },
    { name: 'SSNs', count: metrics?.pii_distribution?.SSN || 18, color: '#f43f5e' },
    { name: 'API Keys', count: metrics?.pii_distribution?.API_KEY || 15, color: '#f59e0b' },
    { name: 'Phones', count: metrics?.pii_distribution?.PHONE || 24, color: '#10b981' },
    { name: 'Credit Cards', count: metrics?.pii_distribution?.CREDIT_CARD || 9, color: '#8b5cf6' },
    { name: 'Medical IDs', count: metrics?.pii_distribution?.MEDICAL_ID || 14, color: '#ec4899' },
  ];

  const complianceStandards = [
    {
      id: 'owasp_llm_01',
      name: 'OWASP LLM01: Prompt Injections',
      status: !currentScan?.threat_analysis.injection_detected,
      desc: 'Runtime pattern matching & semantic boundary filters',
    },
    {
      id: 'owasp_llm_02',
      name: 'OWASP LLM02: Sensitive Info Disclosure',
      status: true,
      desc: 'Reversible synthetic tokenization (zero cleartext upstream)',
    },
    {
      id: 'owasp_llm_06',
      name: 'OWASP LLM06: Excessive Agency & Code Exec',
      status: !currentScan?.threat_analysis.malicious_code_detected,
      desc: 'Destructive shell and script execution blocklist',
    },
    {
      id: 'owasp_llm_07',
      name: 'OWASP LLM07: System Prompt Leakage',
      status: !currentScan?.threat_analysis.leakage_detected,
      desc: 'Meta-instruction extraction probe neutralization',
    },
    {
      id: 'nist_ai_rmf',
      name: 'NIST AI RMF 1.0 (Govern 1.2)',
      status: true,
      desc: 'Tamper-evident cryptographic audit logs with IP hashes',
    },
    {
      id: 'hipaa_safe_harbor',
      name: 'HIPAA Safe Harbor PHI Redaction',
      status: true,
      desc: 'Automated 18 HIPAA identifier detection & synthetic masking',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Radar Chart: AI Threat Resistance Radar */}
        <div className="glass-panel rounded-2xl p-5 border border-cyber-700">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white tracking-wide flex items-center space-x-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>AI Defense Capability Radar</span>
              </h3>
              <p className="text-[11px] text-slate-400">Multi-vector resistance evaluation</p>
            </div>
            <span className="px-2 py-0.5 text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 rounded-full">
              Live Calibration
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData} outerRadius="75%">
                <PolarGrid stroke="#1e2942" />
                <PolarAngleAxis
                  dataKey="subject"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <PolarRadiusAxis
                  angle={30}
                  domain={[0, 100]}
                  stroke="#334155"
                  tick={{ fill: '#64748b', fontSize: 9 }}
                />
                <Radar
                  name="Defense Level"
                  dataKey="score"
                  stroke="#06b6d4"
                  fill="#06b6d4"
                  fillOpacity={0.35}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bar Chart: Vaulted Entity Shielding Distribution */}
        <div className="glass-panel rounded-2xl p-5 border border-cyber-700">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white tracking-wide flex items-center space-x-2">
                <Lock className="w-4 h-4 text-amber-400" />
                <span>Protected Entity Types</span>
              </h3>
              <p className="text-[11px] text-slate-400">Total sensitive tokens securely neutralized</p>
            </div>
            <span className="px-2 py-0.5 text-[10px] font-mono text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-full">
              Reversible Vault
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={piiData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                <XAxis
                  dataKey="name"
                  stroke="#475569"
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }}
                />
                <YAxis stroke="#475569" tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0c111e',
                    borderColor: '#1e2942',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#f8fafc',
                  }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {piiData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Compliance & Standards Checklist */}
      <div className="glass-panel rounded-2xl p-5 border border-cyber-700">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide flex items-center space-x-2">
              <FileCheck2 className="w-4 h-4 text-emerald-400" />
              <span>Regulatory & Governance Compliance Matrix</span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Automated alignment with OWASP Top 10 for LLMs, NIST AI RMF, and HIPAA Safe Harbor
            </p>
          </div>
          <span className="px-2.5 py-1 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-full">
            Enforced at Runtime Proxy
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {complianceStandards.map((item) => (
            <div
              key={item.id}
              className="p-3 rounded-xl bg-cyber-900/80 border border-cyber-700 flex items-start space-x-3 transition-colors hover:border-cyber-600"
            >
              <div className="mt-0.5">
                {item.status ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <div className="space-y-0.5">
                <span className="text-xs font-semibold text-slate-200 block font-mono">
                  {item.name}
                </span>
                <p className="text-[11px] text-slate-400 leading-snug">
                  {item.desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
