import React from 'react';
import { ShieldCheck, ShieldAlert, Shield, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import { TrustScoreBreakdown, ThreatAnalysis } from '../types';

interface TrustScoreGaugeProps {
  score: number;
  breakdown?: TrustScoreBreakdown;
  threatAnalysis?: ThreatAnalysis;
  decision?: string;
  piiCount?: number;
}

export const TrustScoreGauge: React.FC<TrustScoreGaugeProps> = ({
  score = 100,
  breakdown,
  threatAnalysis,
  decision = 'ALLOW',
  piiCount = 0,
}) => {
  // SVG gauge calculations
  const radius = 78;
  const circumference = 2 * Math.PI * radius;
  // Use a 270 degree arc (3/4 circle)
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (score / 100) * arcLength;

  // Dynamic color palette based on trust score
  const getTheme = (val: number) => {
    if (val >= 85) {
      return {
        stroke: '#10b981', // emerald
        gradientFrom: '#10b981',
        gradientTo: '#06b6d4',
        text: 'text-emerald-400',
        bgPill: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        label: 'MAXIMUM TRUST',
        desc: 'Zero adversarial signals detected. Safe for direct LLM ingestion.',
      };
    } else if (val >= 60) {
      return {
        stroke: '#f59e0b', // amber
        gradientFrom: '#f59e0b',
        gradientTo: '#eab308',
        text: 'text-amber-400',
        bgPill: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        label: 'SANITIZED TRANSIT',
        desc: 'Sensitive PII detected & synthetically masked. Safe to forward.',
      };
    } else {
      return {
        stroke: '#f43f5e', // rose
        gradientFrom: '#f43f5e',
        gradientTo: '#ef4444',
        text: 'text-rose-400',
        bgPill: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
        label: 'QUARANTINE BLOCKED',
        desc: 'Adversarial jailbreak or critical injection trigger tripped.',
      };
    }
  };

  const theme = getTheme(score);

  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyber-700">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>Trust & Safety Index</span>
          </h3>
          <p className="text-[11px] text-slate-400">Explainable consolidated AI security score</p>
        </div>
        <span className={`px-2.5 py-1 text-[11px] font-mono font-semibold rounded-full border ${theme.bgPill}`}>
          {theme.label}
        </span>
      </div>

      {/* Radial SVG Gauge */}
      <div className="relative flex flex-col items-center justify-center my-2">
        <svg className="w-48 h-48 transform -rotate-225" viewBox="0 0 200 200">
          <defs>
            <linearGradient id="trustGaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={theme.gradientTo} />
              <stop offset="100%" stopColor={theme.gradientFrom} />
            </linearGradient>
            <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="#131b2e"
            strokeWidth="14"
            strokeDasharray={arcLength}
            strokeDashoffset="0"
            strokeLinecap="round"
          />

          {/* Animated active score progress */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="url(#trustGaugeGradient)"
            strokeWidth="14"
            strokeDasharray={arcLength}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            filter="url(#gaugeGlow)"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none mt-2">
          <span className={`text-4xl font-extrabold font-mono tracking-tight ${theme.text}`}>
            {score}
          </span>
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest mt-0.5">
            OUT OF 100
          </span>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            {decision.replace(/_/g, ' ')}
          </span>
        </div>
      </div>

      <p className="text-xs text-center text-slate-300 px-4 mb-4">
        {theme.desc}
      </p>

      {/* Granular Penalty Deductions Breakdown */}
      <div className="space-y-2.5 pt-3 border-t border-cyber-700/60">
        <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
          Telemetry Penalty Breakdown
        </span>

        {/* Injection Penalty */}
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-300 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
            <span>Prompt Injection Risk</span>
          </span>
          <span className="font-mono text-rose-400">
            {breakdown ? `-${breakdown.injection_penalty}` : '-0'} pts (max -40)
          </span>
        </div>
        <div className="w-full bg-cyber-800 rounded-full h-1.5 overflow-hidden">
          <div
            className="bg-rose-500 h-full rounded-full transition-all duration-500"
            style={{ width: `${((breakdown?.injection_penalty || 0) / 40) * 100}%` }}
          />
        </div>

        {/* PII Penalty */}
        <div className="flex items-center justify-between text-xs pt-1">
          <span className="text-slate-300 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            <span>PII / PHI Data Exposure</span>
          </span>
          <span className="font-mono text-amber-400">
            {breakdown ? `-${breakdown.pii_penalty}` : '-0'} pts (max -30)
          </span>
        </div>
        <div className="w-full bg-cyber-800 rounded-full h-1.5 overflow-hidden">
          <div
            className="bg-amber-500 h-full rounded-full transition-all duration-500"
            style={{ width: `${((breakdown?.pii_penalty || 0) / 30) * 100}%` }}
          />
        </div>

        {/* Heuristic Penalty */}
        <div className="flex items-center justify-between text-xs pt-1">
          <span className="text-slate-300 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
            <span>Malicious Heuristic Anomaly</span>
          </span>
          <span className="font-mono text-indigo-400">
            {breakdown ? `-${breakdown.heuristic_penalty}` : '-0'} pts (max -30)
          </span>
        </div>
        <div className="w-full bg-cyber-800 rounded-full h-1.5 overflow-hidden">
          <div
            className="bg-indigo-500 h-full rounded-full transition-all duration-500"
            style={{ width: `${((breakdown?.heuristic_penalty || 0) / 30) * 100}%` }}
          />
        </div>
      </div>

      {/* Threat Radar Badges */}
      <div className="mt-5 grid grid-cols-3 gap-2 text-center pt-3 border-t border-cyber-700/60">
        <div className="p-2 rounded-xl bg-cyber-900/80 border border-cyber-700">
          <span className="text-[10px] font-mono text-slate-400 block mb-1">Injection Shield</span>
          <span
            className={`text-xs font-semibold flex items-center justify-center space-x-1 ${
              threatAnalysis?.injection_detected ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {threatAnalysis?.injection_detected ? (
              <>
                <XCircle className="w-3.5 h-3.5" />
                <span>Triggered</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Protected</span>
              </>
            )}
          </span>
        </div>

        <div className="p-2 rounded-xl bg-cyber-900/80 border border-cyber-700">
          <span className="text-[10px] font-mono text-slate-400 block mb-1">PII Vault</span>
          <span className="text-xs font-semibold text-cyan-400 flex items-center justify-center space-x-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{piiCount} Masked</span>
          </span>
        </div>

        <div className="p-2 rounded-xl bg-cyber-900/80 border border-cyber-700">
          <span className="text-[10px] font-mono text-slate-400 block mb-1">Zero-Trust Rule</span>
          <span
            className={`text-xs font-semibold flex items-center justify-center space-x-1 ${
              decision === 'QUARANTINE_BLOCKED' ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {decision === 'QUARANTINE_BLOCKED' ? (
              <>
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Quarantine</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Approved</span>
              </>
            )}
          </span>
        </div>
      </div>
    </div>
  );
};
