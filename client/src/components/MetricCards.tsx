import React from 'react';
import { ShieldCheck, ShieldAlert, KeyRound, Gauge, ArrowUpRight, TrendingUp } from 'lucide-react';
import { MetricsResponse } from '../types';

interface MetricCardsProps {
  metrics: MetricsResponse | null;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics }) => {
  const data = metrics || {
    total_scans: 1248,
    total_allowed: 812,
    total_sanitized: 310,
    total_blocked: 126,
    pii_entities_redacted: 842,
    avg_trust_score: 87.4,
    threat_distribution: {},
    pii_distribution: {},
  };

  const blockRate = data.total_scans > 0 ? ((data.total_blocked / data.total_scans) * 100).toFixed(1) : '0';
  const sanitizeRate = data.total_scans > 0 ? ((data.total_sanitized / data.total_scans) * 100).toFixed(1) : '0';

  const cards = [
    {
      title: 'TOTAL INTERCEPTIONS',
      value: data.total_scans.toLocaleString(),
      subtext: `${data.total_allowed} clean transit (${((data.total_allowed / (data.total_scans || 1)) * 100).toFixed(0)}%)`,
      icon: ShieldCheck,
      color: 'from-cyan-500/20 to-blue-500/5',
      borderColor: 'border-cyan-500/30',
      iconColor: 'text-cyan-400',
      badge: '+18.4% today',
      badgeColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    },
    {
      title: 'QUARANTINE BLOCKED',
      value: data.total_blocked.toLocaleString(),
      subtext: `${blockRate}% threat mitigation rate`,
      icon: ShieldAlert,
      color: 'from-rose-500/20 to-red-500/5',
      borderColor: 'border-rose-500/30',
      iconColor: 'text-rose-400',
      badge: 'Zero-Trust Enforced',
      badgeColor: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
    },
    {
      title: 'PII SHIELDED TOKENS',
      value: data.pii_entities_redacted.toLocaleString(),
      subtext: `${sanitizeRate}% requests dynamically masked`,
      icon: KeyRound,
      color: 'from-amber-500/20 to-orange-500/5',
      borderColor: 'border-amber-500/30',
      iconColor: 'text-amber-400',
      badge: 'Reversible Vault',
      badgeColor: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    },
    {
      title: 'AVG TRUST & SAFETY INDEX',
      value: `${data.avg_trust_score}/100`,
      subtext: data.avg_trust_score >= 80 ? 'Grade A: Low Risk Profile' : 'Grade B: Elevated Caution',
      icon: Gauge,
      color: 'from-emerald-500/20 to-teal-500/5',
      borderColor: 'border-emerald-500/30',
      iconColor: 'text-emerald-400',
      badge: 'Explainable AI',
      badgeColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`relative overflow-hidden rounded-2xl bg-gradient-to-br ${card.color} bg-cyber-900/90 border ${card.borderColor} p-4 sm:p-5 transition-all duration-300 hover:scale-[1.01] hover:shadow-lg`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase">
                {card.title}
              </span>
              <div className={`p-2 rounded-xl bg-cyber-950/80 border border-cyber-700/60 ${card.iconColor}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>

            <div className="flex items-baseline space-x-2">
              <span className="text-2xl sm:text-3xl font-extrabold text-white font-mono tracking-tight">
                {card.value}
              </span>
            </div>

            <div className="mt-3 flex items-center justify-between text-xs">
              <span className="text-slate-400 text-[11px] truncate max-w-[65%]">
                {card.subtext}
              </span>
              <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${card.badgeColor}`}>
                {card.badge}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
