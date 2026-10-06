import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  Download,
  Copy,
  Check,
  Hash,
  Clock,
  Terminal,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';
import { AuditLogEntry } from '../types';

interface AuditLogsTableProps {
  logs: AuditLogEntry[];
  loading: boolean;
  onRefresh: () => void;
}

export const AuditLogsTable: React.FC<AuditLogsTableProps> = ({ logs, loading, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.prompt_preview.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.audit_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.client_ip_hash.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.triggers_summary.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesDecision =
      decisionFilter === 'ALL' || log.decision === decisionFilter;

    return matchesSearch && matchesDecision;
  });

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const exportToJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinel_audit_logs_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'QUARANTINE_BLOCKED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3 mr-1" />
            QUARANTINE BLOCKED
          </span>
        );
      case 'SANITIZE_AND_FORWARD':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 mr-1" />
            SANITIZED TRANSIT
          </span>
        );
      case 'ALLOW':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3 mr-1" />
            DIRECT ALLOW
          </span>
        );
    }
  };

  const getTrustScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-rose-400';
  };

  return (
    <div className="glass-panel rounded-2xl border border-cyber-700 overflow-hidden">
      {/* Table Header and Toolbar */}
      <div className="p-4 sm:p-5 border-b border-cyber-700/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-wide flex items-center space-x-2">
            <Hash className="w-4 h-4 text-cyan-400" />
            <span>Tamper-Evident Audit Telemetry Log</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically keyed proxy events, client IP hashes, and runtime policy decisions
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Search Bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search ID, hash, or prompt..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-cyber-900 text-xs text-slate-200 pl-8 pr-3 py-1.5 rounded-xl border border-cyber-600 focus:outline-none focus:border-cyan-500 w-52"
            />
          </div>

          {/* Decision Filter Dropdown */}
          <div className="relative">
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="bg-cyber-900 text-xs text-slate-200 px-3 py-1.5 rounded-xl border border-cyber-600 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Actions</option>
              <option value="ALLOW">Allowed</option>
              <option value="SANITIZE_AND_FORWARD">Sanitized</option>
              <option value="QUARANTINE_BLOCKED">Quarantined</option>
            </select>
          </div>

          {/* Export Button */}
          <button
            onClick={exportToJson}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyber-800 hover:bg-cyber-700 text-cyan-300 rounded-xl border border-cyber-600 text-xs transition-colors"
            title="Export filtered logs as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Table Data */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-cyber-950/80 border-b border-cyber-700/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            <tr>
              <th className="py-3 px-4">Event ID / Time</th>
              <th className="py-3 px-4">Client IP Hash</th>
              <th className="py-3 px-4">Intercepted Payload</th>
              <th className="py-3 px-4">Decision Verdict</th>
              <th className="py-3 px-4">Trust Index</th>
              <th className="py-3 px-4">PII Shield</th>
              <th className="py-3 px-4">Latency</th>
              <th className="py-3 px-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-800/80 font-mono">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500 font-mono text-xs">
                  No telemetry entries match your current search criteria.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr
                  key={log.audit_id}
                  onClick={() => setSelectedLog(log)}
                  className="hover:bg-cyber-900/60 transition-colors cursor-pointer group"
                >
                  {/* Event ID and timestamp */}
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-1.5">
                      <span className="font-semibold text-slate-200 text-xs">
                        {log.audit_id}
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          copyToClipboard(log.audit_id, log.audit_id);
                        }}
                        className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-400 hover:text-cyan-300 transition-opacity"
                        title="Copy ID"
                      >
                        {copiedId === log.audit_id ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                    <span className="text-[10px] text-slate-500 flex items-center space-x-1 mt-0.5">
                      <Clock className="w-2.5 h-2.5" />
                      <span>{log.timestamp}</span>
                    </span>
                  </td>

                  {/* Client IP Hash */}
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-cyber-950 text-slate-400 text-[10px] border border-cyber-800">
                      {log.client_ip_hash}
                    </span>
                  </td>

                  {/* Intercepted Prompt Preview */}
                  <td className="py-3 px-4 max-w-xs truncate text-slate-300 font-sans text-xs">
                    {log.prompt_preview}
                  </td>

                  {/* Verdict Badge */}
                  <td className="py-3 px-4 whitespace-nowrap">
                    {getDecisionBadge(log.decision)}
                  </td>

                  {/* Trust Score */}
                  <td className="py-3 px-4 font-bold text-xs">
                    <span className={getTrustScoreColor(log.trust_score)}>
                      {log.trust_score}/100
                    </span>
                  </td>

                  {/* PII Masked Count */}
                  <td className="py-3 px-4">
                    {log.pii_count > 0 ? (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px]">
                        {log.pii_count} masked
                      </span>
                    ) : (
                      <span className="text-slate-600 text-[10px]">None</span>
                    )}
                  </td>

                  {/* Latency */}
                  <td className="py-3 px-4 text-slate-400 text-xs">
                    {log.latency_ms}ms
                  </td>

                  {/* Action inspect */}
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedLog(log);
                      }}
                      className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                      title="Inspect Event Forensics"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Forensic Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="glass-panel-elevated rounded-2xl border border-cyber-600 w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-700">
              <div className="flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  SECURITY AUDIT FORENSICS: {selectedLog.audit_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="px-2 py-1 text-xs text-slate-400 hover:text-white bg-cyber-800 hover:bg-cyber-700 rounded-lg"
              >
                Close (ESC)
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-cyber-900 border border-cyber-700">
                <span className="text-slate-400 text-[10px] block">DECISION</span>
                <span className="font-bold text-white">{selectedLog.decision}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-cyber-900 border border-cyber-700">
                <span className="text-slate-400 text-[10px] block">TRUST SCORE</span>
                <span className={`font-bold ${getTrustScoreColor(selectedLog.trust_score)}`}>
                  {selectedLog.trust_score}/100
                </span>
              </div>
              <div className="p-2.5 rounded-xl bg-cyber-900 border border-cyber-700">
                <span className="text-slate-400 text-[10px] block">CLIENT IP HASH</span>
                <span className="text-cyan-300">{selectedLog.client_ip_hash}</span>
              </div>
              <div className="p-2.5 rounded-xl bg-cyber-900 border border-cyber-700">
                <span className="text-slate-400 text-[10px] block">PROXY LATENCY</span>
                <span className="text-emerald-400">{selectedLog.latency_ms} ms</span>
              </div>
            </div>

            {/* Prompt preview */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Intercepted Input Payload
              </span>
              <div className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed">
                {selectedLog.prompt_preview}
              </div>
            </div>

            {/* Triggers matched */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Matched Threat Vectors / Signatures
              </span>
              {selectedLog.triggers_summary.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {selectedLog.triggers_summary.map((t, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-lg text-xs font-mono bg-rose-500/20 text-rose-300 border border-rose-500/40"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-emerald-400 font-mono flex items-center space-x-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>No adversarial triggers tripped.</span>
                </span>
              )}
            </div>

            {/* Raw JSON representation */}
            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Tamper-Evident Telemetry Payload
              </span>
              <pre className="p-3 rounded-xl bg-cyber-950 border border-cyber-800 font-mono text-[11px] text-slate-400 overflow-x-auto">
                {JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
