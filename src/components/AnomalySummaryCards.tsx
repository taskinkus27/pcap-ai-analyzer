import React from 'react';
import { PcapSummary } from '../types/pcap';
import { ShieldAlert, Server, Globe, FileCode, Clock, Activity, Zap } from 'lucide-react';

interface AnomalySummaryCardsProps {
  summary: PcapSummary | null;
  onFilterAnomalyType: (type: string) => void;
  onOpenReportModal: () => void;
}

export const AnomalySummaryCards: React.FC<AnomalySummaryCardsProps> = ({
  summary,
  onFilterAnomalyType,
  onOpenReportModal,
}) => {
  if (!summary) return null;

  const criticalCount = summary.severityBreakdown?.CRITICAL || 0;
  const highCount = summary.severityBreakdown?.HIGH || 0;
  const portScansCount = summary.portScansDetected?.length || 0;

  return (
    <div className="bg-slate-900/60 border-b border-slate-800 px-4 py-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
        {/* 1. Total Packets */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-medium">Toplam Paket</div>
            <div className="text-lg font-bold font-mono text-slate-100">{summary.packetCount}</div>
            <div className="text-[10px] text-slate-500 font-mono">{summary.captureDuration}s yakalama</div>
          </div>
          <div className="p-2 rounded bg-slate-800/60 text-slate-400">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        {/* 2. Critical & High Threats */}
        <button
          onClick={() => onFilterAnomalyType('anomaly==true')}
          className="bg-slate-950/80 border border-rose-900/50 hover:border-rose-700/60 transition-colors rounded-lg p-2.5 flex items-center justify-between text-left group"
        >
          <div>
            <div className="text-[10px] text-rose-400 uppercase tracking-wider font-semibold">Kritik Tehditler</div>
            <div className="text-lg font-bold font-mono text-rose-300">
              {criticalCount + highCount}
              <span className="text-xs text-slate-500 font-normal ml-1">/ {summary.totalAnomalies}</span>
            </div>
            <div className="text-[10px] text-rose-400/80">Kritik: {criticalCount}, Yüksek: {highCount}</div>
          </div>
          <div className="p-2 rounded bg-rose-500/10 text-rose-400 group-hover:scale-105 transition-transform">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </button>

        {/* 3. Port Scans Detected */}
        <button
          onClick={() => onFilterAnomalyType('type==PORT_SCAN')}
          className="bg-slate-950/80 border border-amber-900/50 hover:border-amber-700/60 transition-colors rounded-lg p-2.5 flex items-center justify-between text-left group"
        >
          <div>
            <div className="text-[10px] text-amber-400 uppercase tracking-wider font-semibold">Port Taramaları</div>
            <div className="text-lg font-bold font-mono text-amber-300">{portScansCount} Grup</div>
            <div className="text-[10px] text-slate-400 truncate max-w-[110px]">
              {summary.portScansDetected?.[0] ? `${summary.portScansDetected[0].portsScanned.length} port hedefli` : 'Temiz'}
            </div>
          </div>
          <div className="p-2 rounded bg-amber-500/10 text-amber-400 group-hover:scale-105 transition-transform">
            <Server className="w-4 h-4" />
          </div>
        </button>

        {/* 4. Suspicious Payloads (SQLi/LFI) */}
        <button
          onClick={() => onFilterAnomalyType('type==SQL_INJECTION || type==PATH_TRAVERSAL')}
          className="bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-colors rounded-lg p-2.5 flex items-center justify-between text-left group"
        >
          <div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-medium">Zararlı Payload</div>
            <div className="text-lg font-bold font-mono text-slate-100">{summary.suspiciousPayloadsCount}</div>
            <div className="text-[10px] text-slate-500 truncate max-w-[110px]">SQLi / Traversal</div>
          </div>
          <div className="p-2 rounded bg-red-500/10 text-red-400 group-hover:scale-105 transition-transform">
            <FileCode className="w-4 h-4" />
          </div>
        </button>

        {/* 5. DNS Exfiltration */}
        <button
          onClick={() => onFilterAnomalyType('type==DNS_EXFILTRATION')}
          className="bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-colors rounded-lg p-2.5 flex items-center justify-between text-left group"
        >
          <div>
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-medium">DNS Sızıntısı</div>
            <div className="text-lg font-bold font-mono text-slate-100">{summary.dnsExfiltrationCount}</div>
            <div className="text-[10px] text-slate-500 truncate max-w-[110px]">Tünel / C2 Şüphesi</div>
          </div>
          <div className="p-2 rounded bg-purple-500/10 text-purple-400 group-hover:scale-105 transition-transform">
            <Globe className="w-4 h-4" />
          </div>
        </button>

        {/* 6. AI Incident Report CTA */}
        <button
          onClick={onOpenReportModal}
          className="bg-gradient-to-br from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg p-2.5 flex items-center justify-between transition-all shadow-md shadow-cyan-600/20 group"
        >
          <div>
            <div className="text-[10px] uppercase tracking-wider text-cyan-100 font-bold">Gemini AI Raporu</div>
            <div className="text-xs font-bold mt-0.5">Tehdit Raporu</div>
            <div className="text-[10px] text-cyan-200">Adli Analiz & Kurallar</div>
          </div>
          <div className="p-2 rounded bg-white/10 group-hover:scale-110 transition-transform">
            <Zap className="w-4 h-4 text-cyan-100" />
          </div>
        </button>
      </div>
    </div>
  );
};
