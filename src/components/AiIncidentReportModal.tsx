import React, { useState } from 'react';
import { AiForensicReport } from '../types/pcap';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Copy,
  Check,
  X,
  Flame,
  Clock,
  Terminal,
  Download,
  Share2,
  Sparkles,
  RefreshCw,
} from 'lucide-react';

interface AiIncidentReportModalProps {
  report: AiForensicReport | null;
  isLoading: boolean;
  onClose: () => void;
  onRegenerate: () => void;
}

export const AiIncidentReportModal: React.FC<AiIncidentReportModalProps> = ({
  report,
  isLoading,
  onClose,
  onRegenerate,
}) => {
  const [copiedRuleIndex, setCopiedRuleIndex] = useState<number | null>(null);

  const copyRule = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedRuleIndex(idx);
    setTimeout(() => setCopiedRuleIndex(null), 1500);
  };

  const getSeverityBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  const downloadMarkdownReport = () => {
    if (!report) return;
    const md = `# Siber Tehdit Analiz Raporu (AI Destekli PCAP Adli Bilişim)
Tarih: ${report.analyzedAt}
Tehdit Seviyesi: ${report.threatLevel} (Skor: ${report.threatScore}/100)

## Yönetici Özeti
${report.executiveSummary}

## Temel Bulgular
${report.keyFindings.map((f) => `- ${f}`).join('\n')}

## MITRE ATT&CK Eşleşmeleri
${report.mitreTactics
  .map(
    (t) =>
      `### [${t.techniqueId}] ${t.techniqueName} (${t.tactic})\nKanıt: ${t.evidence}`
  )
  .join('\n\n')}

## Teknik Analiz
- **Saldırgan IP'ler**: ${report.technicalAnalysis.attackerIps?.join(', ') || 'Belirtilmedi'}
- **Hedef / Ele Geçirilen Makineler**: ${report.technicalAnalysis.compromisedHosts?.join(', ') || 'Belirtilmedi'}
${report.technicalAnalysis.portScanningDetails ? `\n- **Port Taraması Detayları**: ${report.technicalAnalysis.portScanningDetails}` : ''}
${report.technicalAnalysis.webExploitsDetails ? `\n- **Web Açıklıkları / Payload**: ${report.technicalAnalysis.webExploitsDetails}` : ''}
${report.technicalAnalysis.dataExfiltrationDetails ? `\n- **Veri Sızıntısı**: ${report.technicalAnalysis.dataExfiltrationDetails}` : ''}

## Güvenlik Duvarı ve Müdahale Kuralları
${report.recommendedActions
  .map(
    (a) =>
      `### [${a.priority}] ${a.action}\n\`\`\`bash\n${a.ruleSnippet || '# Kural gerekmiyor'}\n\`\`\``
  )
  .join('\n\n')}
`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PCAP_AI_Tehdit_Raporu_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 text-cyan-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>Google Gemini AI Siber Saldırı & Tehdit Raporu</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  gemini-3.8-flash
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Ayrıştırılan PCAP paketleri ve anomali imzaları temelinde üretilen adli olay analizi.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {report && (
              <button
                onClick={downloadMarkdownReport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 font-medium transition-colors"
                title="Markdown Raporu İndir"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Raporu İndir</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-20 space-y-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
                <Sparkles className="w-6 h-6 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-slate-200">
                  Google Gemini PCAP Trafiğini Adli Olarak İnceliyor...
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Port tarama örüntüleri, MITRE ATT&CK teknikleri ve şüpheli paket yükleri değerlendiriliyor.
                </p>
              </div>
            </div>
          ) : !report ? (
            <div className="text-center py-16 text-slate-400">
              Rapor oluşturulamadı veya henüz üretilmedi.
            </div>
          ) : (
            <>
              {/* Score & Executive Overview */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="md:col-span-1 bg-slate-950/70 border border-slate-800 rounded-xl p-4 flex flex-col items-center justify-center text-center">
                  <span className="text-xs uppercase tracking-wider text-slate-400 font-medium">Tehdit Skoru</span>
                  <div className="relative my-3">
                    <div className="text-4xl font-extrabold font-mono text-cyan-300">
                      {report.threatScore}
                      <span className="text-lg font-normal text-slate-500">/100</span>
                    </div>
                  </div>
                  <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getSeverityBadge(report.threatLevel)}`}>
                    {report.threatLevel} TEHDİT
                  </span>
                </div>

                <div className="md:col-span-3 bg-slate-950/70 border border-slate-800 rounded-xl p-4.5 flex flex-col justify-center">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-1.5 flex items-center gap-1.5">
                    <Flame className="w-4 h-4 text-cyan-400" />
                    Yönetici Özeti (Executive Summary)
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">
                    {report.executiveSummary}
                  </p>
                </div>
              </div>

              {/* Key Findings */}
              <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-2.5 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-cyan-400" />
                  Kritik Adli Bulgular (Key Findings)
                </h3>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  {report.keyFindings.map((finding, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80 text-slate-200"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* MITRE ATT&CK Matrix Mapping */}
              <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2.5 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  MITRE ATT&CK Taktik ve Teknik Eşleşmeleri
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {report.mitreTactics.map((mitre, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-900/80 p-3 rounded-lg border border-slate-800 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-amber-300 bg-amber-950/50 px-2 py-0.5 rounded border border-amber-900/50 text-[11px]">
                          {mitre.techniqueId}
                        </span>
                        <span className="text-[10px] text-slate-400 uppercase tracking-wide">
                          {mitre.tactic}
                        </span>
                      </div>
                      <div className="font-semibold text-slate-100">{mitre.techniqueName}</div>
                      <p className="text-[11px] text-slate-400 font-mono bg-slate-950 p-2 rounded border border-slate-800/60 break-words">
                        {mitre.evidence}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attack Timeline */}
              {report.attackTimeline && report.attackTimeline.length > 0 && (
                <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4.5">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-3 flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    Saldırı Kronolojisi ve Olay Akışı
                  </h3>
                  <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                    {report.attackTimeline.map((item, idx) => (
                      <div key={idx} className="relative flex items-start gap-3">
                        <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-900" />
                        <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 w-full text-xs">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-[10px] text-cyan-300 font-semibold">{item.time}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${getSeverityBadge(item.severity)}`}>
                              {item.severity}
                            </span>
                          </div>
                          <p className="text-slate-200">{item.event}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Actionable Firewall Rules & Remediation */}
              <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-3 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  Müdahale Eylemleri ve Güvenlik Duvarı Kuralları (Firewall & IDS Rules)
                </h3>
                <div className="space-y-3">
                  {report.recommendedActions.map((rec, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              rec.priority === 'IMMEDIATE'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            }`}
                          >
                            {rec.priority}
                          </span>
                          <span className="font-semibold text-slate-100">{rec.action}</span>
                        </div>
                        {rec.ruleType && (
                          <span className="text-[10px] font-mono text-cyan-400 uppercase">
                            [{rec.ruleType}]
                          </span>
                        )}
                      </div>

                      {rec.ruleSnippet && (
                        <div className="relative group">
                          <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre">
                            {rec.ruleSnippet}
                          </pre>
                          <button
                            onClick={() => copyRule(rec.ruleSnippet!, idx)}
                            className="absolute top-2 right-2 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors border border-slate-700"
                            title="Kuralı Kopyala"
                          >
                            {copiedRuleIndex === idx ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-slate-800 bg-slate-950/60 text-xs text-slate-400">
          <div>
            {report?.analyzedAt && (
              <span>Analiz Zamanı: {new Date(report.analyzedAt).toLocaleString('tr-TR')}</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onRegenerate}
              disabled={isLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Yeniden Analiz Et</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
            >
              Kapat
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
