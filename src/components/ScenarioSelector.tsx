import React, { useRef } from 'react';
import { SAMPLE_SCENARIOS, SampleScenario } from '../data/samplePcaps';
import { Upload, Download, ShieldCheck, ShieldAlert, FileText, CheckCircle2 } from 'lucide-react';

interface ScenarioSelectorProps {
  currentScenarioId: string;
  onSelectScenario: (scenario: SampleScenario) => void;
  onFileUpload: (file: File) => void;
  onDownloadCurrentPcap: () => void;
}

export const ScenarioSelector: React.FC<ScenarioSelectorProps> = ({
  currentScenarioId,
  onSelectScenario,
  onFileUpload,
  onDownloadCurrentPcap,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onFileUpload(file);
    }
  };

  return (
    <div className="bg-slate-900 border-b border-slate-800 px-4 py-3">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        {/* Scenario Carousel */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 lg:pb-0 scrollbar-none flex-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 shrink-0 mr-1 flex items-center gap-1">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            Senaryo:
          </span>
          {SAMPLE_SCENARIOS.map((sc) => {
            const isSelected = currentScenarioId === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => onSelectScenario(sc)}
                className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  isSelected
                    ? 'bg-cyan-500/15 border-cyan-500/50 text-cyan-200 shadow-sm shadow-cyan-500/20'
                    : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:bg-slate-800/60 hover:border-slate-700'
                }`}
              >
                {sc.severity === 'CRITICAL' && <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />}
                {sc.severity === 'HIGH' && <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
                {sc.severity === 'LOW' && <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                <span className="font-sans font-medium">{sc.name}</span>
                {isSelected && <CheckCircle2 className="w-3 h-3 text-cyan-400 ml-0.5" />}
              </button>
            );
          })}
        </div>

        {/* Actions (Upload .pcap & Download current) */}
        <div className="flex items-center gap-2 shrink-0">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng,.cap"
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
            title=".pcap veya .pcapng dosyası yükle"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>PCAP Dosyası Yükle</span>
          </button>

          <button
            onClick={onDownloadCurrentPcap}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
            title="Aktif paketleri Wireshark formatında .pcap olarak indir"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>.pcap İndir</span>
          </button>
        </div>
      </div>
    </div>
  );
};
