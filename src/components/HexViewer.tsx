import React, { useState } from 'react';
import { ParsedPacket } from '../types/pcap';
import { Binary, Copy, Check } from 'lucide-react';

interface HexViewerProps {
  packet: ParsedPacket | null;
}

export const HexViewer: React.FC<HexViewerProps> = ({ packet }) => {
  const [copied, setCopied] = useState(false);

  if (!packet) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-950 p-4 text-slate-500 font-mono text-xs">
        Hex dökümünü incelemek için bir paket seçin.
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(packet.hexDump);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-3 font-mono text-xs text-slate-300">
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
        <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
          <Binary className="w-3.5 h-3.5" />
          Paket Ham Baytları (Hex / ASCII Dökümü) — {packet.length} Bayt
        </span>
        <button
          onClick={handleCopy}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] border border-slate-700 transition-colors"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          <span>{copied ? 'Kopyalandı' : 'Hex Kopyala'}</span>
        </button>
      </div>

      <pre className="text-[11px] leading-relaxed text-slate-300 select-all font-mono whitespace-pre overflow-x-auto bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
        {packet.hexDump}
      </pre>

      {packet.payloadText && (
        <div className="mt-3">
          <div className="text-[10px] font-sans font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Çözülmüş Payload Metni (Decoded Payload ASCII / String)
          </div>
          <div className="p-2 bg-slate-900/90 rounded border border-slate-800 text-[11px] text-amber-200/90 font-mono break-all whitespace-pre-wrap max-h-32 overflow-y-auto">
            {packet.payloadText}
          </div>
        </div>
      )}
    </div>
  );
};
