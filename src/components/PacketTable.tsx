import React, { useEffect, useRef } from 'react';
import { ParsedPacket, ProtocolType } from '../types/pcap';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

interface PacketTableProps {
  packets: ParsedPacket[];
  selectedPacket: ParsedPacket | null;
  onSelectPacket: (packet: ParsedPacket) => void;
}

export const PacketTable: React.FC<PacketTableProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
}) => {
  const tableRef = useRef<HTMLDivElement>(null);

  // Keyboard navigation (ArrowUp, ArrowDown)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!selectedPacket || packets.length === 0) return;
      const currentIndex = packets.findIndex((p) => p.id === selectedPacket.id);
      if (currentIndex === -1) return;

      if (e.key === 'ArrowDown' && currentIndex < packets.length - 1) {
        e.preventDefault();
        onSelectPacket(packets[currentIndex + 1]);
      } else if (e.key === 'ArrowUp' && currentIndex > 0) {
        e.preventDefault();
        onSelectPacket(packets[currentIndex - 1]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedPacket, packets, onSelectPacket]);

  // Protocol badge style mapping (Wireshark-like coloring)
  const getProtocolStyle = (proto: ProtocolType) => {
    switch (proto) {
      case 'HTTP':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/50';
      case 'DNS':
        return 'bg-sky-950/80 text-sky-300 border-sky-700/50';
      case 'TLS':
        return 'bg-purple-950/80 text-purple-300 border-purple-700/50';
      case 'TCP':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/50';
      case 'UDP':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/50';
      case 'ICMP':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-700/50';
      case 'ARP':
        return 'bg-orange-950/80 text-orange-300 border-orange-700/50';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getHighestAnomaly = (packet: ParsedPacket) => {
    if (!packet.anomalies || packet.anomalies.length === 0) return null;
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    for (const sev of order) {
      const match = packet.anomalies.find((a) => a.severity === sev);
      if (match) return match;
    }
    return packet.anomalies[0];
  };

  return (
    <div
      ref={tableRef}
      className="flex-1 overflow-auto bg-slate-950 font-mono text-xs select-none border-b border-slate-800"
      style={{ maxHeight: '42vh' }}
    >
      <table className="w-full text-left border-collapse table-fixed">
        <thead className="bg-slate-900/95 sticky top-0 z-10 text-[11px] text-slate-400 font-sans uppercase tracking-wider border-b border-slate-800">
          <tr>
            <th className="w-12 px-2 py-2">No.</th>
            <th className="w-20 px-2 py-2">Zaman</th>
            <th className="w-44 px-2 py-2">Kaynak</th>
            <th className="w-44 px-2 py-2">Hedef</th>
            <th className="w-18 px-2 py-2 text-center">Proto</th>
            <th className="w-14 px-2 py-2 text-right">Boyut</th>
            <th className="px-2 py-2">Bilgi (Info)</th>
            <th className="w-36 px-2 py-2 text-center">Tehdit Durumu</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/40">
          {packets.length === 0 ? (
            <tr>
              <td colSpan={8} className="text-center py-12 text-slate-500 font-sans text-sm">
                Filtreye uygun paket bulunamadı veya hiçbir PCAP yüklenmedi.
              </td>
            </tr>
          ) : (
            packets.map((pkt) => {
              const isSelected = selectedPacket?.id === pkt.id;
              const anomaly = getHighestAnomaly(pkt);

              let rowBg = 'hover:bg-slate-800/60';
              if (isSelected) {
                rowBg = 'bg-cyan-950/80 border-l-2 border-l-cyan-400 text-cyan-50';
              } else if (anomaly) {
                if (anomaly.severity === 'CRITICAL') {
                  rowBg = 'bg-rose-950/30 hover:bg-rose-950/50 text-rose-200';
                } else if (anomaly.severity === 'HIGH') {
                  rowBg = 'bg-amber-950/25 hover:bg-amber-950/45 text-amber-200';
                } else if (anomaly.severity === 'MEDIUM') {
                  rowBg = 'bg-orange-950/20 hover:bg-orange-950/40';
                }
              }

              return (
                <tr
                  key={pkt.id}
                  onClick={() => onSelectPacket(pkt)}
                  className={`cursor-pointer transition-colors ${rowBg}`}
                >
                  <td className="px-2 py-1.5 text-slate-500 text-[11px]">{pkt.id}</td>
                  <td className="px-2 py-1.5 text-slate-400">{pkt.relativeTime.toFixed(4)}s</td>
                  <td className="px-2 py-1.5 truncate">
                    <span className="text-slate-200">{pkt.ip.srcIp}</span>
                    {pkt.transport.srcPort && (
                      <span className="text-slate-400">:{pkt.transport.srcPort}</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 truncate">
                    <span className="text-slate-200">{pkt.ip.dstIp}</span>
                    {pkt.transport.dstPort && (
                      <span className="text-slate-400">:{pkt.transport.dstPort}</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-center">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border ${getProtocolStyle(
                        pkt.protocol
                      )}`}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-right text-slate-400">{pkt.length}</td>
                  <td className="px-2 py-1.5 truncate text-slate-300" title={pkt.info}>
                    {pkt.info}
                  </td>
                  <td className="px-2 py-1.5 text-center">
                    {anomaly ? (
                      <span
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold tracking-wide ${
                          anomaly.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : anomaly.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                        }`}
                        title={`${anomaly.title}: ${anomaly.description}`}
                      >
                        {anomaly.severity === 'CRITICAL' && <ShieldAlert className="w-3 h-3 text-rose-400" />}
                        {anomaly.severity === 'HIGH' && <AlertTriangle className="w-3 h-3 text-amber-400" />}
                        {anomaly.severity === 'MEDIUM' && <AlertCircle className="w-3 h-3 text-orange-400" />}
                        <span className="truncate max-w-[100px]">{anomaly.type.replace('_', ' ')}</span>
                      </span>
                    ) : (
                      <span className="text-slate-600 text-[10px]">Normal</span>
                    )}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
};
