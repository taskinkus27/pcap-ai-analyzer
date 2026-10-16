import React, { useState } from 'react';
import { ParsedPacket } from '../types/pcap';
import { ChevronRight, ChevronDown, ShieldAlert, Cpu, Globe, Server, Copy, Check } from 'lucide-react';

interface PacketDissectorProps {
  packet: ParsedPacket | null;
}

export const PacketDissector: React.FC<PacketDissectorProps> = ({ packet }) => {
  const [copied, setCopied] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    frame: true,
    ethernet: true,
    ip: true,
    transport: true,
    application: true,
    anomalies: true,
  });

  const toggleSection = (key: string) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1500);
  };

  if (!packet) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-900/60 p-6 text-slate-500 font-mono text-xs">
        Detaylı katman ayrıştırmasını (dissection) görmek için yukarıdaki tablodan bir paket seçin.
      </div>
    );
  }

  const { ethernet, ip, transport, protocol, anomalies, http, dns, tls } = packet;

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-3 font-mono text-xs border-r border-slate-800 text-slate-300">
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
        <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
          <Cpu className="w-3.5 h-3.5" />
          Paket Detay Ayrıştırması (Frame #{packet.id})
        </span>
        <span className="text-[11px] text-slate-500">
          Zaman Damgası: {new Date(packet.timestamp * 1000).toLocaleTimeString()} (+{packet.relativeTime.toFixed(4)}s)
        </span>
      </div>

      <div className="space-y-1">
        {/* 1. Anomalies Section (if any) */}
        {anomalies && anomalies.length > 0 && (
          <div className="border border-rose-900/60 bg-rose-950/20 rounded mb-2 overflow-hidden">
            <button
              onClick={() => toggleSection('anomalies')}
              className="w-full flex items-center justify-between px-2.5 py-1.5 bg-rose-950/50 hover:bg-rose-950/70 text-rose-300 font-sans font-semibold text-xs"
            >
              <div className="flex items-center gap-1.5">
                {expandedSections.anomalies ? (
                  <ChevronDown className="w-3.5 h-3.5 text-rose-400" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-rose-400" />
                )}
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Güvenlik Anomalileri ve Tehdit Eşleşmeleri ({anomalies.length})</span>
              </div>
            </button>
            {expandedSections.anomalies && (
              <div className="p-2.5 space-y-2">
                {anomalies.map((anom, idx) => (
                  <div key={idx} className="bg-slate-950/90 p-2 rounded border border-rose-900/40 text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-rose-400">{anom.title}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {anom.severity}
                      </span>
                    </div>
                    <p className="text-slate-300 mt-1">{anom.description}</p>
                    {anom.matchedRule && (
                      <div className="mt-1 text-[10px] text-amber-400 font-mono bg-amber-950/20 px-1.5 py-0.5 rounded border border-amber-900/30">
                        Kural: {anom.matchedRule}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 2. Frame Layer */}
        <div className="rounded border border-slate-800/80 bg-slate-900/40 overflow-hidden">
          <button
            onClick={() => toggleSection('frame')}
            className="w-full flex items-center justify-between px-2.5 py-1.5 hover:bg-slate-800/60 text-slate-300 text-left"
          >
            <div className="flex items-center gap-1.5">
              {expandedSections.frame ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              <span>Frame {packet.id}: {packet.length} bayt (ağ kablosunda {packet.length * 8} bit)</span>
            </div>
          </button>
          {expandedSections.frame && (
            <div className="px-5 py-1.5 text-[11px] text-slate-400 space-y-0.5 border-t border-slate-800/60 bg-slate-950/60">
              <div>Arayüz Kimliği: 0 (eth0)</div>
              <div>Yakalama Uzunluğu: {packet.capturedLength} bayt</div>
              <div>Geliş Zamanı: {new Date(packet.timestamp * 1000).toISOString()}</div>
              <div>Göreceli Zaman (Epoch): {packet.relativeTime.toFixed(6)} saniye</div>
            </div>
          )}
        </div>

        {/* 3. Ethernet II Layer */}
        <div className="rounded border border-slate-800/80 bg-slate-900/40 overflow-hidden">
          <button
            onClick={() => toggleSection('ethernet')}
            className="w-full flex items-center justify-between px-2.5 py-1.5 hover:bg-slate-800/60 text-slate-300 text-left"
          >
            <div className="flex items-center gap-1.5">
              {expandedSections.ethernet ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              <span>Ethernet II, Kaynak: {ethernet.srcMac}, Hedef: {ethernet.dstMac}</span>
            </div>
          </button>
          {expandedSections.ethernet && (
            <div className="px-5 py-1.5 text-[11px] text-slate-400 space-y-0.5 border-t border-slate-800/60 bg-slate-950/60">
              <div>Hedef MAC: {ethernet.dstMac}</div>
              <div>Kaynak MAC: {ethernet.srcMac}</div>
              <div>Tip (EtherType): {ethernet.etherType} ({ip.version === 4 ? 'IPv4' : ip.version === 6 ? 'IPv6' : 'ARP'})</div>
            </div>
          )}
        </div>

        {/* 4. IP Layer */}
        <div className="rounded border border-slate-800/80 bg-slate-900/40 overflow-hidden">
          <button
            onClick={() => toggleSection('ip')}
            className="w-full flex items-center justify-between px-2.5 py-1.5 hover:bg-slate-800/60 text-slate-300 text-left"
          >
            <div className="flex items-center gap-1.5">
              {expandedSections.ip ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              <span>Internet Protocol Version {ip.version}, Kaynak: {ip.srcIp}, Hedef: {ip.dstIp}</span>
            </div>
          </button>
          {expandedSections.ip && (
            <div className="px-5 py-1.5 text-[11px] text-slate-400 space-y-0.5 border-t border-slate-800/60 bg-slate-950/60">
              <div>Versiyon: {ip.version}</div>
              <div>Protokol: {ip.protocolName} ({ip.protocol})</div>
              <div>Yaşam Süresi (TTL): {ip.ttl}</div>
              <div>Toplam Paket Uzunluğu: {ip.totalLength} bayt</div>
              {ip.identification !== undefined && <div>Paket Tanımlayıcı (ID): 0x{ip.identification.toString(16)} ({ip.identification})</div>}
              <div>Kaynak IP Adresi: <span className="text-cyan-300 font-semibold">{ip.srcIp}</span></div>
              <div>Hedef IP Adresi: <span className="text-cyan-300 font-semibold">{ip.dstIp}</span></div>
            </div>
          )}
        </div>

        {/* 5. Transport Layer (TCP/UDP/ICMP/ARP) */}
        {transport.type !== 'OTHER' && (
          <div className="rounded border border-slate-800/80 bg-slate-900/40 overflow-hidden">
            <button
              onClick={() => toggleSection('transport')}
              className="w-full flex items-center justify-between px-2.5 py-1.5 hover:bg-slate-800/60 text-slate-300 text-left"
            >
              <div className="flex items-center gap-1.5">
                {expandedSections.transport ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                <span>
                  {transport.type === 'TCP' && `Transmission Control Protocol, Kaynak Port: ${transport.srcPort}, Hedef Port: ${transport.dstPort}`}
                  {transport.type === 'UDP' && `User Datagram Protocol, Kaynak Port: ${transport.srcPort}, Hedef Port: ${transport.dstPort}`}
                  {transport.type === 'ICMP' && `Internet Control Message Protocol: ${transport.icmpDescription}`}
                  {transport.type === 'ARP' && `Address Resolution Protocol (${transport.arpOperation})`}
                </span>
              </div>
            </button>
            {expandedSections.transport && (
              <div className="px-5 py-1.5 text-[11px] text-slate-400 space-y-0.5 border-t border-slate-800/60 bg-slate-950/60">
                {transport.type === 'TCP' && (
                  <>
                    <div>Kaynak Port: <span className="text-slate-200">{transport.srcPort}</span></div>
                    <div>Hedef Port: <span className="text-slate-200">{transport.dstPort}</span></div>
                    <div>Sıra Numarası (Seq): {transport.seqNumber}</div>
                    <div>Onay Numarası (Ack): {transport.ackNumber}</div>
                    <div>Pencere Boyutu (Window): {transport.windowSize}</div>
                    {transport.flags && (
                      <div className="pt-1">
                        <div className="font-semibold text-slate-300">TCP Bayrakları (Flags):</div>
                        <div className="grid grid-cols-3 gap-1 pl-2 text-[10px] mt-0.5">
                          <span className={transport.flags.syn ? 'text-amber-300 font-bold' : 'text-slate-600'}>SYN: {transport.flags.syn ? '1 (Aktif)' : '0'}</span>
                          <span className={transport.flags.ack ? 'text-blue-300 font-bold' : 'text-slate-600'}>ACK: {transport.flags.ack ? '1 (Aktif)' : '0'}</span>
                          <span className={transport.flags.fin ? 'text-rose-300 font-bold' : 'text-slate-600'}>FIN: {transport.flags.fin ? '1 (Aktif)' : '0'}</span>
                          <span className={transport.flags.rst ? 'text-red-400 font-bold' : 'text-slate-600'}>RST: {transport.flags.rst ? '1 (Aktif)' : '0'}</span>
                          <span className={transport.flags.psh ? 'text-emerald-300 font-bold' : 'text-slate-600'}>PSH: {transport.flags.psh ? '1 (Aktif)' : '0'}</span>
                          <span className={transport.flags.urg ? 'text-purple-300 font-bold' : 'text-slate-600'}>URG: {transport.flags.urg ? '1 (Aktif)' : '0'}</span>
                        </div>
                      </div>
                    )}
                  </>
                )}
                {transport.type === 'UDP' && (
                  <>
                    <div>Kaynak Port: {transport.srcPort}</div>
                    <div>Hedef Port: {transport.dstPort}</div>
                  </>
                )}
                {transport.type === 'ICMP' && (
                  <>
                    <div>Tip: {transport.icmpType}</div>
                    <div>Kod: {transport.icmpCode}</div>
                    <div>Açıklama: {transport.icmpDescription}</div>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {/* 6. Application Layer (HTTP / DNS / TLS) */}
        {(http || dns || tls) && (
          <div className="rounded border border-slate-800/80 bg-slate-900/40 overflow-hidden">
            <button
              onClick={() => toggleSection('application')}
              className="w-full flex items-center justify-between px-2.5 py-1.5 hover:bg-slate-800/60 text-slate-300 text-left"
            >
              <div className="flex items-center gap-1.5">
                {expandedSections.application ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span>
                  {http && `Hypertext Transfer Protocol (${http.method || (http.statusCode ? `Yanıt ${http.statusCode}` : 'HTTP')})`}
                  {dns && `Domain Name System (${dns.isResponse ? 'Response' : 'Query'})`}
                  {tls && `Transport Layer Security (${tls.recordName})`}
                </span>
              </div>
            </button>
            {expandedSections.application && (
              <div className="px-5 py-2 text-[11px] text-slate-400 space-y-1 border-t border-slate-800/60 bg-slate-950/60">
                {http && (
                  <>
                    {http.method && <div>İstek Metodu: <span className="text-emerald-400 font-bold">{http.method}</span></div>}
                    {http.uri && (
                      <div className="break-all">
                        URI: <span className="text-amber-300 font-mono">{http.uri}</span>
                      </div>
                    )}
                    {http.statusCode && <div>Durum Kodu: <span className="text-blue-300">{http.statusCode}</span></div>}
                    {http.host && <div>Host: <span className="text-slate-200">{http.host}</span></div>}
                    {http.userAgent && <div className="truncate">User-Agent: {http.userAgent}</div>}
                    {http.authorization && (
                      <div className="text-rose-400 break-all bg-rose-950/30 p-1 rounded">
                        Authorization Başlığı: {http.authorization}
                      </div>
                    )}
                    {http.bodyPreview && (
                      <div className="mt-1 pt-1 border-t border-slate-800">
                        <span className="text-slate-400 block mb-0.5">HTTP Body Önizleme:</span>
                        <div className="bg-slate-950 p-1.5 rounded border border-slate-800 text-slate-200 font-mono text-[10px] break-all whitespace-pre-wrap">
                          {http.bodyPreview}
                        </div>
                      </div>
                    )}
                  </>
                )}
                {dns && (
                  <>
                    <div>İşlem ID: 0x{dns.id.toString(16)}</div>
                    <div>Sorgulanan Alan Adı: <span className="text-cyan-300 font-bold">{dns.queryName}</span></div>
                    <div>Kayıt Tipi: <span className="text-blue-300">{dns.queryType}</span></div>
                    {dns.subdomainEntropy !== undefined && (
                      <div>
                        Alt Alan Adı Shannon Entropisi:{' '}
                        <span className={dns.subdomainEntropy > 3.8 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                          {dns.subdomainEntropy} {dns.subdomainEntropy > 3.8 ? '(Yüksek / Tünel Şüphesi)' : ''}
                        </span>
                      </div>
                    )}
                  </>
                )}
                {tls && (
                  <>
                    <div>TLS Versiyonu: {tls.version}</div>
                    <div>Kayıt Adı: {tls.recordName}</div>
                    {tls.sni && <div>SNI (Server Name Indication): <span className="text-purple-300 font-bold">{tls.sni}</span></div>}
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
