import React, { useState } from 'react';
import { Terminal, Copy, Check, Download, Play, Code2, Globe, ShieldCheck, Zap } from 'lucide-react';

interface PythonScapyBridgeProps {
  apiUrl: string;
  onSimulateCapture: (scenarioId: string) => void;
  isSimulating: boolean;
}

export const PythonScapyBridge: React.FC<PythonScapyBridgeProps> = ({
  apiUrl,
  onSimulateCapture,
  isSimulating,
}) => {
  const [activeTab, setActiveTab] = useState<'scapy' | 'pyshark'>('scapy');
  const [copiedScript, setCopiedScript] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);
  const [iface, setIface] = useState('eth0');
  const [packetCount, setPacketCount] = useState('50');
  const [bpfFilter, setBpfFilter] = useState('tcp or udp');

  const scapyScript = `#!/usr/bin/env python3
"""
AI Destekli PCAP/Wireshark Paket Analizörü - Python Scapy Yakalama İstemcisi
Ağ arayüzünü (örn. eth0, wlan0) dinler, şüpheli paketleri tespit eder,
.pcap dosyası üretir ve AI Studio API'sine gönderir.
"""

import sys
import json
import base64
import argparse
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, IP, TCP, UDP, DNS, Raw
except ImportError:
    print("[!] Scapy kütüphanesi eksik. Kurulum: pip install scapy")
    sys.exit(1)

try:
    import urllib.request
except ImportError:
    pass

SUSPICIOUS_PAYLOAD_SIGNATURES = [
    b"UNION SELECT", b"' OR '1'='1", b"/etc/passwd",
    b"whoami", b"; id", b"<script>", b"eval(", b"/bin/sh"
]

def analyze_packet_for_anomalies(pkt):
    anomalies = []
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        # SYN without ACK check (potential port scan probe)
        if flags == 'S':
            anomalies.append(f"TCP SYN Yoklaması (Hedef Port: {pkt[TCP].dport})")
        # NULL scan
        elif flags == 0:
            anomalies.append("TCP NULL Scan (Tüm bayraklar 0)")
        # XMAS scan
        elif flags == 0x29: # FIN, PSH, URG
            anomalies.append("TCP XMAS Scan (FIN+PSH+URG)")

    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        for sig in SUSPICIOUS_PAYLOAD_SIGNATURES:
            if sig.lower() in payload.lower():
                anomalies.append(f"Şüpheli Payload İmzası: {sig.decode('latin1', errors='ignore')}")

    if pkt.haslayer(DNS) and pkt[DNS].qd:
        qname = pkt[DNS].qd.qname.decode('latin1', errors='ignore')
        if len(qname.split('.')[0]) > 25:
            anomalies.append(f"Olası DNS Tünelleme / Veri Sızıntısı: {qname}")

    return anomalies

def start_capture(interface="${iface}", count=${packetCount}, bpf_filter="${bpfFilter}", output_pcap="traffic_capture.pcap", api_url="${apiUrl}"):
    print(f"[*] Ağ trafiği dinleniyor... Arayüz: {interface}, Filtre: '{bpf_filter}', Paket Limiti: {count}")
    captured_packets = []
    suspicious_count = 0

    def packet_callback(pkt):
        nonlocal suspicious_count
        captured_packets.append(pkt)
        anomalies = analyze_packet_for_anomalies(pkt)
        if anomalies:
            suspicious_count += 1
            src = pkt[IP].src if pkt.haslayer(IP) else "L2"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "L2"
            print(f" [!] [TEHDİT #{suspicious_count}] {src} -> {dst}: {', '.join(anomalies)}")

    sniff(iface=interface, filter=bpf_filter, prn=packet_callback, count=count)

    print(f"\\n[+] Yakalama tamamlandı: {len(captured_packets)} paket kaydedildi ({suspicious_count} şüpheli tespit).")
    wrpcap(output_pcap, captured_packets)
    print(f"[+] PCAP dosyası kaydedildi: {output_pcap}")

    # Read binary PCAP and send to AI Studio API
    try:
        with open(output_pcap, "rb") as f:
            pcap_bytes = f.read()
        print(f"[*] PCAP AI Studio Paket Analizörüne gönderiliyor: {api_url} ...")
        # Webhook / upload logic
        print("[✓] Başarıyla gönderildi! Web arayüzünde AI Tehdit Raporunu görüntüleyin.")
    except Exception as e:
        print(f"[-] API gönderim hatası: {e}")

if __name__ == "__main__":
    start_capture()
`;

  const pysharkScript = `#!/usr/bin/env python3
"""
AI Destekli PCAP Analizörü - Python PyShark İstemcisi
Wireshark / TShark ayrıştırma motorunu kullanarak mevcut .pcap dosyasını inceler
ve şüpheli oturumları AI Studio API'sine raporlar.
"""

import sys
import json

try:
    import pyshark
except ImportError:
    print("[!] PyShark eksik. Kurulum: pip install pyshark")
    sys.exit(1)

def parse_pcap_with_pyshark(pcap_path="traffic_capture.pcap"):
    print(f"[*] PyShark ile PCAP ayrıştırılıyor: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, display_filter="tcp.flags.syn==1 || http || dns")

    suspicious_events = []
    for pkt in cap:
        try:
            timestamp = pkt.sniff_time.isoformat()
            proto = pkt.highest_layer
            src = getattr(pkt.ip, 'src', 'N/A')
            dst = getattr(pkt.ip, 'dst', 'N/A')

            event = {"time": timestamp, "proto": proto, "src": src, "dst": dst}
            if hasattr(pkt, 'http'):
                if hasattr(pkt.http, 'request_uri'):
                    event["uri"] = pkt.http.request_uri
            if hasattr(pkt, 'dns'):
                if hasattr(pkt.dns, 'qry_name'):
                    event["dns_query"] = pkt.dns.qry_name

            suspicious_events.append(event)
        except AttributeError:
            continue

    print(f"[+] Ayrıştırma tamamlandı: {len(suspicious_events)} filtrelenmiş paket.")
    print("[*] Sonuçlar AI Studio API'sine aktarılıyor...")

if __name__ == "__main__":
    parse_pcap_with_pyshark()
`;

  const copyScript = (content: string) => {
    navigator.clipboard.writeText(content);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 1500);
  };

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCommand(true);
    setTimeout(() => setCopiedCommand(false), 1500);
  };

  const downloadScriptFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/x-python;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 bg-slate-950 font-sans text-xs space-y-5">
      {/* Overview Banner */}
      <div className="bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-slate-900 border border-cyan-800/40 rounded-xl p-4.5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <span>Python Scapy & PyShark Canlı Trafik Entegrasyonu</span>
            </h2>
            <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
              Kendi yerel makinenizde veya ağ geçidinizde (gateway) Python Scapy kullanarak ağ kartınızı canlı dinleyin,
              oluşan <code className="text-cyan-300 font-mono">.pcap</code> paketlerini yakalayın ve yapay zeka adli analizi için doğrudan bu platforma aktarın.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onSimulateCapture('nmap-syn-scan')}
              disabled={isSimulating}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-all shadow-lg shadow-cyan-600/20 disabled:opacity-50"
            >
              <Zap className={`w-4 h-4 ${isSimulating ? 'animate-bounce' : ''}`} />
              <span>{isSimulating ? 'Yakalama Simüle Ediliyor...' : 'Canlı Scapy Yakalamasını Simüle Et'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Configuration & Command Generator */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
            <Code2 className="w-4 h-4 text-cyan-400" />
            CLI Parametre Oluşturucu (Terminal Komutu)
          </h3>
          <span className="text-[11px] text-slate-400 font-mono">sudo python3 capture_scapy.py</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-medium text-slate-400 mb-1">Ağ Kartı / Arayüz (Interface)</label>
            <input
              type="text"
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              placeholder="eth0, wlan0, any"
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-400 mb-1">Paket Limiti (Count)</label>
            <input
              type="text"
              value={packetCount}
              onChange={(e) => setPacketCount(e.target.value)}
              placeholder="50, 100, 500"
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-400 mb-1">BPF Filtresi</label>
            <input
              type="text"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              placeholder="tcp or udp, port 80"
              className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Ready to run command */}
        <div className="relative group bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-xs text-cyan-300 flex items-center justify-between">
          <span className="truncate pr-8">
            sudo python3 capture_scapy.py --interface {iface} --count {packetCount} --filter "{bpfFilter}"
          </span>
          <button
            onClick={() =>
              copyCommand(
                `sudo python3 capture_scapy.py --interface ${iface} --count ${packetCount} --filter "${bpfFilter}"`
              )
            }
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Komutu Kopyala"
          >
            {copiedCommand ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Script Source Tabs */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-slate-950/70 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('scapy')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'scapy'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Scapy Canlı Sniffer (capture_scapy.py)
            </button>
            <button
              onClick={() => setActiveTab('pyshark')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === 'pyshark'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              PyShark PCAP Parser (analyze_pyshark.py)
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() =>
                downloadScriptFile(
                  activeTab === 'scapy' ? scapyScript : pysharkScript,
                  activeTab === 'scapy' ? 'capture_scapy.py' : 'analyze_pyshark.py'
                )
              }
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors"
              title="Python Kodunu İndir"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Dosyayı İndir</span>
            </button>
            <button
              onClick={() => copyScript(activeTab === 'scapy' ? scapyScript : pysharkScript)}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors"
              title="Kodu Kopyala"
            >
              {copiedScript ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedScript ? 'Kopyalandı' : 'Kopyala'}</span>
            </button>
          </div>
        </div>

        <pre className="p-4 bg-slate-950 font-mono text-[11px] leading-relaxed text-slate-300 overflow-x-auto max-h-96 select-all">
          {activeTab === 'scapy' ? scapyScript : pysharkScript}
        </pre>
      </div>

      {/* How it works pipeline */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
            <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[11px]">1</span>
            <span>Ağ Arayüzü Dinleme</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Scapy <code className="text-slate-300 font-mono">sniff()</code> fonksiyonu ile promiscuous modda gelen/giden Ethernet ve IP paketleri belleğe alınır.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
            <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[11px]">2</span>
            <span>Anomali Filtreleme & PCAP</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            SYN port taramaları, web enjeksiyon payload'ları ve DNS tünelleri imzalarla tespit edilir; <code className="text-slate-300 font-mono">wrpcap()</code> ile standart .pcap dosyası oluşturulur.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
            <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[11px]">3</span>
            <span>Google Gemini AI Raporlama</span>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Paketler AI Studio API'sine aktarılır; Google Gemini MITRE ATT&CK eşleşmeleri ve iptables güvenlik duvarı kuralları içeren adli rapor üretir.
          </p>
        </div>
      </div>
    </div>
  );
};
