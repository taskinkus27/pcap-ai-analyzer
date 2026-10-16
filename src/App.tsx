import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { PcapParser } from './utils/pcapParser';
import { AnomalyDetector } from './utils/anomalyDetector';
import { SAMPLE_SCENARIOS, SampleScenario } from './data/samplePcaps';
import { ParsedPacket, PcapSummary, AiForensicReport } from './types/pcap';
import { Header } from './components/Header';
import { ScenarioSelector } from './components/ScenarioSelector';
import { AnomalySummaryCards } from './components/AnomalySummaryCards';
import { FilterBar } from './components/FilterBar';
import { PacketTable } from './components/PacketTable';
import { PacketDissector } from './components/PacketDissector';
import { HexViewer } from './components/HexViewer';
import { AiIncidentReportModal } from './components/AiIncidentReportModal';
import { PythonScapyBridge } from './components/PythonScapyBridge';
import { AiForensicCopilot } from './components/AiForensicCopilot';
import { AlertCircle, Sparkles } from 'lucide-react';

export default function App() {
  const [currentScenario, setCurrentScenario] = useState<SampleScenario>(SAMPLE_SCENARIOS[0]);
  const [currentBuffer, setCurrentBuffer] = useState<ArrayBuffer | null>(null);
  const [fileName, setFileName] = useState<string>('nmap_syn_portscan.pcap');
  const [packets, setPackets] = useState<ParsedPacket[]>([]);
  const [summary, setSummary] = useState<PcapSummary | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<ParsedPacket | null>(null);
  const [filterQuery, setFilterQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'packets' | 'python' | 'report'>('packets');

  // AI Report State
  const [aiReport, setAiReport] = useState<AiForensicReport | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load a scenario
  const loadScenario = useCallback((scenario: SampleScenario) => {
    try {
      setErrorMessage(null);
      setCurrentScenario(scenario);
      const buffer = scenario.generator();
      setCurrentBuffer(buffer);
      const generatedFileName = `${scenario.id.replace(/-/g, '_')}.pcap`;
      setFileName(generatedFileName);

      const parsed = PcapParser.parse(buffer);
      const { packetsWithAnomalies, summary } = AnomalyDetector.analyze(
        parsed,
        generatedFileName,
        buffer.byteLength
      );

      setPackets(packetsWithAnomalies);
      setSummary(summary);
      setSelectedPacket(packetsWithAnomalies[0] || null);
      setAiReport(null); // reset report so user gets fresh AI analysis
    } catch (err: any) {
      console.error('Scenario load error:', err);
      setErrorMessage('Senaryo yüklenirken hata: ' + (err.message || 'Bilinmeyen hata'));
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadScenario(SAMPLE_SCENARIOS[0]);
  }, [loadScenario]);

  // Handle local .pcap / .pcapng file upload
  const handleFileUpload = (file: File) => {
    setErrorMessage(null);
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const buffer = e.target?.result as ArrayBuffer;
        if (!buffer) return;
        setCurrentBuffer(buffer);
        setFileName(file.name);

        const parsed = PcapParser.parse(buffer);
        const { packetsWithAnomalies, summary } = AnomalyDetector.analyze(
          parsed,
          file.name,
          buffer.byteLength
        );

        setPackets(packetsWithAnomalies);
        setSummary(summary);
        setSelectedPacket(packetsWithAnomalies[0] || null);
        setAiReport(null);
        setActiveTab('packets');
      } catch (err: any) {
        console.error('File parsing error:', err);
        setErrorMessage('PCAP ayrıştırma hatası: ' + (err.message || 'Dosya okunamadı.'));
      }
    };
    reader.readAsArrayBuffer(file);
  };

  // Download active PCAP
  const handleDownloadPcap = () => {
    if (!currentBuffer) return;
    const blob = new Blob([currentBuffer], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName.endsWith('.pcap') ? fileName : `${fileName}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Trigger Gemini AI Incident Analysis
  const runAiAnalysis = async () => {
    if (!summary || packets.length === 0) return;
    setIsAiLoading(true);
    setIsReportModalOpen(true);

    try {
      // Find suspicious packets to feed into AI
      const suspicious = packets.filter((p) => p.anomalies.length > 0);
      const sampleSuspicious = suspicious.length > 0 ? suspicious : packets.slice(0, 15);

      const response = await fetch('/api/analyze-pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          summary,
          suspiciousPackets: sampleSuspicious,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'AI analizi başarısız oldu.');
      }

      setAiReport(data.report);
    } catch (err: any) {
      console.error('AI Report error:', err);
      setErrorMessage('AI Analiz Raporu oluşturulamadı: ' + (err.message || 'Bilinmeyen hata'));
    } finally {
      setIsAiLoading(false);
    }
  };

  // Simulate live python capture
  const handleSimulateCapture = (scenarioId: string) => {
    setIsSimulating(true);
    setTimeout(() => {
      const match = SAMPLE_SCENARIOS.find((s) => s.id === scenarioId) || SAMPLE_SCENARIOS[1];
      loadScenario(match);
      setIsSimulating(false);
      setActiveTab('packets');
    }, 1200);
  };

  // Filter evaluation logic (Wireshark-like syntax)
  const filteredPackets = useMemo(() => {
    if (!filterQuery.trim()) return packets;

    const q = filterQuery.toLowerCase().trim();

    return packets.filter((pkt) => {
      // 1. Anomaly filters
      if (q === 'anomaly==true' || q === 'anomaly' || q === 'threat') {
        return pkt.anomalies.length > 0;
      }
      if (q.startsWith('type==')) {
        const targetType = q.replace('type==', '').trim().toUpperCase();
        return pkt.anomalies.some((a) => a.type === targetType);
      }

      // 2. Protocol filters
      if (['http', 'dns', 'tcp', 'udp', 'icmp', 'arp', 'tls'].includes(q)) {
        return pkt.protocol.toLowerCase() === q;
      }
      if (q.startsWith('proto==')) {
        const protoTarget = q.replace('proto==', '').trim().toUpperCase();
        return pkt.protocol === protoTarget;
      }

      // 3. IP and Port filters
      if (q.startsWith('ip.src==')) {
        const ip = q.replace('ip.src==', '').trim();
        return pkt.ip.srcIp === ip;
      }
      if (q.startsWith('ip.dst==')) {
        const ip = q.replace('ip.dst==', '').trim();
        return pkt.ip.dstIp === ip;
      }
      if (q.startsWith('port==')) {
        const port = parseInt(q.replace('port==', '').trim(), 10);
        return pkt.transport.srcPort === port || pkt.transport.dstPort === port;
      }

      // 4. TCP Flag filters
      if (q === 'tcp.syn==1' || q === 'tcp.flags.syn==1') {
        return pkt.transport.flags?.syn && !pkt.transport.flags.ack;
      }
      if (q === 'tcp.synack==1') {
        return pkt.transport.flags?.syn && pkt.transport.flags.ack;
      }

      // 5. Free-text matching (Info, IPs, payloads, URIs)
      const textToSearch = `${pkt.info} ${pkt.ip.srcIp} ${pkt.ip.dstIp} ${pkt.protocol} ${
        pkt.http?.uri || ''
      } ${pkt.dns?.queryName || ''} ${pkt.payloadText || ''}`.toLowerCase();

      return textToSearch.includes(q);
    });
  }, [packets, filterQuery]);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans">
      {/* 1. Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={(tab) => {
          if (tab === 'report') {
            setIsReportModalOpen(true);
            if (!aiReport && !isAiLoading) {
              runAiAnalysis();
            }
          } else {
            setActiveTab(tab);
          }
        }}
        fileName={fileName}
        packetCount={packets.length}
        threatLevel={summary?.severityBreakdown?.CRITICAL ? 'CRITICAL' : 'HIGH'}
        onOpenCopilot={() => setIsCopilotOpen(true)}
      />

      {/* 2. Scenario & File Bar */}
      <ScenarioSelector
        currentScenarioId={currentScenario.id}
        onSelectScenario={loadScenario}
        onFileUpload={handleFileUpload}
        onDownloadCurrentPcap={handleDownloadPcap}
      />

      {/* Error alert if any */}
      {errorMessage && (
        <div className="px-4 py-2 bg-rose-950/80 border-b border-rose-800 text-rose-200 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-rose-400 hover:text-rose-100 font-bold ml-4"
          >
            ×
          </button>
        </div>
      )}

      {/* 3. Main Views */}
      {activeTab === 'python' ? (
        <PythonScapyBridge
          apiUrl={window.location.origin + '/api/analyze-pcap'}
          onSimulateCapture={handleSimulateCapture}
          isSimulating={isSimulating}
        />
      ) : (
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {/* Anomaly telemetry cards */}
          <AnomalySummaryCards
            summary={summary}
            onFilterAnomalyType={(filter) => setFilterQuery(filter)}
            onOpenReportModal={runAiAnalysis}
          />

          {/* Wireshark filter query bar */}
          <FilterBar
            filterQuery={filterQuery}
            setFilterQuery={setFilterQuery}
            filteredCount={filteredPackets.length}
            totalCount={packets.length}
          />

          {/* Wireshark 3-Pane Layout */}
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
            {/* Top: Packet List Table */}
            <PacketTable
              packets={filteredPackets}
              selectedPacket={selectedPacket}
              onSelectPacket={setSelectedPacket}
            />

            {/* Split Bottom Panes (Dissector & Hex Viewer) */}
            <div className="flex-1 grid grid-cols-1 md:grid-cols-2 min-h-0 overflow-hidden border-t border-slate-800">
              <PacketDissector packet={selectedPacket} />
              <HexViewer packet={selectedPacket} />
            </div>
          </div>
        </div>
      )}

      {/* 4. AI Incident Report Modal */}
      {isReportModalOpen && (
        <AiIncidentReportModal
          report={aiReport}
          isLoading={isAiLoading}
          onClose={() => setIsReportModalOpen(false)}
          onRegenerate={runAiAnalysis}
        />
      )}

      {/* 5. AI Forensic Copilot Drawer */}
      <AiForensicCopilot
        summary={summary}
        selectedPacket={selectedPacket}
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
      />
    </div>
  );
}
